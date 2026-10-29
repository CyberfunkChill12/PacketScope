using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace PacketScope.Windows;

public sealed class AnalyzerException : Exception { public AnalyzerException(string m) : base(m) { } }

/// <summary>
/// Bounded classic-PCAP parser (Windows port of the macOS analyzer). It never
/// reads past a frame: container corruption is a file error, while an
/// undecodable packet is retained as an honest counted entry. Statistics are
/// computed over the whole file; only the first 2,000 rows are kept for display.
/// </summary>
public static partial class PacketAnalyzer
{
    public const int DisplayLimit = 2000;
    public const long MaxFileBytes = 100 * 1024 * 1024;
    private static readonly HashSet<int> SupportedLinks = new() { 0, 1, 12, 101, 108, 149, 258, 228, 229 };

    public static CaptureReport Analyze(string path)
    {
        var info = new FileInfo(path);
        if (info.Length > MaxFileBytes) throw new AnalyzerException($"Capture file is {info.Length} bytes, over the 100 MiB import limit.");
        return Analyze(File.ReadAllBytes(path));
    }

    /// <summary>Writes a new classic PCAP with only the given 1-based frames, copied unchanged.</summary>
    public static void ExportPacketSubset(string source, HashSet<int> frames, string destination)
    {
        var b = File.ReadAllBytes(source);
        if (b.Length < 24) throw new AnalyzerException("Truncated PCAP: global header.");
        bool little = b[0] == 0xD4 || b[0] == 0x4D;
        int U32(int o) => little ? b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24 : b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3];
        using var output = new MemoryStream();
        output.Write(b, 0, 24);
        int off = 24, number = 0;
        while (off + 16 <= b.Length)
        {
            int incl = U32(off + 8);
            if (off + 16 + incl > b.Length) throw new AnalyzerException($"Truncated PCAP: packet data at offset {off}.");
            number++;
            if (frames.Contains(number)) output.Write(b, off, 16 + incl);
            off += 16 + incl;
        }
        File.WriteAllBytes(destination, output.ToArray());
    }

    private sealed class Decoded
    {
        public string Src = "Unknown", Dst = "Unknown";
        public int? Sport, Dport;
        public string Proto = "Unknown", Summary = "Packet could not be decoded further.";
        public string? Hostname, ProcessName;
        public int? ProcessId;
        public bool IsTcp, IsRst, Undecodable, IsQuic, TlsAppData, IcmpUnreachable;
        public int TcpFlags; public uint TcpSeq; public int PayloadLength;
        public string Mix = "OTHER";
        public string? TlsEvent, TlsSni, HttpHost, HttpUrl, ArpReplySender;
        public bool TlsEch;
        public byte[] TcpPayload = Array.Empty<byte>();
        public DnsMessage? Dns;
        public string? PlaintextProto;
        public int DnsTxId; public string DnsTransport = "udp";
    }

    private sealed class DnsMessage
    {
        public bool IsResponse; public int Rcode; public bool Truncated; public bool IsMdns;
        public List<(string Name, int Type, int Cls)> Questions = new();
        public List<(string Owner, int Type, string Address)> Answers = new();
    }

    private sealed class Flow
    {
        public string Initiator = "", Server = "";
        public int InitiatorPort, ServerPort;
        public List<int> SynFrames = new(); public List<double> SynTimes = new();
        public HashSet<uint> SynSeqs = new(); public HashSet<string> DataSeqs = new();
        public bool Connected, Refused, ResetLater, ClientHello, ServerHello, AlertBeforeHello, SawHttp;
        public string? Sni; public bool Ech;
        public int Packets; public long Bytes; public List<int> Frames = new(); public int Retransmissions;
        public List<int> RefusedFrames = new();
    }

    public static CaptureReport Analyze(byte[] b)
    {
        if (b.Length > MaxFileBytes) throw new AnalyzerException("Capture file is over the 100 MiB import limit.");
        if (b.Length >= 4 && b[0] == 0x0A && b[1] == 0x0D && b[2] == 0x0D && b[3] == 0x0A)
            throw new AnalyzerException("PCAPNG files are not supported. Please provide a classic PCAP file.");
        if (b.Length < 24) throw new AnalyzerException("Truncated PCAP: global header.");
        uint first = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        uint swapped = (uint)(b[3] << 24 | b[2] << 16 | b[1] << 8 | b[0]);
        bool little, nano;
        if (first == 0xA1B2C3D4) { little = false; nano = false; }
        else if (first == 0xA1B23C4D) { little = false; nano = true; }
        else if (swapped == 0xA1B2C3D4) { little = true; nano = false; }
        else if (swapped == 0xA1B23C4D) { little = true; nano = true; }
        else throw new AnalyzerException("This file is not a classic PCAP capture.");
        ushort U16(int o) => little ? (ushort)(b[o] | b[o + 1] << 8) : (ushort)(b[o] << 8 | b[o + 1]);
        uint U32(int o) => little ? (uint)(b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) : (uint)(b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]);
        if (U16(4) != 2 || U16(6) != 4) throw new AnalyzerException($"Unsupported PCAP version {U16(4)}.{U16(6)}; only 2.4 is supported.");
        long snaplen = U32(16);
        if (snaplen <= 0) throw new AnalyzerException("Invalid PCAP: snapshot length is zero.");
        int linkType = (int)U32(20);
        if (!SupportedLinks.Contains(linkType)) throw new AnalyzerException($"Unsupported PCAP link type {linkType}.");

        var recs = new List<(double Ts, int Incl, int Orig, int Off)>();
        int off = 24;
        while (off < b.Length)
        {
            if (off + 16 > b.Length) throw new AnalyzerException($"Truncated PCAP: record header at offset {off}.");
            uint sec = U32(off), frac = U32(off + 4);
            int incl = (int)U32(off + 8), orig = (int)U32(off + 12);
            long fracLimit = nano ? 1_000_000_000 : 1_000_000;
            if (frac >= fracLimit) throw new AnalyzerException("Invalid PCAP: timestamp fraction out of range.");
            if (incl > snaplen) throw new AnalyzerException("Invalid PCAP: captured length exceeds snapshot length.");
            if (incl > orig) throw new AnalyzerException("Invalid PCAP: captured length exceeds original length.");
            if (off + 16 + incl > b.Length) throw new AnalyzerException($"Truncated PCAP: packet data at offset {off}.");
            recs.Add((sec + (double)frac / fracLimit, incl, orig, off + 16));
            off += 16 + incl;
        }

        var st = new State { Little = little, LinkType = linkType, FirstTs = recs.Count > 0 ? recs[0].Ts : null };
        double span = recs.Count > 1 ? Math.Max(0, recs[^1].Ts - recs[0].Ts) : 0;
        st.BucketWidth = Math.Max(1, Math.Ceiling(span / 119));
        for (int i = 0; i < recs.Count; i++)
        {
            var frame = new byte[recs[i].Incl];
            Array.Copy(b, recs[i].Off, frame, 0, recs[i].Incl);
            st.CurrentNumber = i + 1;
            st.DecodePacket(frame, i + 1, recs[i].Ts, recs[i].Orig, recs[i].Incl);
        }
        return st.Finish(recs.Count);
    }

    private sealed partial class State
    {
        public bool Little; public int LinkType; public double? FirstTs; public double LastTs; public double BucketWidth = 1;
        public int CurrentNumber;
        public long CapturedBytes;
        public Dictionary<string, (int Count, long Bytes)> ProtoStats = new();
        public Dictionary<string, (int Packets, long Bytes)> EndpointStats = new();
        public List<PacketRecord> Records = new();
        public int Undecodable;
        public int DnsResponses, DnsErrors, TcpPackets, TcpResets, TcpRetransmissions;
        public List<int> DnsErrorPackets = new(), RstPackets = new(), IcmpPackets = new(), TlsAlertPackets = new();
        public List<(int Num, string Proto)> PlainRemote = new(), PlainLocal = new();
        public List<double> Intervals = new();
        public Dictionary<int, TrafficBucket> Buckets = new();
        public Dictionary<string, (List<string> Addr, int Queries, int Errors, List<int> Frames)> Domains = new();
        public List<string> DomainOrder = new();
        public Dictionary<string, string> IpToName = new();
        public List<DnsLookup> Lookups = new();
        public int DnsQueryCount;
        public List<string> Resolvers = new();
        public List<(string Name, int Frame)> Nxdomains = new();
        public List<string> Cnames = new();
        private sealed class Pending { public double Ts; public int Count; public List<int> LookupIdx = new(); }
        private readonly Dictionary<string, Pending> _pending = new();
        private readonly HashSet<string> _answeredKeys = new();
        public Dictionary<string, (int Count, long Bytes)> MixStats = new();
        public int QuicPackets, EncryptedOther;
        public string? ArpResponder;
        public Dictionary<string, Flow> Flows = new();
        public List<string> FlowOrder = new();
        public Dictionary<string, (string Server, int Port, bool Quic, int Packets, long Bytes, List<int> Frames)> UdpGroups = new();
        public List<string> UdpOrder = new();
        public List<string> HttpHosts = new(), HttpUrls = new();
        public List<CertificateObservable> Certs = new();
        public List<TlsFingerprint> Fps = new();
        public Dictionary<string, ObservableEndpoint> ObsEndpoints = new();
        public HashSet<string> ObsIps = new();
        public bool ObsTruncated;
        // TLS stream reassembly (16 KB per direction, memory only)
        private sealed class TlsStream { public uint BaseSeq; public List<(uint Seq, byte[] Data)> Segments = new(); public int ParsedOffset; public bool Finished; public int Buffered; }
        private readonly Dictionary<string, TlsStream> _tlsStreams = new();

        public static bool IsLoopback(string a)
        {
            if (a == "::1") return true;
            if (a.StartsWith("::ffff:")) return IsLoopback(a[7..]);
            var p = a.Split('.');
            return p.Length == 4 && p[0] == "127";
        }

        public void DecodePacket(byte[] frame, int number, double ts, int originalLength, int capturedLength)
        {
            if (ts > LastTs) LastTs = ts;
            CapturedBytes += capturedLength;
            var d = new Decoded();
            DecodeLink(frame, LinkType, d);
            if (d.Undecodable) Undecodable++;
            AddTo(ProtoStats, d.Proto, capturedLength);
            if (d.Src != "Unknown") AddTo(EndpointStats, d.Src, capturedLength);
            if (d.Dst != "Unknown") AddTo(EndpointStats, d.Dst, capturedLength);
            bool bothLoop = IsLoopback(d.Src) && IsLoopback(d.Dst) && d.Src != "Unknown";
            bool isDnsErr = false;
            if (d.IsTcp) { TcpPackets++; if (d.IsRst) { TcpResets++; if (RstPackets.Count < 100) RstPackets.Add(number); } }
            if (d.Dns != null) HandleDns(d.Dns, d, number, ts, ref isDnsErr);
            if (d.PlaintextProto != null)
            {
                if (bothLoop) PlainLocal.Add((number, d.PlaintextProto)); else PlainRemote.Add((number, d.PlaintextProto));
                if (d.PlaintextProto == "HTTP") ParseHttp(d.TcpPayload, d);
            }
            if (d.HttpHost != null && !HttpHosts.Contains(d.HttpHost) && HttpHosts.Count < 1000) HttpHosts.Add(d.HttpHost);
            if (d.HttpUrl != null && !HttpUrls.Contains(d.HttpUrl) && HttpUrls.Count < 1000) HttpUrls.Add(d.HttpUrl);
            AddTo(MixStats, d.Mix, capturedLength);
            if (d.IsQuic) QuicPackets++;
            if (d.TlsAppData) EncryptedOther++;
            if (d.ArpReplySender != null && ArpResponder == null) ArpResponder = d.ArpReplySender;
            if (d.IcmpUnreachable && IcmpPackets.Count < 100) IcmpPackets.Add(number);
            if (d.TlsEvent == "alert" && TlsAlertPackets.Count < 100) TlsAlertPackets.Add(number);
            // Full observable set for threat matching
            if (d.Src != "Unknown") { if (ObsIps.Count < 250_000) ObsIps.Add(d.Src); else ObsTruncated = true; }
            if (d.Dst != "Unknown")
            {
                if (ObsIps.Count < 250_000) ObsIps.Add(d.Dst); else ObsTruncated = true;
                if (d.Dport is int dp && (d.IsTcp || d.Proto is "UDP" or "QUIC" or "DNS"))
                {
                    string key = $"{d.Dst}|{dp}";
                    if (ObsEndpoints.TryGetValue(key, out var e)) { e.Packets++; if (e.Frames.Count < 10) e.Frames.Add(number); }
                    else if (ObsEndpoints.Count < 100_000) ObsEndpoints[key] = new ObservableEndpoint { Address = d.Dst, Port = dp, Packets = 1, Frames = { number } };
                    else ObsTruncated = true;
                }
            }
            UpdateFlow(d, number, capturedLength);
            if (FirstTs is double f)
            {
                int idx = (int)((ts - f) / BucketWidth);
                if (!Buckets.TryGetValue(idx, out var bk)) { bk = new TrafficBucket { Second = idx * (int)BucketWidth }; Buckets[idx] = bk; }
                bk.Packets++; bk.Bytes += capturedLength;
                if (isDnsErr) bk.DnsErrors++;
                if (d.IsRst) bk.TcpResets++;
            }
            if (Records.Count < DisplayLimit)
            {
                Records.Add(new PacketRecord
                {
                    Id = number, Timestamp = ts, Source = d.Src, Destination = d.Dst,
                    SourcePort = d.Sport, DestinationPort = d.Dport, ProtocolName = d.Proto,
                    Length = originalLength, Summary = d.Summary, ProcessName = d.ProcessName,
                    ProcessId = d.ProcessId, Hostname = d.Hostname,
                });
            }
        }

        private static void AddTo(Dictionary<string, (int, long)> dict, string key, long bytes)
        {
            dict.TryGetValue(key, out var v);
            dict[key] = (v.Item1 + 1, v.Item2 + bytes);
        }

        // ---- link / IP / transport decoding (all reads bounds-checked) ----

        private void DecodeLink(byte[] frame, int link, Decoded d)
        {
            switch (link)
            {
                case 0: case 108:
                    if (frame.Length < 4) { d.Undecodable = true; return; }
                    DecodeIp(frame.AsSpan(4).ToArray(), d); break;
                case 1: DecodeEthernet(frame, d); break;
                case 12: case 101: DecodeIp(frame, d); break;
                case 228: DecodeIPv4(frame, d); break;
                case 229: DecodeIPv6(frame, d); break;
                case 149: case 258: DecodePktap(frame, d); break;
                default: d.Undecodable = true; d.Proto = $"Link {link}"; break;
            }
        }


        // Apple PKTAP metadata (captures recorded on macOS). v1 and v2
        // headers are bounds-checked; process identity comes only from the
        // metadata actually present, never inferred.
        private void DecodePktap(byte[] frame, Decoded d)
        {
            d.Proto = "PKTAP";
            if (frame.Length < 8) { d.Undecodable = true; d.Summary = "Truncated PKTAP metadata."; return; }
            int RU32(int o) => Little ? frame[o] | frame[o + 1] << 8 | frame[o + 2] << 16 | frame[o + 3] << 24 : frame[o] << 24 | frame[o + 1] << 16 | frame[o + 2] << 8 | frame[o + 3];
            int RU16(int o) => Little ? frame[o] | frame[o + 1] << 8 : frame[o] << 8 | frame[o + 1];
            string CStr(int start, int maxLen)
            {
                if (start >= frame.Length) return "";
                int end = start;
                while (end < Math.Min(frame.Length, start + maxLen) && frame[end] != 0) end++;
                return System.Text.Encoding.UTF8.GetString(frame, start, end - start);
            }
            bool looksV2 = frame.Length >= 40 && (RU32(36) & 0x00080000) != 0 && frame[0] >= 40 && frame[0] <= 200;
            if (looksV2)
            {
                int innerDlt = RU16(6);
                int flags = RU32(36);
                int pid = RU32(28);
                int commOff = frame[4], ecommOff = frame[5];
                int headerLen = frame[0];
                string name = commOff > 0 ? CStr(commOff, 20) : "";
                if (name.Length == 0 && ecommOff > 0) name = CStr(ecommOff, 20);
                if (commOff > 0) headerLen = Math.Max(headerLen, commOff + 20);
                if (ecommOff > 0) headerLen = Math.Max(headerLen, ecommOff + 20);
                int ifOff = frame[3];
                if (ifOff > 0) headerLen = Math.Max(headerLen, ifOff + 24);
                headerLen = Math.Min(Math.Max(headerLen, 40), frame.Length);
                if (name.Length > 0) d.ProcessName = name;
                if (pid != 0) d.ProcessId = pid;
                if (innerDlt is 0 or 1 or 12 or 101 or 108 or 228 or 229)
                    DecodeLink(frame.AsSpan(headerLen).ToArray(), innerDlt, d);
                else { d.Undecodable = true; d.Summary = $"PKTAP record with unsupported inner link type {innerDlt}."; }
                return;
            }
            int v1Len = RU32(0);
            if (v1Len < 100 || v1Len > frame.Length) { d.Undecodable = true; d.Summary = "Malformed PKTAP metadata (bad header length)."; return; }
            int dlt = RU32(8);
            int pidv1 = RU32(52);
            string namev1 = CStr(56, 20);
            if (namev1.Length == 0) namev1 = CStr(88, 20);
            if (namev1.Length > 0) d.ProcessName = namev1;
            if (pidv1 != 0) d.ProcessId = pidv1;
            if (dlt is 0 or 1 or 12 or 101 or 108 or 228 or 229)
                DecodeLink(frame.AsSpan(v1Len).ToArray(), dlt, d);
            else { d.Undecodable = true; d.Summary = $"PKTAP record with unsupported inner link type {dlt}."; }
        }

        private void DecodeEthernet(byte[] frame, Decoded d)
        {
            if (frame.Length < 14) { d.Undecodable = true; d.Proto = "Ethernet"; d.Summary = "Truncated Ethernet frame."; return; }
            int off = 12;
            int ether = frame[off] << 8 | frame[off + 1]; off += 2;
            int vlans = 0;
            while ((ether == 0x8100 || ether == 0x88A8 || ether == 0x9100) && vlans < 4)
            {
                if (frame.Length < off + 4) { d.Undecodable = true; return; }
                ether = frame[off + 2] << 8 | frame[off + 3]; off += 4; vlans++;
            }
            var payload = frame.AsSpan(off).ToArray();
            switch (ether)
            {
                case 0x0800: DecodeIPv4(payload, d); break;
                case 0x86DD: DecodeIPv6(payload, d); break;
                case 0x0806:
                    d.Proto = "ARP";
                    if (payload.Length >= 28 && payload[4] == 6 && payload[5] == 4)
                    {
                        string spa = string.Join(".", payload[14..18]);
                        string tpa = string.Join(".", payload[24..28]);
                        d.Src = spa; d.Dst = tpa;
                        int op = payload[6] << 8 | payload[7];
                        if (op == 2) d.ArpReplySender = spa;
                        d.Summary = op == 1 ? $"ARP request: who has {tpa}? (sender {spa})" : $"ARP reply: {spa} is at the sender hardware address.";
                    }
                    else d.Summary = "ARP packet.";
                    break;
                default: d.Proto = "Ethernet"; d.Summary = $"Ethernet frame, EtherType 0x{ether:x}."; break;
            }
        }

        private void DecodeIp(byte[] frame, Decoded d)
        {
            if (frame.Length == 0) { d.Undecodable = true; d.Summary = "Empty IP packet."; return; }
            int v = frame[0] >> 4;
            if (v == 4) DecodeIPv4(frame, d);
            else if (v == 6) DecodeIPv6(frame, d);
            else { d.Undecodable = true; d.Proto = "IP"; d.Summary = "Unknown IP version."; }
        }

        private static string Ipv6String(byte[] b)
        {
            if (b.Length != 16) return "Unknown";
            var groups = new ushort[8];
            for (int i = 0; i < 8; i++) groups[i] = (ushort)(b[2 * i] << 8 | b[2 * i + 1]);
            if (groups.Take(5).All(g => g == 0) && groups[5] == 0xFFFF)
                return $"::ffff:{b[12]}.{b[13]}.{b[14]}.{b[15]}";
            int bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
            for (int i = 0; i < 8; i++)
            {
                if (groups[i] == 0) { if (curStart < 0) { curStart = i; curLen = 1; } else curLen++; if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; } }
                else { curStart = -1; curLen = 0; }
            }
            string Hex(ushort g) => g.ToString("x");
            if (bestLen >= 2)
                return string.Join(":", groups.Take(bestStart).Select(Hex)) + "::" + string.Join(":", groups.Skip(bestStart + bestLen).Select(Hex));
            return string.Join(":", groups.Select(Hex));
        }

        private void DecodeIPv4(byte[] frame, Decoded d)
        {
            if (frame.Length < 20 || frame[0] >> 4 != 4) { d.Undecodable = true; d.Proto = "IPv4"; d.Summary = "Truncated IPv4 header."; return; }
            int ihl = (frame[0] & 0x0F) * 4;
            if (ihl < 20 || frame.Length < ihl) { d.Undecodable = true; d.Proto = "IPv4"; return; }
            int total = frame[2] << 8 | frame[3];
            int end = total >= ihl && total <= frame.Length ? total : frame.Length;
            d.Src = string.Join(".", frame[12..16]);
            d.Dst = string.Join(".", frame[16..20]);
            int frag = (frame[6] << 8 | frame[7]) & 0x1FFF;
            bool more = (frame[6] & 0x20) != 0;
            var payload = frame.AsSpan(ihl, end - ihl).ToArray();
            if (frag != 0 || more) { d.Proto = "IPv4"; d.Summary = "IPv4 fragment (transport header not reassembled)."; return; }
            DecodeTransport(frame[9], payload, d, false);
        }

        private void DecodeIPv6(byte[] frame, Decoded d)
        {
            if (frame.Length < 40 || frame[0] >> 4 != 6) { d.Undecodable = true; d.Proto = "IPv6"; return; }
            d.Src = Ipv6String(frame[8..24]);
            d.Dst = Ipv6String(frame[24..40]);
            int next = frame[6], off = 40, hops = 0;
            while (hops++ < 8)
            {
                switch (next)
                {
                    case 0: case 43: case 60:
                        if (frame.Length < off + 2) { d.Undecodable = true; d.Proto = "IPv6"; return; }
                        int len = (frame[off + 1] + 1) * 8;
                        if (len < 8 || frame.Length < off + len) { d.Undecodable = true; d.Proto = "IPv6"; return; }
                        next = frame[off]; off += len; break;
                    case 44: d.Proto = "IPv6"; d.Summary = "IPv6 fragment (transport header not reassembled)."; return;
                    case 51:
                        if (frame.Length < off + 2) { d.Undecodable = true; d.Proto = "IPv6"; return; }
                        int alen = (frame[off + 1] + 2) * 4;
                        if (frame.Length < off + alen) { d.Undecodable = true; d.Proto = "IPv6"; return; }
                        next = frame[off]; off += alen; break;
                    default:
                        DecodeTransport(next, frame.AsSpan(off).ToArray(), d, true);
                        return;
                }
            }
            d.Proto = "IPv6"; d.Undecodable = true; d.Summary = "Too many IPv6 extension headers.";
        }

        private void DecodeTransport(int proto, byte[] payload, Decoded d, bool v6)
        {
            switch (proto)
            {
                case 6: DecodeTcp(payload, d); break;
                case 17: DecodeUdp(payload, d); break;
                case 1:
                    d.Proto = "ICMP"; d.Mix = "ICMP";
                    if (payload.Length >= 2)
                    {
                        d.Summary = $"ICMP type {payload[0]}, code {payload[1]} between {d.Src} and {d.Dst}.";
                        if (payload[0] == 3) { d.IcmpUnreachable = true; d.Summary = $"ICMP destination unreachable (code {payload[1]}) from {d.Src} to {d.Dst}."; }
                    }
                    else d.Summary = "ICMP packet.";
                    break;
                case 58:
                    d.Proto = "ICMPv6"; d.Mix = "ICMP";
                    if (payload.Length >= 2)
                    {
                        d.Summary = $"ICMPv6 type {payload[0]}, code {payload[1]} between {d.Src} and {d.Dst}.";
                        if (payload[0] == 1) { d.IcmpUnreachable = true; d.Summary = $"ICMPv6 destination unreachable (code {payload[1]}) from {d.Src}."; }
                    }
                    else d.Summary = "ICMPv6 packet.";
                    break;
                default:
                    d.Proto = v6 ? "IPv6" : "IPv4";
                    d.Summary = $"IP protocol {proto} between {d.Src} and {d.Dst}.";
                    break;
            }
        }

        private void DecodeTcp(byte[] payload, Decoded d)
        {
            d.IsTcp = true; d.Mix = "TCP";
            if (payload.Length < 20) { d.Undecodable = true; d.Proto = "TCP"; d.Summary = "Truncated TCP header."; return; }
            d.Sport = payload[0] << 8 | payload[1];
            d.Dport = payload[2] << 8 | payload[3];
            d.TcpSeq = (uint)(payload[4] << 24 | payload[5] << 16 | payload[6] << 8 | payload[7]);
            int hlen = (payload[12] >> 4) * 4;
            if (hlen < 20 || payload.Length < hlen) { d.Undecodable = true; d.Proto = "TCP"; return; }
            int flags = payload[13];
            d.TcpFlags = flags;
            d.IsRst = (flags & 0x04) != 0;
            var names = new List<string>();
            if ((flags & 0x02) != 0) names.Add("SYN");
            if ((flags & 0x10) != 0) names.Add("ACK");
            if ((flags & 0x01) != 0) names.Add("FIN");
            if ((flags & 0x04) != 0) names.Add("RST");
            if ((flags & 0x08) != 0) names.Add("PSH");
            d.Proto = "TCP";
            var body = payload.AsSpan(hlen).ToArray();
            d.PayloadLength = body.Length;
            d.TcpPayload = body;
            string summary = $"TCP {d.Src}:{d.Sport} → {d.Dst}:{d.Dport}" + (names.Count > 0 ? $" [{string.Join(",", names)}]" : "") + ".";
            if (d.IsRst) summary += " Connection reset observed.";
            FeedTls(d, body);
            if (d.TlsEvent == "clientHello") summary += " Secure setup (TLS) started" + (d.TlsSni != null ? $" for {d.TlsSni}" : "") + ".";
            if (d.TlsEvent == "serverHello") summary += " Secure setup (TLS) answered.";
            if (d.TlsEvent == "alert") summary += " TLS alert observed (contents not shown).";
            if (d.TlsAppData) summary += " Encrypted TLS data (contents can't be read).";
            if ((d.Sport == 53 || d.Dport == 53) && body.Length >= 2)
            {
                int mlen = body[0] << 8 | body[1];
                if (mlen >= 12 && body.Length >= 2 + mlen && ParseDns(body.AsSpan(2, mlen).ToArray(), false) is { } dns)
                {
                    d.Proto = "DNS"; d.Mix = "DNS"; d.Dns = dns; d.Hostname = dns.Questions.FirstOrDefault().Name;
                    d.DnsTxId = body[2] << 8 | body[3]; d.DnsTransport = "tcp";
                    summary = DnsSummary(dns, d, "TCP");
                }
            }
            else if (DetectPlaintext(body) is { } app)
            {
                d.PlaintextProto = app; d.Proto = app;
                summary += $" Recognizable plaintext {app} content visible (contents are not shown).";
            }
            d.Summary = summary;
        }

        private void DecodeUdp(byte[] payload, Decoded d)
        {
            if (payload.Length < 8) { d.Undecodable = true; d.Proto = "UDP"; return; }
            d.Sport = payload[0] << 8 | payload[1];
            d.Dport = payload[2] << 8 | payload[3];
            var body = payload.AsSpan(8).ToArray();
            d.Proto = "UDP"; d.Mix = "UDP_OTHER";
            string summary = $"UDP {d.Src}:{d.Sport} → {d.Dst}:{d.Dport}.";
            if ((d.Sport == 443 || d.Dport == 443) && body.Length > 0 && (body[0] & 0x80) != 0)
            {
                d.IsQuic = true; d.Proto = "QUIC"; d.Mix = "QUIC";
                d.Summary = $"QUIC {d.Src}:{d.Sport} → {d.Dst}:{d.Dport} (encrypted; server names are not extracted in the Windows version).";
                return;
            }
            bool mdns = d.Sport == 5353 || d.Dport == 5353;
            if (d.Sport == 53 || d.Dport == 53 || mdns)
            {
                if (body.Length >= 12 && ParseDns(body, mdns) is { } dns)
                {
                    d.Proto = mdns ? "mDNS" : "DNS";
                    if (!mdns) d.Mix = "DNS";
                    d.Dns = dns; d.Hostname = dns.Questions.FirstOrDefault().Name;
                    d.DnsTxId = body[0] << 8 | body[1]; d.DnsTransport = "udp";
                    summary = DnsSummary(dns, d, "UDP");
                }
            }
            else if (DetectPlaintext(body) is { } app)
            {
                d.PlaintextProto = app; d.Proto = app;
                summary += $" Recognizable plaintext {app} content visible (contents are not shown).";
            }
            d.Summary = summary;
        }

        private static string DnsSummary(DnsMessage dns, Decoded d, string transport)
        {
            string name = dns.Questions.FirstOrDefault().Name ?? "a name";
            if (dns.IsResponse)
                return dns.Rcode == 0
                    ? $"DNS reply ({transport}) for {name} between {d.Src} and {d.Dst}."
                    : $"DNS error reply ({transport}, code {dns.Rcode}) for {name} between {d.Src} and {d.Dst}.";
            return $"DNS query ({transport}) for {name} between {d.Src} and {d.Dst}.";
        }

        // Recognizable plaintext only — never by port number, never stored.
        private static string? DetectPlaintext(byte[] body)
        {
            if (body.Length < 3) return null;
            string head = Encoding.ASCII.GetString(body, 0, Math.Min(64, body.Length));
            foreach (var tok in new[] { "HTTP/", "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "PATCH ", "OPTIONS " })
                if (head.StartsWith(tok)) return "HTTP";
            foreach (var tok in new[] { "EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:" })
                if (head.StartsWith(tok)) return "SMTP";
            foreach (var tok in new[] { "USER ", "PASS ", "RETR ", "STOR ", "LIST", "CWD ", "TYPE " })
                if (head.StartsWith(tok)) return "FTP";
            if (head.StartsWith("220 ") || head.StartsWith("220-"))
            {
                string lower = head.ToLowerInvariant();
                if (lower.Contains("ftp")) return "FTP";
                if (lower.Contains("smtp") || lower.Contains("mail")) return "SMTP";
                return "FTP/SMTP";
            }
            return null;
        }

        private void ParseHttp(byte[] body, Decoded d)
        {
            if (body.Length < 16) return;
            string text = Encoding.UTF8.GetString(body, 0, Math.Min(4096, body.Length));
            int lineEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
            if (lineEnd < 0) lineEnd = text.IndexOf('\n');
            if (lineEnd < 0) return;
            var parts = text[..lineEnd].Split(' ');
            if (parts.Length != 3 || !parts[2].StartsWith("HTTP/")) return;
            string path = parts[1];
            string? host = null;
            foreach (var rawLine in text[(lineEnd..)].Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.StartsWith("host:", StringComparison.OrdinalIgnoreCase)) { host = line[5..].Trim(); break; }
                if (line.Length == 0) break;
            }
            if (path.StartsWith("http://") || path.StartsWith("https://"))
            {
                d.HttpUrl = path;
                if (Uri.TryCreate(path, UriKind.Absolute, out var u)) d.HttpHost = u.Host.ToLowerInvariant();
            }
            else if (!string.IsNullOrEmpty(host))
            {
                d.HttpHost = host.ToLowerInvariant();
                d.HttpUrl = "http://" + host + path;
            }
        }
    }
}

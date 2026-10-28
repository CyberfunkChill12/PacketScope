using System.Security.Cryptography;
using System.Text;

namespace PacketScope.Windows;

public static partial class PacketAnalyzer
{
    private sealed partial class State
    {
        // ---------------- DNS ----------------

        private static string RcodeName(int r) => r switch { 0 => "NOERROR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 5 => "REFUSED", _ => $"RCODE {r}" };

        private void AddDomain(string name, int packet)
        {
            if (!Domains.ContainsKey(name))
            {
                if (Domains.Count >= 2000) return;
                Domains[name] = (new List<string>(), 0, 0, new List<int>());
                DomainOrder.Add(name);
            }
            var d = Domains[name];
            if (d.Frames.Count < 50) d.Frames.Add(packet);
            Domains[name] = d;
        }

        private void HandleDns(DnsMessage dns, Decoded d, int number, double ts, ref bool isErr)
        {
            foreach (var q in dns.Questions)
            {
                AddDomain(q.Name, number);
                if (!dns.IsResponse)
                {
                    var entry = Domains[q.Name]; entry.Queries++; Domains[q.Name] = entry;
                }
            }
            if (dns.IsResponse)
            {
                DnsResponses++;
                if (!dns.IsMdns && !Resolvers.Contains(d.Src) && Resolvers.Count < 16) Resolvers.Add(d.Src);
                if (dns.Rcode != 0)
                {
                    DnsErrors++; isErr = true;
                    if (DnsErrorPackets.Count < 100) DnsErrorPackets.Add(number);
                    foreach (var q in dns.Questions) if (Domains.ContainsKey(q.Name)) { var e = Domains[q.Name]; e.Errors++; Domains[q.Name] = e; }
                    if (dns.Rcode == 3 && dns.Questions.Count > 0 && Nxdomains.Count < 50) Nxdomains.Add((dns.Questions[0].Name, number));
                }
            }
            foreach (var ans in dns.Answers.Where(a => a.Type == 5))
            {
                if (!Cnames.Contains(ans.Address) && Cnames.Count < 500) Cnames.Add(ans.Address);
                AddDomain(ans.Address, number);
            }
            foreach (var ans in dns.Answers.Where(a => a.Type == 1 || a.Type == 28))
            {
                IpToName.TryAdd(ans.Address, ans.Owner);
                AddDomain(ans.Owner, number);
                var e = Domains[ans.Owner];
                if (!e.Addr.Contains(ans.Address) && e.Addr.Count < 16) e.Addr.Add(ans.Address);
                Domains[ans.Owner] = e;
            }
            if (dns.IsMdns || dns.Truncated || d.Sport is not int sp || d.Dport is not int dp) return;
            string qkey = string.Join(";", dns.Questions.Select(q => $"{q.Name}/{q.Type}/{q.Cls}"));
            if (dns.IsResponse)
            {
                string key = $"{d.DnsTransport}|{d.Dst}|{d.Src}|{dp}|{sp}|{d.DnsTxId}|{qkey}";
                if (_pending.TryGetValue(key, out var entry))
                {
                    if (entry.Count == 1 && !_answeredKeys.Contains(key))
                    {
                        double dt = ts - entry.Ts;
                        if (dt >= 0 && dt <= 30)
                        {
                            Intervals.Add(dt * 1000);
                            foreach (int idx in entry.LookupIdx)
                                if (idx < Lookups.Count) { Lookups[idx].Milliseconds = dt * 1000; Lookups[idx].Rcode = RcodeName(dns.Rcode); }
                        }
                    }
                    _pending.Remove(key);
                    _answeredKeys.Add(key);
                }
            }
            else
            {
                var idxs = new List<int>();
                foreach (var q in dns.Questions)
                {
                    DnsQueryCount++;
                    if (Lookups.Count < 1000)
                    {
                        string typeName = new Dictionary<int, string> { [1] = "A", [28] = "AAAA", [65] = "HTTPS", [5] = "CNAME" }.GetValueOrDefault(q.Type, $"TYPE{q.Type}");
                        Lookups.Add(new DnsLookup { Name = q.Name, Type = typeName, Frame = number });
                        idxs.Add(Lookups.Count - 1);
                    }
                }
                string key = $"{d.DnsTransport}|{d.Src}|{d.Dst}|{sp}|{dp}|{d.DnsTxId}|{qkey}";
                _answeredKeys.Remove(key);
                if (_pending.TryGetValue(key, out var existing)) { existing.Count++; _pending[key] = existing; }
                else if (_pending.Count < 4096) _pending[key] = new Pending { Ts = ts, Count = 1, LookupIdx = idxs };
            }
        }

        private static DnsMessage? ParseDns(byte[] msg, bool isMdns)
        {
            if (msg.Length < 12) return null;
            int U16(int o) => msg[o] << 8 | msg[o + 1];
            int flags = U16(2);
            int qd = U16(4), an = U16(6), ns = U16(8), ar = U16(10);
            if (qd > 32 || an + ns + ar > 256) return null;
            var info = new DnsMessage { IsResponse = (flags & 0x8000) != 0, Truncated = (flags & 0x0200) != 0, Rcode = flags & 0xF, IsMdns = isMdns };
            int off = 12;
            for (int i = 0; i < qd; i++)
            {
                var name = ReadDnsName(msg, off);
                if (name is null) return null;
                if (name.Value.Next + 4 > msg.Length) return null;
                info.Questions.Add((name.Value.Name, U16(name.Value.Next), U16(name.Value.Next + 2)));
                off = name.Value.Next + 4;
            }
            bool ReadRRs(int count, bool collect)
            {
                for (int i = 0; i < count; i++)
                {
                    var name = ReadDnsName(msg, off);
                    if (name is null) return false;
                    int next = name.Value.Next;
                    if (next + 10 > msg.Length) return false;
                    int type = U16(next), rdlen = U16(next + 8), rdata = next + 10;
                    if (rdata + rdlen > msg.Length) return false;
                    if (collect && type == 1 && rdlen == 4)
                        info.Answers.Add((name.Value.Name, type, string.Join(".", msg.AsSpan(rdata, 4).ToArray())));
                    if (collect && type == 28 && rdlen == 16)
                        info.Answers.Add((name.Value.Name, type, Ipv6String(msg.AsSpan(rdata, 16).ToArray())));
                    if (collect && type == 5 && ReadDnsName(msg, rdata) is { } target)
                        info.Answers.Add((name.Value.Name, type, target.Name));
                    off = rdata + rdlen;
                }
                return true;
            }
            if (!ReadRRs(an, true) || !ReadRRs(ns, false) || !ReadRRs(ar, false)) return null;
            return info;
        }

        // Compression pointers must point strictly backwards; labels are escaped.
        private static (string Name, int Next)? ReadDnsName(byte[] msg, int offset)
        {
            var labels = new List<string>();
            int pos = offset, jumps = 0, total = 0;
            int? next = null;
            while (true)
            {
                if (pos >= msg.Length) return null;
                int len = msg[pos];
                if (len == 0) { next ??= pos + 1; break; }
                if ((len & 0xC0) == 0xC0)
                {
                    if (pos + 1 >= msg.Length) return null;
                    int target = (len & 0x3F) << 8 | msg[pos + 1];
                    if (target >= pos) return null;
                    next ??= pos + 2;
                    pos = target;
                    if (++jumps > 32) return null;
                    continue;
                }
                if (len > 63 || pos + 1 + len > msg.Length) return null;
                total += len + 1;
                if (total > 255) return null;
                var sb = new StringBuilder();
                foreach (byte by in msg.AsSpan(pos + 1, len))
                {
                    if (by == 46) sb.Append("\\.");
                    else if (by == 92) sb.Append("\\\\");
                    else if (by is >= 32 and <= 126) sb.Append((char)by);
                    else sb.Append($"\\{by:000}");
                }
                labels.Add(sb.ToString());
                pos += 1 + len;
            }
            return next is int n ? (string.Join(".", labels), n) : null;
        }

        // ---------------- TLS: ClientHello, JA3/JA4, certificates ----------------

        internal sealed class HelloInfo
        {
            public string? Sni; public bool Ech;
            public List<ushort> Ciphers = new(), Extensions = new(), Groups = new(), SigAlgs = new(), Versions = new();
            public List<byte> PointFormats = new();
            public List<string> Alpn = new();
            public int ClientVersion;
        }

        private static bool IsGrease(ushort v) => (v & 0x0F0F) == 0x0A0A;
        private static int? U16At(byte[] b, int o) => o + 1 < b.Length ? b[o] << 8 | b[o + 1] : null;

        internal static HelloInfo? ParseClientHello(byte[] hs)
        {
            if (hs.Length < 4 || hs[0] != 1) return null;
            int declared = hs[1] << 16 | hs[2] << 8 | hs[3];
            var body = hs.AsSpan(4, Math.Min(declared, hs.Length - 4)).ToArray();
            if (body.Length < 34) return null;
            var info = new HelloInfo { ClientVersion = U16At(body, 0) ?? 0 };
            int off = 2 + 32;
            if (off >= body.Length) return null;
            off += 1 + body[off];
            if (U16At(body, off) is not int csLen) return null;
            off += 2;
            if (off + csLen > body.Length) return null;
            for (int i = off; i < off + csLen; i += 2) if (U16At(body, i) is int v) info.Ciphers.Add((ushort)v);
            off += csLen;
            if (off >= body.Length) return null;
            off += 1 + body[off];
            if (U16At(body, off) is not int extLen) return null;
            off += 2;
            int extEnd = Math.Min(body.Length, off + extLen);
            while (off + 4 <= extEnd)
            {
                if (U16At(body, off) is not int etype || U16At(body, off + 2) is not int elen) break;
                int data = off + 4;
                if (data + elen > extEnd) break;
                info.Extensions.Add((ushort)etype);
                var seg = body.AsSpan(data, elen).ToArray();
                switch (etype)
                {
                    case 0:
                        if (seg.Length >= 5 && seg[2] == 0)
                        {
                            int nl = U16At(seg, 3) ?? 0;
                            if (nl > 0 && 5 + nl <= seg.Length) info.Sni = Encoding.UTF8.GetString(seg, 5, nl);
                        }
                        break;
                    case 0xFE0D: info.Ech = true; break;
                    case 10:
                        if (seg.Length >= 2 && U16At(seg, 0) is int n) for (int i = 2; i + 1 < Math.Min(seg.Length, 2 + n) + 0 && i + 1 <= Math.Min(seg.Length, 2 + n); i += 2) if (U16At(seg, i) is int gv) info.Groups.Add((ushort)gv);
                        break;
                    case 11:
                        if (seg.Length >= 1) info.PointFormats.AddRange(seg.AsSpan(1).ToArray());
                        break;
                    case 13:
                        if (seg.Length >= 2 && U16At(seg, 0) is int sn) for (int i = 2; i + 1 <= Math.Min(seg.Length, 2 + sn); i += 2) if (U16At(seg, i) is int sv) info.SigAlgs.Add((ushort)sv);
                        break;
                    case 16:
                        int p2 = 2;
                        while (p2 < seg.Length) { int l = seg[p2]; p2++; if (p2 + l <= seg.Length) info.Alpn.Add(Encoding.ASCII.GetString(seg, p2, l)); p2 += l; }
                        break;
                    case 43:
                        int p3 = 1;
                        while (p3 + 1 < seg.Length + 1 && p3 + 2 <= seg.Length) { if (U16At(seg, p3) is int vv) info.Versions.Add((ushort)vv); p3 += 2; }
                        break;
                }
                off = data + elen;
            }
            return info;
        }

        internal static string Ja3(HelloInfo info)
        {
            static IEnumerable<ushort> Strip(IEnumerable<ushort> xs) => xs.Where(x => !IsGrease(x));
            string s = $"{info.ClientVersion},{string.Join("-", Strip(info.Ciphers))},{string.Join("-", Strip(info.Extensions))},{string.Join("-", Strip(info.Groups))},{string.Join("-", info.PointFormats)}";
            return Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
        }

        internal static string Ja4(HelloInfo info, bool quic)
        {
            static List<ushort> Strip(IEnumerable<ushort> xs) => xs.Where(x => !IsGrease(x)).ToList();
            string version = info.Versions.Contains(0x0304) ? "13" : (info.Versions.Contains(0x0303) || info.ClientVersion == 0x0303 ? "12" : "13");
            var ciphers = Strip(info.Ciphers);
            var exts = Strip(info.Extensions);
            string alpn = info.Alpn.Count > 0 ? $"{info.Alpn[0][0]}{info.Alpn[0][^1]}" : "00";
            string cipherHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(",", ciphers.Select(c => c.ToString("x4")).OrderBy(x => x))))).ToLowerInvariant()[..12];
            string extPart = string.Join(",", exts.Where(e => e != 0 && e != 16).Select(e => e.ToString("x4")).OrderBy(x => x));
            string sigPart = string.Join(",", info.SigAlgs.Select(s2 => s2.ToString("x4")));
            string extHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(extPart + "_" + sigPart))).ToLowerInvariant()[..12];
            return $"{(quic ? "q" : "t")}{version}{(info.Sni != null ? "d" : "i")}{Math.Min(99, ciphers.Count):00}{Math.Min(99, exts.Count):00}{alpn}_{cipherHash}_{extHash}";
        }

        private void FeedTls(Decoded d, byte[] body)
        {
            if (d.Sport is not int sp || d.Dport is not int dp) return;
            string flowId = string.Join("|", new[] { $"{d.Src}:{sp}", $"{d.Dst}:{dp}" }.OrderBy(x => x));
            string key = flowId + "|" + $"{d.Src}:{sp}>{d.Dst}:{dp}";
            bool firstIsTls = body.Length >= 5 && body[0] is 20 or 21 or 22 or 23 && body[1] == 3;
            if (!_tlsStreams.ContainsKey(key))
            {
                if (!firstIsTls || _tlsStreams.Count >= 512) return;
                _tlsStreams[key] = new TlsStream { BaseSeq = d.TcpSeq };
            }
            var stream = _tlsStreams[key];
            if (stream.Finished) return;
            int offset = unchecked((int)(d.TcpSeq - stream.BaseSeq));
            if (offset >= 0 && stream.Buffered <= 24576)
            {
                stream.Segments.Add((d.TcpSeq, body));
                stream.Buffered += body.Length;
            }
            var assembled = new List<byte>();
            foreach (var seg in stream.Segments.OrderBy(s => unchecked((int)(s.Seq - stream.BaseSeq))))
            {
                int segOff = unchecked((int)(seg.Seq - stream.BaseSeq));
                if (segOff > assembled.Count) break;
                int skip = assembled.Count - segOff;
                if (skip < seg.Data.Length) assembled.AddRange(seg.Data.AsSpan(skip).ToArray());
                if (assembled.Count >= 16384) break;
            }
            int off = stream.ParsedOffset;
            while (off + 5 <= assembled.Count)
            {
                byte recType = assembled[off];
                if (recType is not (20 or 21 or 22 or 23)) { stream.Finished = true; break; }
                int recLen = assembled[off + 3] << 8 | assembled[off + 4];
                if (off + 5 + recLen > assembled.Count) break;
                var rec = assembled.GetRange(off + 5, recLen).ToArray();
                switch (recType)
                {
                    case 23: d.TlsAppData = true; break;
                    case 21: d.TlsEvent ??= "alert"; break;
                    case 22: ParseHandshake(rec, d); break;
                }
                off += 5 + recLen;
                if (off >= 16384) stream.Finished = true;
            }
            stream.ParsedOffset = off;
        }

        private void ParseHandshake(byte[] rec, Decoded d)
        {
            int off = 0;
            while (off + 4 <= rec.Length)
            {
                byte hsType = rec[off];
                int hsLen = rec[off + 1] << 16 | rec[off + 2] << 8 | rec[off + 3];
                if (off + 4 + hsLen > rec.Length) return;
                var hs = rec.AsSpan(off, 4 + hsLen).ToArray();
                switch (hsType)
                {
                    case 1:
                        if (ParseClientHello(hs) is { } info)
                        {
                            d.TlsEvent = "clientHello";
                            d.TlsSni = info.Sni;
                            d.TlsEch = info.Ech;
                            d.Hostname = info.Sni;
                            if (Fps.Count < 2000)
                                Fps.Add(new TlsFingerprint { Ja3 = Ja3(info), Ja4 = Ja4(info, false), Sni = info.Sni, Ech = info.Ech, Frame = CurrentNumber, ServerAddress = d.Dst, ServerPort = d.Dport ?? 0 });
                        }
                        break;
                    case 2: d.TlsEvent = "serverHello"; break;
                    case 11:
                        if (hs.Length >= 10)
                        {
                            int certLen = hs[7] << 16 | hs[8] << 8 | hs[9];
                            int certStart = 10;
                            if (certLen > 0 && certStart + certLen <= hs.Length)
                            {
                                var der = hs.AsSpan(certStart, certLen).ToArray();
                                if (Certs.Count < 1000)
                                {
                                    Certs.Add(new CertificateObservable
                                    {
                                        Sha1 = Convert.ToHexString(SHA1.HashData(der)).ToLowerInvariant(),
                                        Sha256 = Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant(),
                                        Frame = CurrentNumber, ServerAddress = d.Src, ServerPort = d.Sport ?? 0,
                                    });
                                }
                            }
                        }
                        break;
                }
                off += 4 + hsLen;
            }
        }

        // ---------------- Flows, destinations, finish ----------------

        private static string FlowKey(string src, int sport, string dst, int dport)
        {
            var a = $"{src}:{sport}"; var b = $"{dst}:{dport}";
            return string.CompareOrdinal(a, b) <= 0 ? a + "|" + b : b + "|" + a;
        }

        private void UpdateFlow(Decoded d, int number, int capturedLength)
        {
            if (d.Sport is not int sp || d.Dport is not int dp || d.Src == "Unknown") return;
            if (d.IsTcp)
            {
                string key = FlowKey(d.Src, sp, d.Dst, dp);
                if (!Flows.TryGetValue(key, out var f))
                {
                    if (Flows.Count >= 4096) return;
                    f = new Flow { Initiator = d.Src, InitiatorPort = sp, Server = d.Dst, ServerPort = dp };
                    Flows[key] = f; FlowOrder.Add(key);
                }
                bool syn = (d.TcpFlags & 0x02) != 0, ack = (d.TcpFlags & 0x10) != 0, rst = (d.TcpFlags & 0x04) != 0;
                bool fromServer = d.Src == f.Server && sp == f.ServerPort;
                if (syn && !ack)
                {
                    if (f.SynSeqs.Contains(d.TcpSeq)) { f.Retransmissions++; TcpRetransmissions++; }
                    f.SynSeqs.Add(d.TcpSeq);
                    if (f.SynFrames.Count < 200) f.SynFrames.Add(number);
                    if (!fromServer) { f.Initiator = d.Src; f.InitiatorPort = sp; f.Server = d.Dst; f.ServerPort = dp; }
                }
                if (syn && ack) f.Connected = true;
                if (rst)
                {
                    if (f.Connected) f.ResetLater = true;
                    else if (fromServer && f.SynFrames.Count > 0) { f.Refused = true; if (f.RefusedFrames.Count < 200) f.RefusedFrames.Add(number); }
                }
                if (d.PayloadLength > 0)
                {
                    string sk = $"{d.Src}:{sp}>{d.TcpSeq}:{d.PayloadLength}";
                    if (f.DataSeqs.Contains(sk)) { f.Retransmissions++; TcpRetransmissions++; }
                    if (f.DataSeqs.Count < 8192) f.DataSeqs.Add(sk);
                }
                switch (d.TlsEvent)
                {
                    case "clientHello": f.ClientHello = true; f.Ech = d.TlsEch; if (d.TlsSni != null) f.Sni = d.TlsSni; break;
                    case "serverHello": f.ServerHello = true; break;
                    case "alert": if (!f.ServerHello) f.AlertBeforeHello = true; break;
                }
                if (d.PlaintextProto == "HTTP") f.SawHttp = true;
                f.Packets++; f.Bytes += capturedLength;
                if (f.Frames.Count < 200) f.Frames.Add(number);
            }
            else if (d.Proto is "QUIC" or "UDP")
            {
                string key = FlowKey(d.Src, sp, d.Dst, dp);
                if (!UdpGroups.TryGetValue(key, out var g))
                {
                    if (UdpGroups.Count >= 2048) return;
                    string server; int serverPort;
                    if (dp <= 1024 || dp == 443) { server = d.Dst; serverPort = dp; }
                    else if (sp <= 1024 || sp == 443) { server = d.Src; serverPort = sp; }
                    else { server = d.Dst; serverPort = dp; }
                    g = (server, serverPort, d.IsQuic, 0, 0, new List<int>());
                    UdpGroups[key] = g; UdpOrder.Add(key);
                }
                g.Packets++; g.Bytes += capturedLength;
                if (g.Frames.Count < 200) g.Frames.Add(number);
                UdpGroups[key] = g;
            }
        }

        public CaptureReport Finish(int totalPackets)
        {
            var findings = new List<Finding>();
            if (DnsErrors > 0)
                findings.Add(new Finding { Id = "dns-errors", Severity = "warning", Title = "DNS error replies observed", Evidence = $"{DnsErrors} of {DnsResponses} visible DNS replies were error replies. An error reply is an observation, not proof of a bad ISP or malware.", Recommendation = "Check the name being looked up and the DNS server in use; retry the affected app and mark the moment it fails.", PacketNumbers = DnsErrorPackets.Take(20).ToList() });
            if (TcpResets > 0)
                findings.Add(new Finding { Id = "tcp-resets", Severity = "notice", Title = "TCP resets observed", Evidence = $"{TcpResets} of {TcpPackets} decoded TCP packets carried the RST flag. A reset can be a normal way to close a refused or finished connection.", Recommendation = "Note which app and destination were involved and whether the app reported an error at the same moment.", PacketNumbers = RstPackets.Take(20).ToList() });
            if (PlainRemote.Count > 0)
                findings.Add(new Finding { Id = "plaintext-remote", Severity = "warning", Title = "Plaintext application data observed", Evidence = $"Recognizable plaintext {string.Join(", ", PlainRemote.Select(p => p.Proto).Distinct().OrderBy(x => x))} content was visible beyond loopback in {PlainRemote.Count} packet(s). Contents were not stored in this report.", Recommendation = "Prefer the encrypted (HTTPS/TLS) version of the service where available and check which app sent it.", PacketNumbers = PlainRemote.Take(20).Select(p => p.Num).ToList() });
            if (PlainLocal.Count > 0)
                findings.Add(new Finding { Id = "plaintext-local", Severity = "info", Title = "Plaintext between addresses on this Mac", Evidence = $"Recognizable plaintext content was visible between loopback addresses in {PlainLocal.Count} packet(s). This finding by itself says nothing about the rest of the capture.", Recommendation = "No action is usually needed: traffic between loopback addresses stays on this device.", PacketNumbers = PlainLocal.Take(20).Select(p => p.Num).ToList() });

            // Destinations from flows and UDP groups
            var groups = new Dictionary<string, (DestinationRecord Rec, List<int> SynFrames, List<int> RefusedFrames)>();
            var order = new List<string>();
            foreach (var key in FlowOrder)
            {
                var f = Flows[key];
                string gk = $"{f.Server}:{f.ServerPort}/TCP";
                if (!groups.TryGetValue(gk, out var g))
                {
                    g = (new DestinationRecord { Address = f.Server, Port = f.ServerPort, ProtocolLabel = f.SawHttp ? "TCP · HTTP" : (f.ClientHello || f.ServerHello || f.Sni != null || f.ServerPort == 443 ? "TCP · TLS" : "TCP"), Outcome = "not_checked" }, new List<int>(), new List<int>());
                    groups[gk] = g; order.Add(gk);
                }
                var rec = g.Rec;
                rec.Attempts += f.SynFrames.Count;
                rec.Packets += f.Packets; rec.Bytes += f.Bytes;
                rec.PacketNumbers.AddRange(f.Frames);
                g.SynFrames.AddRange(f.SynFrames);
                g.RefusedFrames.AddRange(f.RefusedFrames);
                if (f.AlertBeforeHello) rec.TlsStatus = "failed"; else if (f.ServerHello) rec.TlsStatus = "passed";
                if (f.Ech) { if (rec.NameSource == null) { rec.NameSource = "sni_outer"; } }
                else if (rec.Name == null && f.Sni != null) { rec.Name = f.Sni; rec.NameSource = "sni"; }
                string flowOutcome = f.Connected && f.ResetLater ? "reset_later" : f.Connected ? "connected" : f.Refused ? "refused" : f.SynFrames.Count > 0 ? "no_reply" : "not_checked";
                var rank = new Dictionary<string, int> { ["connected"] = 4, ["reset_later"] = 3, ["refused"] = 2, ["no_reply"] = 2, ["not_checked"] = 1 };
                if (rec.Outcome == "not_checked" || rank[flowOutcome] > rank[rec.Outcome]) rec.Outcome = flowOutcome;
                if (rec.Outcome == "no_reply" && flowOutcome == "connected") rec.Outcome = "connected";
                groups[gk] = g;
            }
            foreach (var key in UdpOrder)
            {
                var u = UdpGroups[key];
                string gk = $"{u.Server}:{u.Port}/{(u.Quic ? "QUIC" : "UDP")}";
                if (!groups.TryGetValue(gk, out var g))
                {
                    g = (new DestinationRecord { Address = u.Server, Port = u.Port, ProtocolLabel = u.Quic ? "QUIC" : "UDP", Outcome = u.Quic ? "not_checked" : "background" }, new List<int>(), new List<int>());
                    groups[gk] = g; order.Add(gk);
                }
                g.Rec.Packets += u.Packets; g.Rec.Bytes += u.Bytes; g.Rec.PacketNumbers.AddRange(u.Frames);
                groups[gk] = g;
            }
            var destinations = new List<DestinationRecord>();
            foreach (var gk in order)
            {
                var g = groups[gk];
                var rec = g.Rec;
                if (rec.Name == null && IpToName.TryGetValue(rec.Address, out var dn)) { rec.Name = dn; rec.NameSource = "dns"; }
                bool isTcp = rec.ProtocolLabel.StartsWith("TCP");
                rec.EvidenceFilter = isTcp ? $"ip.addr=={rec.Address} && tcp.port=={rec.Port}" : (rec.ProtocolLabel == "QUIC" ? $"ip.addr=={rec.Address} && udp.port=={rec.Port}" : $"ip.addr=={rec.Address}");
                rec.EvidenceCount = rec.Packets;
                rec.PacketNumbers = rec.PacketNumbers.Take(200).ToList();
                destinations.Add(rec);
                groups[gk] = g;
            }
            var outcomeRank = new Dictionary<string, int> { ["no_reply"] = 0, ["refused"] = 0, ["reset_later"] = 1, ["connected"] = 2, ["not_checked"] = 3, ["background"] = 4 };
            destinations = destinations.OrderBy(x => outcomeRank.GetValueOrDefault(x.Outcome, 5)).ThenByDescending(x => x.Packets).ToList();

            if (Nxdomains.Count > 0)
                findings.Add(new Finding { Id = "dns-name-not-found", Severity = "likely_cause", Title = $"The name {Nxdomains[0].Name} was reported as not existing", Evidence = $"The DNS server replied that {Nxdomains[0].Name} does not exist (NXDOMAIN), in packet #{Nxdomains[0].Frame}. {DnsErrors} of {DnsResponses} visible DNS replies were error replies.", Recommendation = "Check the spelling of the name and whether the service has changed or removed it; try the correct name, then capture again.", PacketNumbers = Nxdomains.Take(20).Select(x => x.Frame).ToList() });
            foreach (var rec in destinations.Where(x => x.Outcome == "refused"))
                findings.Add(new Finding { Id = "refused-connection", Severity = "likely_cause", Title = $"{rec.Name ?? rec.Address} refused the connection", Evidence = $"The destination at {rec.Address} port {rec.Port} answered connection attempts with a reset (refused), across {rec.Attempts} attempt(s).", Recommendation = "Check whether the service is running on that device and whether a firewall on it is rejecting the connection; then try again.", PacketNumbers = rec.PacketNumbers.Take(20).ToList() });
            int unansweredAttempts = 0, refusedAttempts = 0;
            foreach (var rec in destinations.Where(x => x.Outcome == "no_reply" && x.Attempts >= 1))
            {
                unansweredAttempts += rec.Attempts;
                findings.Add(new Finding { Id = "unanswered-connection", Severity = rec.Attempts >= 2 ? "likely_cause" : "warning", Title = $"{rec.Name ?? rec.Address} never answered the connection attempts", Evidence = $"{rec.Attempts} connection request(s) (TCP SYN) to {rec.Address} on port {rec.Port} received no reply of any kind: no SYN-ACK, no reset, no ICMP error. {destinations.Count(x => x.Outcome == "connected")} other destination(s) connected successfully in this capture.", Recommendation = "Try the same website or app on a different network, such as a phone hotspot. If it works there, a firewall, VPN, or filter on this network is likely blocking it; if it fails everywhere, the service may be down.", PacketNumbers = rec.PacketNumbers.Take(20).ToList() });
            }
            foreach (var rec in destinations.Where(x => x.Outcome == "refused")) refusedAttempts += rec.Attempts;
            if (TlsAlertPackets.Count > 0)
                findings.Add(new Finding { Id = "tls-alerts", Severity = "warning", Title = "Secure setup (TLS) alerts observed", Evidence = $"{TlsAlertPackets.Count} TLS alert(s) were visible. An alert can mean the secure setup was rejected or failed.", Recommendation = "Check the device date and time, then retry; if it repeats for one service, share this report with its support team.", PacketNumbers = TlsAlertPackets.Take(20).ToList() });
            var sortedIntervals = Intervals.OrderBy(x => x).ToList();
            double? p95 = sortedIntervals.Count == 0 ? null : sortedIntervals[Math.Min(sortedIntervals.Count - 1, (int)Math.Ceiling(0.95 * sortedIntervals.Count) - 1)];
            if (p95 is double pv && pv > 300)
                findings.Add(new Finding { Id = "slow-dns", Severity = "warning", Title = "Name lookups were slow", Evidence = $"Matched DNS exchanges averaged {(Intervals.Count > 0 ? Intervals.Average() : 0):0} ms and the slowest 5% took at least {pv:0} ms across {Intervals.Count} pair(s).", Recommendation = "Compare this after changing one thing at a time, such as trying a different network.", PacketNumbers = new List<int>() });
            var sevRank = new Dictionary<string, int> { ["likely_cause"] = 0, ["warning"] = 1, ["notice"] = 2, ["info"] = 3 };
            findings = findings.OrderBy(f => sevRank.GetValueOrDefault(f.Severity, 4)).ToList();

            int answeredLookups = Lookups.Count(l => l.Milliseconds != null);
            int unansweredLookups = Math.Max(0, DnsQueryCount - answeredLookups);
            var checks = new List<CheckRecord>
            {
                new() { Id = "dns-errors", Label = "DNS errors (NXDOMAIN, SERVFAIL)", Count = DnsErrors, Flagged = DnsErrors > 0, Note = DnsErrors > 0 ? "See findings" : "None", PacketNumbers = DnsErrorPackets.Take(200).ToList(), Filter = "dns.flags.response == 1 && dns.flags.rcode != 0" },
                new() { Id = "dns-unanswered", Label = "DNS lookups with no answer", Count = unansweredLookups, Flagged = unansweredLookups > 0, Note = unansweredLookups > 0 ? "No matching reply was captured" : "None", Filter = "dns.flags.response == 0 && !dns.response_in" },
                new() { Id = "tcp-refused", Label = "Refused connections (TCP reset)", Count = refusedAttempts, Flagged = refusedAttempts > 0, Note = refusedAttempts > 0 ? "Destination refused" : "None", Filter = "tcp.flags.reset == 1" },
                new() { Id = "tcp-unanswered", Label = "Unanswered connection attempts", Count = unansweredAttempts, Flagged = unansweredAttempts > 0, Note = unansweredAttempts > 0 ? "No reply captured" : "None", PacketNumbers = destinations.Where(x => x.Outcome == "no_reply").SelectMany(x => x.PacketNumbers).Take(200).ToList(), Filter = destinations.Where(x => x.Outcome == "no_reply").SelectMany(x => x.PacketNumbers).Take(200).ToList() is { Count: > 0 } synFrames ? "frame.number in {" + string.Join(", ", synFrames) + "}" : "" },
                new() { Id = "icmp-unreachable", Label = "ICMP unreachable messages", Count = IcmpPackets.Count, Flagged = IcmpPackets.Count > 0, Note = IcmpPackets.Count > 0 ? "A device reported it could not deliver traffic" : "None", PacketNumbers = IcmpPackets.ToList(), Filter = "icmp.type == 3 || icmpv6.type == 1" },
                new() { Id = "tls-alerts", Label = "TLS alerts or failed handshakes", Count = TlsAlertPackets.Count, Flagged = TlsAlertPackets.Count > 0, Note = TlsAlertPackets.Count > 0 ? "Secure setup was rejected or failed" : "None", PacketNumbers = TlsAlertPackets.ToList(), Filter = "tls.record.content_type == 21" },
                new() { Id = "tcp-retransmissions", Label = "TCP retransmissions", Count = TcpRetransmissions, Flagged = TcpRetransmissions > 20, Note = TcpRetransmissions == 0 ? "None" : (TcpRetransmissions > 20 ? "High level" : "Normal level"), Filter = "tcp.analysis.retransmission" },
                new() { Id = "kernel-drops", Label = "Packets dropped by capture", Count = 0, Flagged = false, Note = "Nothing lost", Filter = "" },
            };
            int checkedCount = Math.Max(0, totalPackets - QuicPackets - EncryptedOther - Undecodable);
            var mixOrder = new[] { "TCP", "DNS", "QUIC", "UDP_OTHER", "ICMP", "OTHER" };
            var mix = mixOrder.Where(n => MixStats.ContainsKey(n)).Select(n => new ProtocolCount { Name = n, Count = MixStats[n].Count, Bytes = MixStats[n].Bytes }).ToList();

            var facts = new CaptureFacts
            {
                FirstTimestamp = FirstTs,
                LastTimestamp = FirstTs is null ? null : LastTs,
                DnsResponses = DnsResponses, DnsErrors = DnsErrors, TcpPackets = TcpPackets, TcpResets = TcpResets,
                AverageDnsMilliseconds = Intervals.Count > 0 ? Intervals.Average() : null,
                MatchedDnsPairs = Intervals.Count,
                DnsQueries = DnsQueryCount, DnsAnswered = answeredLookups, DnsUnanswered = unansweredLookups,
                DnsP95Milliseconds = p95, DnsMaxMilliseconds = sortedIntervals.Count > 0 ? sortedIntervals[^1] : null,
                DnsResolvers = Resolvers, DnsLookups = Lookups,
                TcpRetransmissions = TcpRetransmissions, IcmpUnreachable = IcmpPackets.Count, TlsAlerts = TlsAlertPackets.Count,
                QuicPackets = QuicPackets, EncryptedOtherPackets = EncryptedOther, CheckedPackets = checkedCount,
                Destinations = destinations, Checks = checks, ArpResponder = ArpResponder, TrafficMix = mix,
                HttpHosts = HttpHosts, HttpUrls = HttpUrls, CnameTargets = Cnames, Certificates = Certs, Fingerprints = Fps,
                ObservableEndpoints = ObsEndpoints.Values.OrderByDescending(e => e.Packets).ToList(),
                ObservableIpCount = ObsIps.Count, ObservableTruncated = ObsTruncated,
                Timeline = Buckets.Values.OrderBy(b2 => b2.Second).ToList(),
                Domains = DomainOrder.Where(Domains.ContainsKey).Select(n => { var d = Domains[n]; return (n, d.Addr, d.Queries, d.Errors, d.Frames); }).ToList(),
            };
            var notes = new List<string>();
            if (totalPackets > DisplayLimit) notes.Add($"Showing the first {DisplayLimit} of {totalPackets} packets in the packet log. Totals, findings, timeline, and endpoint statistics cover the entire file.");
            if (Undecodable > 0) notes.Add($"{Undecodable} packet(s) could not be decoded beyond a counted entry; no bytes were read past their frames.");
            if (totalPackets == 0) notes.Add("This capture contains no packets. An empty capture does not prove the network is healthy; the selected interface may simply have seen no traffic.");
            return new CaptureReport
            {
                PacketCount = totalPackets,
                CapturedBytes = CapturedBytes,
                Duration = FirstTs is double f0 ? Math.Max(0, LastTs - f0) : 0,
                Protocols = ProtoStats.Select(kv => new ProtocolCount { Name = kv.Key, Count = kv.Value.Count, Bytes = kv.Value.Bytes }).OrderByDescending(p => p.Count).ToList(),
                Endpoints = EndpointStats.Select(kv => new EndpointStat { Address = kv.Key, Packets = kv.Value.Packets, Bytes = kv.Value.Bytes }).OrderByDescending(e => e.Bytes).Take(200).ToList(),
                Findings = findings,
                Packets = Records,
                LimitationNotes = notes,
                Facts = facts,
            };
        }
    }
}

using PacketScope.Windows;

// Minimal assertion harness for the Windows build's platform-independent
// logic (analyzer, results builder, threat-intel parsers/matcher). The
// WinForms UI and Npcap capture can only run on Windows itself.

int passed = 0, failed = 0;
void Check(bool cond, string name)
{
    if (cond) { passed++; Console.WriteLine($"PASS {name}"); }
    else { failed++; Console.WriteLine($"FAIL {name}"); }
}
void Eq<T>(T actual, T expected, string name) => Check(EqualityComparer<T>.Default.Equals(actual, expected), $"{name} (expected {expected}, got {actual})");

// ---- PCAP builders (synthetic, tests only) ----
static byte[] U16(int v) => new[] { (byte)(v >> 8), (byte)v };
static byte[] U32(uint v) => new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v };
static byte[] Ipv4(string src, string dst, int proto, byte[] payload)
{
    var s = src.Split('.').Select(byte.Parse).ToArray();
    var d = dst.Split('.').Select(byte.Parse).ToArray();
    var h = new List<byte> { 0x45, 0 };
    h.AddRange(U16(20 + payload.Length)); h.AddRange(U16(1)); h.AddRange(U16(0));
    h.AddRange(new byte[] { 64, (byte)proto, 0, 0 }); h.AddRange(s); h.AddRange(d);
    return h.Concat(payload).ToArray();
}
static byte[] Tcp(string src, string dst, int sport, int dport, byte flags, byte[] payload = null!)
{
    var h = new List<byte>();
    h.AddRange(U16(sport)); h.AddRange(U16(dport)); h.AddRange(U32(100)); h.AddRange(U32(0));
    h.AddRange(new byte[] { 0x50, flags }); h.AddRange(U16(8192)); h.AddRange(U16(0)); h.AddRange(U16(0));
    return Ipv4(src, dst, 6, h.Concat(payload ?? Array.Empty<byte>()).ToArray());
}
static byte[] UdpDns(string src, string dst, int sport, int dport, byte[] payload)
{
    var h = new List<byte>();
    h.AddRange(U16(sport)); h.AddRange(U16(dport)); h.AddRange(U16(8 + payload.Length)); h.AddRange(U16(0));
    return Ipv4(src, dst, 17, h.Concat(payload).ToArray());
}
static byte[] DnsName(string name)
{
    var outBytes = new List<byte>();
    foreach (var label in name.Split('.')) { outBytes.Add((byte)label.Length); outBytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label)); }
    outBytes.Add(0);
    return outBytes.ToArray();
}
static byte[] DnsMsg(int id, bool response, int rcode, string name, string? answerIp = null)
{
    var m = new List<byte>();
    m.AddRange(U16(id)); m.AddRange(U16((response ? 0x8000 : 0) | rcode));
    m.AddRange(U16(1)); m.AddRange(U16(answerIp != null ? 1 : 0)); m.AddRange(U16(0)); m.AddRange(U16(0));
    m.AddRange(DnsName(name)); m.AddRange(U16(1)); m.AddRange(U16(1));
    if (answerIp != null)
    {
        m.AddRange(DnsName(name)); m.AddRange(U16(1)); m.AddRange(U16(1)); m.AddRange(U32(60)); m.AddRange(U16(4));
        m.AddRange(answerIp.Split('.').Select(byte.Parse));
    }
    return m.ToArray();
}
static byte[] Pcap(int linkType, List<(double Ts, byte[] Frame)> packets)
{
    var outBytes = new List<byte>();
    outBytes.AddRange(new byte[] { 0xD4, 0xC3, 0xB2, 0xA1 }); // little-endian usec
    void W16(int v) { outBytes.Add((byte)v); outBytes.Add((byte)(v >> 8)); }
    void W32(uint v) { outBytes.Add((byte)v); outBytes.Add((byte)(v >> 8)); outBytes.Add((byte)(v >> 16)); outBytes.Add((byte)(v >> 24)); }
    W16(2); W16(4); W32(0); W32(0); W32(65535); W32((uint)linkType);
    foreach (var (ts, frame) in packets)
    {
        W32((uint)ts); W32((uint)((ts - (uint)ts) * 1_000_000)); W32((uint)frame.Length); W32((uint)frame.Length);
        outBytes.AddRange(frame);
    }
    return outBytes.ToArray();
}

// 1. PCAPNG rejected
try { PacketAnalyzer.Analyze(new byte[] { 0x0A, 0x0D, 0x0D, 0x0A }.Concat(new byte[24]).ToArray()); Check(false, "pcapng rejected"); }
catch (AnalyzerException ex) { Check(ex.Message.Contains("PCAPNG"), "pcapng rejected"); }

// 2. Unanswered connection -> likely cause, step 3 failed
{
    var pkts = new List<(double, byte[])>();
    pkts.Add((1000, UdpDns("192.168.1.23", "192.168.1.1", 40000, 53, DnsMsg(1, false, 0, "api.example.com"))));
    pkts.Add((1000.03, UdpDns("192.168.1.1", "192.168.1.23", 53, 40000, DnsMsg(1, true, 0, "api.example.com", "203.0.113.10"))));
    foreach (var t in new[] { 1012.04, 1013.05, 1015.07, 1019.10, 1027.12, 1033.04 })
        pkts.Add((t, Tcp("192.168.1.23", "203.0.113.10", 51544, 443, 0x02)));
    for (int i = 0; i < 10; i++) pkts.Add((1040 + i, Tcp("192.168.1.23", "203.0.113.99", 51000, 443, 0x10)));
    pkts.Sort((a, b) => a.Item1.CompareTo(b.Item1));
    var rep = PacketAnalyzer.Analyze(Pcap(101, pkts));
    var dest = rep.Facts!.Destinations.FirstOrDefault(d => d.Address == "203.0.113.10");
    Eq(dest?.Outcome, "no_reply", "unanswered outcome");
    Eq(dest?.Name, "api.example.com", "destination named from DNS");
    var ctx = new SessionContext { Goal = CaptureGoal.Website, Interface = "Ethernet0" };
    ctx.Markers.Add(new ProblemMarker { Timestamp = 1014 });
    var results = CaptureResultsBuilder.Build(rep, ctx, 0);
    Eq(results.Verdict, "cause_found", "verdict cause_found");
    var path = results.Paths.First(p => p.Destination == "api.example.com");
    Eq(path.Stages.First(s => s.Id == "tcp").Status, "failed", "step 3 failed");
    Eq(path.Stages.First(s => s.Id == "tls").Status, "not_reached", "tls not reached");
    Check(results.Findings.Any(f => f.Id == "unanswered-connection" && f.Severity == "likely_cause"), "likely-cause finding with SYN frames");
}

// 3. NXDOMAIN fails step 2
{
    var pkts = new List<(double, byte[])>
    {
        (1000, UdpDns("192.168.1.23", "192.168.1.1", 40000, 53, DnsMsg(1, false, 0, "no-such-host-4821.example.com"))),
        (1000.03, UdpDns("192.168.1.1", "192.168.1.23", 53, 40000, DnsMsg(1, true, 3, "no-such-host-4821.example.com"))),
    };
    for (int i = 0; i < 10; i++) pkts.Add((1001 + i, Tcp("192.168.1.23", "203.0.113.5", 51000, 443, 0x10)));
    var rep = PacketAnalyzer.Analyze(Pcap(101, pkts));
    var results = CaptureResultsBuilder.Build(rep, new SessionContext { Goal = CaptureGoal.Website, Interface = "Ethernet0" }, 0);
    Eq(results.Verdict, "cause_found", "nxdomain verdict");
    Check(results.Findings.Any(f => f.Id == "dns-name-not-found" && f.Title.Contains("no-such-host-4821.example.com")), "nxdomain finding names the domain");
    Eq(results.Paths[0].Stages.First(s => s.Id == "dns").Status, "failed", "step 2 failed");
}

// 4. Refused says refused
{
    var pkts = new List<(double, byte[])>
    {
        (1000, Tcp("192.168.1.23", "192.168.1.1", 51000, 81, 0x02)),
        (1000.05, Tcp("192.168.1.1", "192.168.1.23", 81, 51000, 0x14)),
    };
    for (int i = 0; i < 10; i++) pkts.Add((1001 + i, Tcp("192.168.1.23", "203.0.113.5", 51001, 443, 0x10)));
    var rep = PacketAnalyzer.Analyze(Pcap(101, pkts));
    Eq(rep.Facts!.Destinations.FirstOrDefault(d => d.Address == "192.168.1.1")?.Outcome, "refused", "refused outcome");
    Check(rep.Findings.Any(f => f.Id == "refused-connection"), "refused finding");
    Check(!rep.Findings.Any(f => f.Id == "unanswered-connection"), "not labelled unanswered");
}

// 5. Threat matching with the synthetic test feed
{
    const string csv = """
type,value,threat,severity
ipv4,203.0.113.50,botnet_c2,high
ip_port,198.51.100.7:8443,botnet_c2,high
cidr,198.51.100.128/25,hijacked_netblock,medium
domain,c2.test-ioc.example,botnet_c2,high
url,http://downloads.test-ioc.example/payload.bin,malware_download,high
ipv4,10.0.0.5,botnet_c2,high
""";
    var meta = new FeedMeta { Id = "test_feed", Name = "Synthetic test feed", License = "Test", BaseSeverity = "high", Parser = "test_csv" };
    var parsed = FeedParser.Parse(meta, System.Text.Encoding.UTF8.GetBytes(csv));
    Eq(parsed.Indicators.Count, 6, "test feed parses");
    var store = new IndicatorStore();
    store.Load(parsed.Indicators, null, DateTimeOffset.Now);
    var pkts = new List<(double, byte[])>
    {
        (1000, Tcp("192.168.1.23", "203.0.113.50", 51000, 443, 0x02)),
        (1000.05, Tcp("203.0.113.50", "192.168.1.23", 443, 51000, 0x12)),
    };
    var rep = PacketAnalyzer.Analyze(Pcap(101, pkts));
    var outcome = IntelMatcher.Match(rep, store, new Dictionary<string, FeedMeta> { ["test_feed"] = meta }, new List<AllowlistEntry>(), DateTimeOffset.Now);
    Check(outcome.Matches.Any(m => m.MatchedOn == "ipv4" && m.Severity == "high"), "connected listed IP -> high");
    var intel = ThreatIntelSummary.Make(outcome, new List<FeedRef>(), "checked");
    Eq(intel.SecurityAlert, "high", "security alert high");
    // DNS-only domain match drops one level
    var dnsPkts = new List<(double, byte[])> { (1000, UdpDns("192.168.1.23", "192.168.1.1", 40000, 53, DnsMsg(1, false, 0, "c2.test-ioc.example"))) };
    var dnsRep = PacketAnalyzer.Analyze(Pcap(101, dnsPkts));
    var dnsOutcome = IntelMatcher.Match(dnsRep, store, new Dictionary<string, FeedMeta> { ["test_feed"] = meta }, new List<AllowlistEntry>(), DateTimeOffset.Now);
    var dm = dnsOutcome.Matches.FirstOrDefault(m => m.MatchedOn == "domain");
    Eq(dm?.Severity, "medium", "dns-only domain one level lower");
    Check(dm?.SeverityReasons.Contains("downgraded: contact attempted, not completed") ?? false, "attempted-not-completed reason");
}

// 6. Exported-packet subset
{
    var pkts = Enumerable.Range(0, 5).Select(i => ((double)(1000 + i), UdpDns("10.0.0.1", "10.0.0.2", 1000, 2000, DnsMsg(1, false, 0, "a.example.com")))).ToList();
    string dir = Path.Combine(Path.GetTempPath(), "ps-win-tests-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    string src = Path.Combine(dir, "in.pcap"), dst = Path.Combine(dir, "out.pcap");
    File.WriteAllBytes(src, Pcap(101, pkts));
    PacketAnalyzer.ExportPacketSubset(src, new HashSet<int> { 2, 4 }, dst);
    var rep = PacketAnalyzer.Analyze(dst);
    Eq(rep.PacketCount, 2, "export subset writes only listed frames");
    Directory.Delete(dir, true);
}

Console.WriteLine("---");
Console.WriteLine($"{passed} passed, {failed} failed");
return failed == 0 ? 0 : 1;

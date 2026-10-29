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


// Shared sample location for parity tests.
var samplesDirPath = new Lazy<string>(() =>
{
    string candidate = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "samples"));
    return Directory.Exists(candidate) ? candidate : Path.GetFullPath("samples");
});

// 7. AI summary (Windows): settings guard, validator, and service fallback
{
    var settings = new AiSettings { Enabled = true, Endpoint = "https://models.example.com", Model = "x" };
    Check(settings.ValidationError != null, "non-loopback AI endpoint is rejected");
    settings.Endpoint = "http://127.0.0.1:11434";
    Check(settings.ValidationError == null, "loopback AI endpoint is accepted");

    var facts = new CaptureFacts
    {
        DnsQueries = 9, DnsAnswered = 9,
        Destinations = new List<DestinationRecord> { new() { Name = "api.example.com", Address = "203.0.113.10", Port = 443, ProtocolLabel = "TCP · TLS", Outcome = "connected", Packets = 31, Attempts = 1 } },
    };
    var aiReport = new CaptureReport { PacketCount = 157, CapturedBytes = 71345, Duration = 3.8, Facts = facts };
    var aiResults = CaptureResultsBuilder.Build(aiReport, new SessionContext { Goal = CaptureGoal.Website, Interface = "Ethernet0" }, 0);
    string Input() => SummaryValidator.ModelInputJson(aiResults);

    var good = new AiCandidate { Headline = "All measured connections succeeded in this capture", Body = "9 of 9 name lookups were answered. The connections your device started completed during these 3.8 seconds.", NextStep = "Capture again and mark the moment if it happens again.", Citations = new() { new AiCandidate.AiCitation { Text = "9 of 9 name lookups were answered", Anchor = "#dns" } } };
    Check(SummaryValidator.Validate(good, aiResults, Input()) != null, "validator accepts a compliant summary");
    var invented = new AiCandidate { Headline = "There were 999 failures", Body = "All 999 attempts failed during this capture.", NextStep = "Retry.", Citations = new() };
    Check(SummaryValidator.Validate(invented, aiResults, Input()) == null, "validator rejects invented numbers");
    var infected = new AiCandidate { Headline = "This device is infected", Body = "The device is infected with malware.", NextStep = "Scan it.", Citations = new() };
    Check(SummaryValidator.Validate(infected, aiResults, Input()) == null, "validator rejects 'infected' verdict language");
    var feedsNoMatch = new AiCandidate { Headline = "Nothing was flagged by threat feeds", Body = "No matches in 4 threat feeds were found.", NextStep = "Capture again.", Citations = new() };
    Check(SummaryValidator.Validate(feedsNoMatch, aiResults, Input()) == null, "validator rejects threat-feed talk when there are no matches");

    // Service behaviour with a fake loopback model.
    var handler = new FakeModelHandler();
    var summarizer = new LocalModelSummarizer(new HttpClient(handler));
    var aiOn = new AiSettings { Enabled = true, Endpoint = "http://127.0.0.1:11434", Model = "llama3.1:8b" };
    handler.ResponseJson = """{"headline":"All measured connections succeeded in this capture","body":"9 of 9 name lookups were answered. The connections your device started completed.","nextStep":"Capture again and mark the moment if it happens again.","citations":[{"text":"9 of 9 name lookups were answered","anchor":"#dns"}]}""";
    var used = ResultsSummaryService.SummarizeAsync(aiResults, aiOn, summarizer).GetAwaiter().GetResult();
    Check(!used.FromTemplate, "valid model wording is used");
    handler.ResponseJson = """{"headline":"There were 999 failures","body":"All 999 attempts failed.","nextStep":"Retry.","citations":[]}""";
    var fellBack = ResultsSummaryService.SummarizeAsync(aiResults, aiOn, summarizer).GetAwaiter().GetResult();
    Check(fellBack.FromTemplate, "invalid model wording falls back to the template");
    int callsBefore = handler.Calls;
    var off = ResultsSummaryService.SummarizeAsync(aiResults, new AiSettings { Enabled = false }, summarizer).GetAwaiter().GetResult();
    Check(off.FromTemplate && handler.Calls == callsBefore, "disabled AI never calls the model");
    Check(!aiResults.TemplateSummary.Headline.Equals("", StringComparison.Ordinal), "template summary is never empty");
}


// 8. Display filters match Wireshark counts (tshark, when available)
{
    string? tshark = new[] { @"C:\Program Files\Wireshark\tshark.exe", "/opt/homebrew/bin/tshark", "/usr/local/bin/tshark" }
        .FirstOrDefault(File.Exists);
    if (tshark == null)
    {
        Console.WriteLine("NOTE: tshark not installed; filter-count check skipped");
    }
    else
    {
        int TsharkCount(string pcap, string filter)
        {
            var psi = new System.Diagnostics.ProcessStartInfo(tshark, $"-r \"{pcap}\" -Y \"{filter.Replace("\"", "\\\"")}\" -T fields -e frame.number")
            { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            using var proc = System.Diagnostics.Process.Start(psi)!;
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            return output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;
        }
        var pkts = new List<(double, byte[])>
        {
            (1000, UdpDns("192.168.1.23", "192.168.1.1", 40000, 53, DnsMsg(7, false, 0, "silent.example.com"))),
            (1001, Tcp("192.168.1.23", "203.0.113.10", 51544, 443, 0x02)),
            (1002, Tcp("192.168.1.23", "203.0.113.10", 51544, 443, 0x02)),
            (1003, Tcp("192.168.1.23", "203.0.113.10", 51544, 443, 0x02)),
        };
        for (int i = 0; i < 10; i++) pkts.Add((1030 + i, Tcp("192.168.1.23", "203.0.113.99", 51000, 443, 0x10)));
        string dir = Path.Combine(Path.GetTempPath(), "ps-win-filter-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string pcapPath = Path.Combine(dir, "fixture.pcap");
        File.WriteAllBytes(pcapPath, Pcap(101, pkts));
        var rep = PacketAnalyzer.Analyze(pcapPath);
        var unanswered = rep.Facts!.Checks.First(c => c.Id == "tcp-unanswered");
        Eq(unanswered.Count, 3, "windows unanswered count");
        Check(unanswered.Filter.StartsWith("frame.number in {"), "windows unanswered filter built from frames");
        Eq(TsharkCount(pcapPath, unanswered.Filter), 3, "tshark matches the shown unanswered count");
        var dnsCheck = rep.Facts!.Checks.First(c => c.Id == "dns-unanswered");
        Eq(dnsCheck.Filter, "dns.flags.response == 0 && !dns.response_in", "windows unanswered-DNS filter");
        Eq(TsharkCount(pcapPath, dnsCheck.Filter), 1, "tshark matches the shown unanswered-DNS count");
        Directory.Delete(dir, true);
    }
}


// 9. Custom feed form flow: import samples/threat-demo-feed.txt as Domain /
// one-per-line, then the threat-demo sample must flag example.com (as on Mac).
{
    string samplesDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "samples"));
    if (!Directory.Exists(samplesDir)) samplesDir = Path.GetFullPath("samples");
    var dir = Path.Combine(Path.GetTempPath(), "ps-win-custom-" + Guid.NewGuid().ToString("N"));
    var updater = new FeedUpdater(dir, new InMemoryKeyStore());
    var meta = new FeedMeta { Id = "custom-demo", Name = "Threat demo feed", Url = "file://custom", License = "Demo", EnabledByDefault = true, RefreshSec = 86400, MinRefreshSec = 300, MaxAgeSec = 259200, BaseSeverity = "high", Parser = "custom_lines" };
    updater.ImportLocalCopy(meta, File.ReadAllBytes(Path.Combine(samplesDir, "threat-demo-feed.txt")), "domain");
    var (store, perFeedDbg) = updater.LoadStore(DateTimeOffset.Now, new List<FeedMeta> { meta });
    var directParse = FeedParser.Parse(meta, File.ReadAllBytes(Path.Combine(samplesDir, "threat-demo-feed.txt")), "domain");
    Eq(store.Count, 1, "custom demo feed stores one indicator");
    var rep = PacketAnalyzer.Analyze(Path.Combine(samplesDir, "threat-demo.pcap"));
    var outcome = IntelMatcher.Match(rep, store, new Dictionary<string, FeedMeta> { [meta.Id] = meta }, new List<AllowlistEntry>(), DateTimeOffset.Now);
    Check(outcome.Matches.Any(m => m.MatchedOn == "domain" && m.Observed == "example.com"), "threat demo flags example.com");
    var intel = ThreatIntelSummary.Make(outcome, new List<FeedRef>(), "checked");
    var results = CaptureResultsBuilder.Build(rep, new SessionContext { Goal = CaptureGoal.Website, Interface = "Ethernet0" }, 0, intel);
    Eq(results.SecurityAlert, "high", "threat demo security alert high");
    Check(results.Findings.Any(f => f.Category == "security" && f.Title.Contains("example.com")), "security finding names example.com");
}

// 10. Support report preview options + redaction (as on Mac)
{
    var rep = PacketAnalyzer.Analyze(Path.Combine(samplesDirPath.Value, "threat-demo.pcap"));
    var ctx = new SessionContext { Interface = "Ethernet0", Symptom = "cannot reach example.com from 192.168.1.23" };
    string defaultText = SupportReportText.Generate(rep, ctx, null);
    Check(!defaultText.Contains("example.com"), "domains off by default in support report");
    Check(!defaultText.Contains("cannot reach"), "notes off by default in support report");
    var withNotes = SupportReportText.Generate(rep, ctx, null, new SupportOptions { IncludeNotes = true });
    Check(withNotes.Contains("cannot reach"), "notes appear when opted in");
    Check(!withNotes.Contains("192.168.1.23") && withNotes.Contains("[address hidden]"), "IPs inside opted-in notes are still redacted");
    Check(!withNotes.Contains("example.com") && withNotes.Contains("[domain hidden]"), "domains inside opted-in notes are still redacted");
}

// 11. Never-flagged scope + abuse.ch date downgrade (parity with Mac)
{
    Check(Normalize.IsNeverFlaggedIp("192.0.0.9"), "192.0.0.9 is never-flagged (/24)");
    Check(!Normalize.IsNeverFlaggedIp("192.0.78.9"), "192.0.78.9 is not never-flagged");
    var ind = new Indicator { FeedId = "feodo_recommended", Type = "ipv4", Value = "203.0.113.50", Threat = "botnet_c2", Severity = "high", LastSeen = "2026-03-12" };
    var store = new IndicatorStore();
    store.Load(new List<Indicator> { ind }, null, DateTimeOffset.Now);
    var meta = new FeedMeta { Id = "feodo_recommended", Name = "Feodo Tracker", License = "CC0", BaseSeverity = "high", Parser = "feodo_json" };
    var pkts = new List<(double, byte[])>
    {
        (1000, Tcp("192.168.1.23", "203.0.113.50", 51000, 443, 0x02)),
        (1000.01, Tcp("203.0.113.50", "192.168.1.23", 443, 51000, 0x12)),
    };
    var rep = PacketAnalyzer.Analyze(Pcap(101, pkts));
    var outcome = IntelMatcher.Match(rep, store, new Dictionary<string, FeedMeta> { [meta.Id] = meta }, new List<AllowlistEntry>(), DateTimeOffset.FromUnixTimeSeconds(1793500000));
    Eq(outcome.Matches.FirstOrDefault(m => m.MatchedOn == "ipv4")?.Severity, "medium", "windows feodo-format date downgrades one level");
}

// 12. Sample parity with the Mac app (verdicts and check counts)
{
    string dir = samplesDirPath.Value;
    var unanswered = PacketAnalyzer.Analyze(Path.Combine(dir, "unanswered-connection.pcap"));
    var ur = CaptureResultsBuilder.Build(unanswered, new SessionContext { Goal = CaptureGoal.Website, Interface = "en0" }, 0);
    Eq(ur.Verdict, "cause_found", "sample unanswered verdict");
    Eq(unanswered.Facts!.Checks.First(c => c.Id == "tcp-unanswered").Count, 8, "sample unanswered count");
    var nx = PacketAnalyzer.Analyze(Path.Combine(dir, "name-not-found.pcap"));
    var nr = CaptureResultsBuilder.Build(nx, new SessionContext { Goal = CaptureGoal.Website, Interface = "en0" }, 0);
    Eq(nr.Verdict, "cause_found", "sample name-not-found verdict");
    Eq(nx.Facts!.Checks.First(c => c.Id == "dns-errors").Count, 1, "sample dns error count");
    var threat = PacketAnalyzer.Analyze(Path.Combine(dir, "threat-demo.pcap"));
    var tr = CaptureResultsBuilder.Build(threat, new SessionContext { Goal = CaptureGoal.Website, Interface = "en0" }, 0);
    Eq(tr.Verdict, "inconclusive", "sample threat demo verdict without the custom feed");
}

Console.WriteLine("---");
Console.WriteLine($"{passed} passed, {failed} failed");

return failed == 0 ? 0 : 1;

sealed class FakeModelHandler : HttpMessageHandler
{
    public string ResponseJson = "{}";
    public int Calls;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Calls++;
        string body = "{\"message\":{\"content\":" + System.Text.Json.JsonSerializer.Serialize(ResponseJson) + "}}";
        return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
        });
    }
}


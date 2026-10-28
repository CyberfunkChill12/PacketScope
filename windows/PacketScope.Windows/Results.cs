namespace PacketScope.Windows;

// Structured capture results (Windows port): the Results page renders only
// from this object. The verdict is decided here, in code.

public sealed class EvidenceRef
{
    public string Filter = "";
    public List<int> Frames = new();
    public int Count;
}

public sealed class PathStage
{
    public string Id = "", Status = "not_visible", Result = "", Detail = "";
    public string Title => Id switch { "local" => "Local network", "dns" => "Name lookup (DNS)", "tcp" => "Connection (TCP)", "tls" => "Secure setup (TLS)", _ => "App response" };
}

public sealed class ResultFinding
{
    public string Id = "", Severity = "info", Title = "", Observed = "", Interpretation = "", Confidence = "low";
    public EvidenceRef Evidence = new();
    public List<string> NextSteps = new();
    public string Category = "connectivity";
    public List<ThreatMatch> MatchedIndicators = new();
}

public sealed class MatchedDestination
{
    public string Key = "", DisplayName = "";
    public string? Ip; public int? Port;
    public string Severity = "info";
    public List<ThreatMatch> Matches = new();
}

public sealed class FeedRef
{
    public string Id = "", Name = "";
    public DateTimeOffset? UpdatedAt;
    public bool Stale;
    public int IndicatorCount;
}

public sealed class ResultSummary
{
    public string Headline = "", Body = "", NextStep = "";
    public bool FromTemplate = true;
    public List<(string Text, string Anchor)> Citations = new();
}

public sealed class CaptureResults
{
    public string GoalLabel = "";
    public DateTimeOffset? StartedAt;
    public double DurationSec;
    public int Packets;
    public long Bytes;
    public string InterfaceName = "";
    public int KernelDrops;
    public List<double> MarkedMomentsSec = new();
    public int CheckedPackets;
    public List<(string Reason, int Packets)> Skipped = new();
    public bool TooShort;
    public List<ProtocolCount> Mix = new();
    public List<(string Destination, List<PathStage> Stages)> Paths = new();
    public CaptureReport Report = new();
    public SessionContext Context = new();
    public List<ResultFinding> Findings = new();
    public string Verdict = "inconclusive";
    public ResultSummary TemplateSummary = new();
    public ThreatIntelSummary? ThreatIntel;
    public string SecurityAlert => ThreatIntel?.SecurityAlert ?? "none";
    public double CheckedPercent => Packets > 0 ? 100.0 * CheckedPackets / Packets : 0;
}

public static class CaptureResultsBuilder
{
    public const double TooShortThresholdSec = 15;

    public static CaptureResults Build(CaptureReport report, SessionContext ctx, int kernelDrops, ThreatIntelSummary? threatIntel = null)
    {
        var facts = report.Facts;
        int total = report.PacketCount;
        int quic = facts?.QuicPackets ?? 0;
        int encOther = facts?.EncryptedOtherPackets ?? 0;
        int checkedPackets = facts?.CheckedPackets ?? Math.Max(0, total - quic);
        var skipped = new List<(string, int)>();
        if (quic > 0) skipped.Add(("encrypted_quic", quic));
        if (encOther > 0) skipped.Add(("encrypted_other", encOther));
        var findings = BuildFindings(report);
        bool hasFailed = findings.Any(f => f.Severity == "likely_cause") || (facts?.Destinations.Any(d => d.Outcome is "no_reply" or "refused") ?? false);
        bool tooShort = ctx.Goal == CaptureGoal.Website && !hasFailed && ctx.Markers.Count == 0 && report.Duration < TooShortThresholdSec && total >= 10;
        string verdict =
            total < 10 ? "not_enough_traffic" :
            findings.Any(f => f.Severity == "likely_cause") ? "cause_found" :
            findings.Any(f => f.Severity == "warning") ? "possible_issue" :
            (tooShort || ctx.Markers.Count == 0 || (total > 0 && (double)checkedPackets / total < 0.7)) ? "inconclusive" :
            "no_problem_seen";
        var r = new CaptureResults
        {
            GoalLabel = GoalInfo.Title(ctx.Goal),
            StartedAt = ctx.StartedAt is double s ? DateTimeOffset.FromUnixTimeMilliseconds((long)(s * 1000)) : null,
            DurationSec = report.Duration,
            Packets = total,
            Bytes = report.CapturedBytes,
            InterfaceName = ctx.Interface,
            KernelDrops = kernelDrops,
            MarkedMomentsSec = facts?.FirstTimestamp is double f0 ? ctx.Markers.Select(m => m.Timestamp - f0).ToList() : new List<double>(),
            CheckedPackets = checkedPackets,
            Skipped = skipped,
            TooShort = tooShort,
            Mix = facts?.TrafficMix ?? new List<ProtocolCount>(),
            Paths = BuildPaths(report, facts),
            Report = report,
            Context = ctx,
            Findings = findings,
            Verdict = verdict,
            ThreatIntel = threatIntel,
        };
        r.TemplateSummary = Template(r);
        if (threatIntel != null) AttachThreatIntel(r, threatIntel, report);
        return r;
    }

    private static List<ResultFinding> BuildFindings(CaptureReport report)
    {
        var output = new List<ResultFinding>();
        foreach (var f in report.Findings)
        {
            string sev = f.Severity switch { "likely_cause" => "likely_cause", "warning" or "notice" => "warning", _ => "info" };
            string interpretation = f.Id switch
            {
                "unanswered-connection" => "A silent drop. A refused connection would have returned a reset; a missing route would usually return an ICMP error. Silence typically comes from a firewall rule, a VPN or filter, or a server that is offline.",
                "refused-connection" => "The destination was reachable but actively refused the connection. The service may not be running, or a firewall on that device is rejecting it.",
                "dns-name-not-found" => "The name does not exist according to the DNS server, so the app never got an address to connect to.",
                "dns-errors" => "Name lookups are failing, which can make apps look like they have no connection even when the link is up.",
                "slow-dns" => "Slow name lookups delay every new connection before any data moves.",
                "plaintext-remote" => "Readable application data left this device without encryption. Devices on the network path could potentially see it.",
                "plaintext-local" => "Readable traffic between addresses on this device. It stays on the device and is listed for awareness.",
                _ => f.Evidence,
            };
            var steps = f.Id switch
            {
                "unanswered-connection" => new List<string> { "Open the same website or app on a different network, such as a phone hotspot.", "If it works there, a firewall, VPN or content filter on this network is likely blocking it. Share this report with whoever runs the network.", "If it fails everywhere, the service may be down. Check its status page or contact its support." },
                _ => new List<string> { f.Recommendation },
            };
            output.Add(new ResultFinding
            {
                Id = f.Id, Severity = sev, Title = f.Title, Observed = f.Evidence, Interpretation = interpretation,
                Confidence = sev == "likely_cause" ? "high" : sev == "warning" ? "medium" : "low",
                Evidence = new EvidenceRef { Filter = f.Id == "unanswered-connection" && f.PacketNumbers.Count > 0 ? "frame.number in {" + string.Join(", ", f.PacketNumbers.Take(200)) + "}" : FilterFor(f.Id), Frames = f.PacketNumbers.Take(200).ToList(), Count = f.PacketNumbers.Count },
                NextSteps = steps,
            });
        }
        var rank = new Dictionary<string, int> { ["likely_cause"] = 0, ["warning"] = 1, ["info"] = 2 };
        return output.OrderBy(f => rank.GetValueOrDefault(f.Severity, 3)).ToList();
    }

    private static string FilterFor(string id) => id switch
    {
        "dns-errors" or "dns-name-not-found" => "dns.flags.response == 1 && dns.flags.rcode != 0",
        "tcp-resets" or "refused-connection" => "tcp.flags.reset == 1",
        "unanswered-connection" => "", // built from evidence frames in BuildFindings
        "tls-alerts" => "tls.record.content_type == 21",
        "plaintext-remote" or "plaintext-local" => "http || ftp || smtp",
        _ => "",
    };

    private static List<(string, List<PathStage>)> BuildPaths(CaptureReport report, CaptureFacts? facts)
    {
        var paths = new List<(string, List<PathStage>)>();
        var destinations = facts?.Destinations ?? new List<DestinationRecord>();
        foreach (var dest in destinations.Take(12))
            paths.Add((dest.Name ?? dest.Address, StagesFor(report, facts, dest)));
        if (facts?.DnsLookups.FirstOrDefault(l => l.Rcode == "NXDOMAIN") is { } nx)
        {
            var fake = new DestinationRecord { Name = nx.Name, Address = "—", Port = 0, ProtocolLabel = "DNS", Outcome = "not_checked" };
            paths.Insert(0, (nx.Name, StagesFor(report, facts, fake)));
        }
        if (paths.Count == 0) paths.Add(("This device", StagesFor(report, facts, null)));
        return paths;
    }

    private static List<PathStage> StagesFor(CaptureReport report, CaptureFacts? facts, DestinationRecord? dest)
    {
        var stages = new List<PathStage>();
        if (facts?.ArpResponder is string gw) stages.Add(new PathStage { Id = "local", Status = "passed", Result = "Router answered", Detail = $"ARP reply from {gw}" });
        else if (report.PacketCount > 0) stages.Add(new PathStage { Id = "local", Status = "passed", Result = "Traffic was exchanged", Detail = "Packets were seen on the selected interface" });
        else stages.Add(new PathStage { Id = "local", Status = "not_visible", Result = "Not visible", Detail = "No packets were captured" });
        bool dnsFailed = false;
        if (dest?.Name is string name)
        {
            var lookups = facts?.DnsLookups.Where(l => l.Name == name).ToList() ?? new List<DnsLookup>();
            if (lookups.FirstOrDefault(l => l.Rcode is "NXDOMAIN" or "SERVFAIL" or "REFUSED") is { } err)
            {
                stages.Add(new PathStage { Id = "dns", Status = "failed", Result = $"{name} was reported as not existing ({err.Rcode})", Detail = "The name lookup failed, so no connection could start" });
                dnsFailed = true;
            }
            else if (lookups.FirstOrDefault(l => l.Milliseconds != null) is { } ok)
                stages.Add(new PathStage { Id = "dns", Status = "passed", Result = $"Resolved to {dest.Address}", Detail = $"Answered in {Format.Ms(ok.Milliseconds ?? 0)}" });
            else if (facts?.Domains.Any(dm => dm.Name == name && dm.Addresses.Contains(dest.Address)) ?? false)
                stages.Add(new PathStage { Id = "dns", Status = "passed", Result = $"Resolved to {dest.Address}", Detail = "The answer was seen in this capture" });
            else stages.Add(new PathStage { Id = "dns", Status = "not_visible", Result = "No lookup seen", Detail = "The address may already have been cached" });
        }
        else if (facts is { DnsQueries: > 0 })
        {
            if (report.Findings.Any(f => f.Id == "dns-name-not-found"))
            {
                stages.Add(new PathStage { Id = "dns", Status = "failed", Result = "A name was reported as not existing (NXDOMAIN)", Detail = "The name lookup failed, so no connection could start" });
                dnsFailed = true;
            }
            else stages.Add(new PathStage { Id = "dns", Status = "passed", Result = $"{facts.DnsAnswered} of {facts.DnsQueries} answered", Detail = facts.AverageDnsMilliseconds is double a ? $"Average {Format.Ms(a)}" : "" });
        }
        else stages.Add(new PathStage { Id = "dns", Status = "not_visible", Result = "No lookup seen", Detail = "Names may already have been cached, or encrypted DNS was used" });
        bool tcpFailed = false;
        if (dest != null)
        {
            switch (dest.Outcome)
            {
                case "connected": stages.Add(new PathStage { Id = "tcp", Status = "passed", Result = "Connected", Detail = $"{dest.Packets} packets exchanged with {dest.Address}:{dest.Port}" }); break;
                case "refused": stages.Add(new PathStage { Id = "tcp", Status = "failed", Result = "Refused", Detail = $"The destination answered with a reset on port {dest.Port}" }); tcpFailed = true; break;
                case "no_reply": stages.Add(new PathStage { Id = "tcp", Status = "failed", Result = $"0 of {dest.Attempts} answered", Detail = $"No reply on port {dest.Port}" }); tcpFailed = true; break;
                case "reset_later": stages.Add(new PathStage { Id = "tcp", Status = "warning", Result = "Connected, then reset", Detail = "The connection started, then was cut short" }); break;
                default: stages.Add(new PathStage { Id = "tcp", Status = "not_visible", Result = "Not checked", Detail = "This destination's traffic could not be checked (for example, encrypted QUIC)" }); break;
            }
        }
        else if (facts is { TcpPackets: > 0 }) stages.Add(new PathStage { Id = "tcp", Status = facts.TcpResets > 0 ? "warning" : "passed", Result = $"{facts.TcpPackets} TCP packets checked", Detail = facts.TcpResets > 0 ? $"{facts.TcpResets} carried a reset" : "No resets seen" });
        else stages.Add(new PathStage { Id = "tcp", Status = "not_visible", Result = "Not visible", Detail = "No TCP traffic was captured" });
        bool failedSoFar = dnsFailed || tcpFailed;
        if (failedSoFar) stages.Add(new PathStage { Id = "tls", Status = "not_reached", Result = "Not reached", Detail = "Needs the earlier step to succeed first" });
        else if (dest != null)
        {
            stages.Add(dest.TlsStatus switch
            {
                "passed" => new PathStage { Id = "tls", Status = "passed", Result = "Secure setup completed", Detail = "The encrypted session was established" },
                "failed" => new PathStage { Id = "tls", Status = "failed", Result = "Secure setup failed", Detail = "A TLS alert was seen before the setup completed" },
                _ => new PathStage { Id = "tls", Status = "not_visible", Result = dest.ProtocolLabel.Contains("QUIC") ? "Inside QUIC" : "Not seen completed", Detail = dest.ProtocolLabel.Contains("QUIC") ? "QUIC encrypts its setup; it can't be checked separately" : "The setup may have finished outside the capture window" },
            });
        }
        else stages.Add(new PathStage { Id = "tls", Status = "not_visible", Result = "Not visible", Detail = "Encrypted setup can't be verified beyond the handshake" });
        if (failedSoFar || stages.Any(s => s.Id == "tls" && s.Status == "failed"))
            stages.Add(new PathStage { Id = "app", Status = "not_reached", Result = "Not reached", Detail = "Needs a connection first" });
        else if (dest is { ProtocolLabel: "TCP · HTTP" })
            stages.Add(new PathStage { Id = "app", Status = "passed", Result = "Visible (not encrypted)", Detail = "The app response was readable plaintext" });
        else stages.Add(new PathStage { Id = "app", Status = "not_visible", Result = "Encrypted", Detail = "Contents can't be read without keys" });
        bool seenFailure = false;
        for (int i = 0; i < stages.Count; i++)
        {
            if (seenFailure && stages[i].Status != "not_reached")
                stages[i] = new PathStage { Id = stages[i].Id, Status = "not_reached", Result = "Not reached", Detail = "Needs the earlier step to succeed first" };
            if (stages[i].Status == "failed") seenFailure = true;
        }
        return stages;
    }

    private static void AttachThreatIntel(CaptureResults results, ThreatIntelSummary intel, CaptureReport report)
    {
        var groups = ThreatIntelSummary.GroupByDestination(intel.Matches);
        var enriched = results.Report.Facts?.Destinations ?? new List<DestinationRecord>();
        foreach (var dest in enriched)
        {
            var mine = intel.Matches.Where(m => m.DestinationIP == dest.Address).ToList();
            if (mine.Count > 0)
            {
                dest.IntelMatchIds = mine.Select(m => m.Id).ToList();
                var rank = new Dictionary<string, int> { ["high"] = 0, ["medium"] = 1, ["low"] = 2, ["info"] = 3 };
                dest.IntelTopSeverity = mine.Select(m => m.Severity).OrderBy(s => rank.GetValueOrDefault(s, 4)).First();
            }
        }
        if (results.Report.Facts != null)
        {
            var rank = new Dictionary<string, int> { ["high"] = 0, ["medium"] = 1, ["low"] = 2, ["info"] = 3 };
            results.Report.Facts.Destinations = enriched.Select((d, i) => (d, i))
                .OrderBy(x => x.d.IntelTopSeverity is string s ? rank.GetValueOrDefault(s, 9) : 9).ThenBy(x => x.i).Select(x => x.d).ToList();
        }
        var security = new List<ResultFinding>();
        foreach (var group in groups)
        {
            var first = group.Matches[0];
            var dest = results.Report.Facts?.Destinations.FirstOrDefault(x => x.Address == group.Ip);
            string feedNames = string.Join(", ", group.Matches.Select(m => string.IsNullOrEmpty(m.FeedName) ? m.Indicator.FeedId : m.FeedName).Distinct().OrderBy(x => x));
            string observed = dest != null
                ? $"{(first.Connected ? "Connected to" : "Tried to contact")} {dest.Address}:{dest.Port} — {dest.Packets} packets, {dest.Attempts} connection attempt(s). Matched {group.Matches.Count} indicator(s)."
                : $"Matched {group.Matches.Count} indicator(s) for {group.DisplayName} ({(first.Direction == "dns_only" ? "name lookup only; no connection followed" : "observed in this capture")}).";
            string interpretation = first.Indicator.Threat switch
            {
                "botnet_c2" => "This address or name is listed as a botnet command-and-control server. Malware on a device uses such servers to receive instructions and send stolen data.",
                "malware_download" => "This address, name, or file is listed as distributing malware.",
                "phishing" => "This name or address is listed as a phishing site.",
                "hijacked_netblock" => "This address sits inside a network block listed as run or hijacked by criminal operations. Ordinary services can occasionally share such ranges, so treat it as a prompt to check, not proof.",
                _ => "A threat feed lists this destination. A listing is evidence to investigate, not proof that this device is infected.",
            };
            string sevMap = group.Severity switch { "high" => "likely_cause", "medium" => "warning", _ => "info" };
            var f = new ResultFinding
            {
                Id = "security-" + group.Key,
                Severity = sevMap,
                Title = $"{group.DisplayName} is listed by {feedNames}",
                Observed = observed,
                Interpretation = interpretation,
                Confidence = group.Severity == "high" ? "high" : group.Severity == "medium" ? "medium" : "low",
                Evidence = new EvidenceRef { Filter = dest?.EvidenceFilter ?? first.Filter, Frames = group.Matches.SelectMany(m => m.Frames).Distinct().OrderBy(x => x).Take(200).ToList(), Count = dest?.EvidenceCount ?? group.Matches.Sum(m => m.EvidenceCount) },
                NextSteps = new List<string> { "Run a malware scan on this device.", "If this is a work device, tell your IT or security team and share this report with them.", "Note what app was running at the marked time, then capture again after scanning." },
                Category = "security",
                MatchedIndicators = group.Matches,
            };
            security.Add(f);
        }
        results.Findings = security.Concat(results.Findings).ToList();
    }

    public static ResultSummary Template(CaptureResults r)
    {
        var top = r.Findings.FirstOrDefault(f => f.Category != "security");
        switch (r.Verdict)
        {
            case "not_enough_traffic":
                return new ResultSummary { Headline = "Not enough traffic was captured", Body = $"Only {Format.Count(r.Packets)} packets were recorded, which is too little to answer your question. The selected interface may not be the one carrying the traffic.", NextStep = "Check the selected interface, then capture again while you reproduce the problem." };
            case "cause_found":
            {
                var f = top!;
                return new ResultSummary { Headline = HeadlineFor(f, r), Body = f.Observed.Length > 300 ? f.Observed[..300] : f.Observed, NextStep = f.NextSteps.FirstOrDefault() ?? "Share this report with support." };
            }
            case "possible_issue":
            {
                var f = top!;
                return new ResultSummary { Headline = HeadlineFor(f, r), Body = $"{f.Observed} {f.Interpretation}", NextStep = f.NextSteps.FirstOrDefault() ?? "Capture again and compare." };
            }
            case "inconclusive":
            {
                var facts = r.Report.Facts;
                string dnsText = (facts?.DnsQueries ?? 0) > 0 ? $"{facts!.DnsAnswered} of {facts.DnsQueries} name lookups were answered" : "No name lookups were seen";
                int connected = facts?.Destinations.Count(d => d.Outcome == "connected") ?? 0;
                string connText = connected > 0 ? " and the connections your device started succeeded" : "";
                string skippedText = r.Skipped.Count > 0 ? $", and {Format.Count(r.Skipped[0].Packets)} of {Format.Count(r.Packets)} packets were QUIC traffic whose contents can't be read" : "";
                string shortText = r.TooShort ? $" But the capture ran for only {Format.Duration(r.DurationSec)}" : "";
                return new ResultSummary
                {
                    Headline = "No connection failure was seen, but this capture probably missed it",
                    Body = $"All measured checks passed: {dnsText}{connText}. Nothing was refused, reset or left unanswered.{shortText}{skippedText}, so the failing attempt was most likely not recorded.",
                    NextStep = "Capture for 60 seconds while you reproduce the problem. Start the capture, open the website or app that won't connect, and press Mark the moment when it fails.",
                };
            }
            default:
            {
                var facts = r.Report.Facts;
                var dest = facts?.Destinations.FirstOrDefault(d => d.Outcome == "connected");
                string headline = dest != null ? $"All connections to {dest.Name ?? dest.Address} succeeded in this capture" : "No problem was seen in this capture";
                return new ResultSummary { Headline = headline[..Math.Min(90, headline.Length)], Body = $"{facts?.DnsAnswered ?? 0} of {facts?.DnsQueries ?? 0} name lookups were answered, and the connections your device started completed. This covers only what could be seen during these {Format.Duration(r.DurationSec)}.", NextStep = "If the problem comes back, capture again and mark the moment it happens." };
            }
        }
    }

    private static string HeadlineFor(ResultFinding f, CaptureResults r)
    {
        string name = r.Report.Facts?.Destinations.FirstOrDefault(d => d.Outcome is "no_reply" or "refused") is { } d ? (d.Name ?? d.Address) : "This capture";
        string h = f.Id switch
        {
            "unanswered-connection" => $"{name} never answered your device's connection attempts",
            "refused-connection" => $"{name} refused your device's connection",
            "dns-name-not-found" => "The name could not be found, so nothing could connect",
            "dns-errors" => "Name lookups failed during this capture",
            "slow-dns" => "Name lookups were slow during this capture",
            "plaintext-remote" => "Some traffic left this device without encryption",
            "tls-alerts" => "Secure connections were rejected during this capture",
            _ => f.Title,
        };
        return h[..Math.Min(90, h.Length)];
    }
}

namespace PacketScope.Windows;

public sealed class SupportOptions
{
    public bool IncludeIPs = false;
    public bool IncludeDomains = false;
    public bool IncludeApps = true;
    public bool IncludeNotes = false;
}

public static class SupportReportText
{
    public static string Generate(CaptureReport report, SessionContext ctx, ThreatIntelSummary? intel, SupportOptions? options = null)
    {
        options ??= new SupportOptions();
        var lines = new List<string>
        {
            "PacketScope support report (Windows)",
            "====================================",
            "This report was generated on this device from measured capture evidence. It contains no packet payloads and no PCAP data.",
            "",
            $"Capture: {report.PacketCount} packets, {report.CapturedBytes} captured bytes, observed span {report.Duration:0.0} s",
            $"Goal: {GoalInfo.Title(ctx.Goal)}",
            $"Interface: {(string.IsNullOrEmpty(ctx.Interface) ? "unknown" : ctx.Interface)}",
        };
        if (ctx.Markers.Count > 0)
        {
            lines.Add("Marked moments:");
            foreach (var m in ctx.Markers) lines.Add($"  - {DateTimeOffset.FromUnixTimeMilliseconds((long)(m.Timestamp * 1000))}: {m.Note}");
        }
        lines.Add("");
        lines.Add("Observations and next steps:");
        if (report.Findings.Count == 0) lines.Add("  No matching checks fired. This does not prove the network is healthy.");
        foreach (var f in report.Findings)
        {
            lines.Add($"  - {f.Title}");
            lines.Add($"    Observed: {f.Evidence}");
            lines.Add($"    Check next: {f.Recommendation}");
            lines.Add($"    Supporting packets: {string.Join(", ", f.PacketNumbers.Select(n => $"#{n}"))}");
        }
        if (report.Facts is { } facts)
        {
            lines.Add("");
            lines.Add("Measured facts:");
            lines.Add($"  Visible DNS replies: {facts.DnsResponses}; DNS error replies: {facts.DnsErrors}");
            lines.Add($"  Decoded TCP packets: {facts.TcpPackets}; with RST: {facts.TcpResets}");
            if (options.IncludeApps)
                lines.Add($"  Apps (approximate, endpoint-matched): {string.Join(", ", facts.Applications.Take(20).Select(a => a.Name))}");
            if (options.IncludeDomains && facts.Domains.Count > 0)
            {
                lines.Add("  Observed DNS names:");
                foreach (var d in facts.Domains.Take(100)) lines.Add($"    {d.Name}: {d.QueryCount} queries, {d.ErrorCount} errors{(d.Addresses.Count > 0 ? ", addresses " + string.Join(", ", d.Addresses) : "")}");
            }
            if (options.IncludeIPs && report.Endpoints.Count > 0)
            {
                lines.Add("  Endpoints:");
                foreach (var e in report.Endpoints.Take(30)) lines.Add($"    {e.Address}: {e.Packets} packets, {e.Bytes} bytes");
            }
        }
        if (intel != null)
        {
            lines.Add("");
            lines.Add("Threat feed matching (checked locally on this device):");
            switch (intel.Status)
            {
                case "no_feeds": lines.Add("  Threat matching didn't run: no feed copies had been downloaded."); break;
                case "disabled": lines.Add("  Threat matching is turned off."); break;
                case "loading": lines.Add("  Threat matching didn't run: feeds were still loading."); break;
                default:
                    if (intel.Matches.Count == 0) lines.Add($"  No matches in {intel.Feeds.Count} threat feeds. Feeds only list known threats, so this doesn't rule out new ones.");
                    foreach (var group in ThreatIntelSummary.GroupByDestination(intel.Matches))
                    {
                        lines.Add($"  - {group.DisplayName}: severity {group.Severity}");
                        foreach (var m in group.Matches)
                            lines.Add($"    {(string.IsNullOrEmpty(m.FeedName) ? m.Indicator.FeedId : m.FeedName)}: {m.MatchedOn} {Normalize.Defanged(m.Observed, m.MatchedOn)} (threat: {m.Indicator.Threat ?? "listed"}{(m.Indicator.LastSeen != null ? $", last seen {m.Indicator.LastSeen}" : "")})");
                    }
                    foreach (var id in intel.Matches.Select(m => m.Indicator.FeedId).Concat(intel.Feeds.Select(f => f.Id)).Distinct().OrderBy(x => x))
                    {
                        if (FeedRegistry.Meta(id) is { } meta)
                            lines.Add($"  Feed: {meta.Name} — license {meta.License}.{(meta.Attribution != null ? " " + meta.Attribution : "")}");
                    }
                    if (intel.IgnoredByAllowlist > 0) lines.Add($"  Ignored by your allowlist: {intel.IgnoredByAllowlist}");
                    break;
            }
        }
        if (options.IncludeNotes && !string.IsNullOrEmpty(ctx.Symptom))
        {
            lines.Add("");
            lines.Add($"Your notes / symptoms: {ctx.Symptom}");
        }
        lines.Add("");
        lines.Add("Limitations:");
        lines.Add("  - Encrypted traffic cannot be read; only metadata and visible plaintext headers are used.");
        lines.Add("  - An observed DNS name does not establish a website visit or a destination's owner. No reverse-DNS or external lookups were performed.");
        lines.Add("  - Captured volume is not a speed test and is not connection capacity.");
        lines.Add("  - On Windows, process names come from connection-table snapshots matched by endpoint and are approximate.");
        foreach (var n in report.LimitationNotes) lines.Add($"  - {n}");
        lines.Add("  - Timestamps and packet references are shown by design; these options are selective redaction, not guaranteed anonymization. Review the preview before sharing, especially free-text notes.");
        return Redact(string.Join("\n", lines), report, options);
    }

    // Redaction is applied to the whole generated text, including opted-in
    // notes; turning notes on never turns addresses or domains on.
    public static string Redact(string text, CaptureReport report, SupportOptions options)
    {
        string output = text;
        var facts = report.Facts;
        if (!options.IncludeApps && facts != null)
        {
            foreach (var app in facts.Applications.Where(a => a.Name != "Unknown" && a.Name.Length >= 3).OrderByDescending(a => a.Name.Length))
                output = output.Replace(app.Name, "[app hidden]", StringComparison.Ordinal);
        }
        if (!options.IncludeDomains)
        {
            if (facts != null)
                foreach (var d in facts.Domains.Select(x => x.Name).OrderByDescending(x => x.Length))
                    output = output.Replace(d, "[domain hidden]", StringComparison.Ordinal);
            output = System.Text.RegularExpressions.Regex.Replace(output, @"https?://\S+", "[domain hidden]");
            output = System.Text.RegularExpressions.Regex.Replace(output, @"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|co|uk|de|fr|jp|au|ca|us|info|biz|dev|app|local|lan|home|internal|example)(?![A-Za-z0-9_-])", "[domain hidden]");
        }
        if (!options.IncludeIPs)
        {
            foreach (var e in report.Endpoints.OrderByDescending(e => e.Address.Length))
                if (e.Address.Contains('.') || e.Address.Contains(':'))
                    output = output.Replace(e.Address, "[address hidden]", StringComparison.Ordinal);
            output = System.Text.RegularExpressions.Regex.Replace(output, @"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])", "[address hidden]");
            output = System.Text.RegularExpressions.Regex.Replace(output, @"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])", "[address hidden]");
        }
        return output;
    }
}


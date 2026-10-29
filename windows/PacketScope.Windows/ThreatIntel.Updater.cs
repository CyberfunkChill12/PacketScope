using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PacketScope.Windows;

// ---------------- Secrets: Windows Credential Manager ----------------

public interface IFeedKeyStore
{
    string? Get(string feedId);
    void Set(string? key, string feedId);
}

public sealed class InMemoryKeyStore : IFeedKeyStore
{
    private readonly Dictionary<string, string> _values = new();
    public string? Get(string feedId) => _values.GetValueOrDefault(feedId);
    public void Set(string? key, string feedId) { if (key == null) _values.Remove(feedId); else _values[feedId] = key; }
}

public sealed class CredentialManagerKeyStore : IFeedKeyStore
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public uint Flags, Type;
        public string TargetName, Comment, UserName;
        public long LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist, AttributeCount;
        public IntPtr Attributes, TargetAlias;
    }
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredWrite([In] ref Credential credential, uint flags);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);
    [DllImport("advapi32.dll")] private static extern void CredFree(IntPtr credential);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    private const uint Generic = 1, PersistLocalMachine = 2;
    private static string Target(string feedId) => $"PacketScope/feed/{feedId}";

    public string? Get(string feedId)
    {
        if (!CredRead(Target(feedId), Generic, 0, out var ptr)) return null;
        try
        {
            var cred = Marshal.PtrToStructure<Credential>(ptr);
            if (cred.CredentialBlob == IntPtr.Zero || cred.CredentialBlobSize == 0) return null;
            var bytes = new byte[cred.CredentialBlobSize];
            Marshal.Copy(cred.CredentialBlob, bytes, 0, bytes.Length);
            return Encoding.Unicode.GetString(bytes);
        }
        finally { CredFree(ptr); }
    }
    public void Set(string? key, string feedId)
    {
        CredDelete(Target(feedId), Generic, 0);
        if (string.IsNullOrEmpty(key)) return;
        var bytes = Encoding.Unicode.GetBytes(key);
        var blob = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, blob, bytes.Length);
            var cred = new Credential { Type = Generic, TargetName = Target(feedId), UserName = "PacketScope", CredentialBlobSize = (uint)bytes.Length, CredentialBlob = blob, Persist = PersistLocalMachine };
            CredWrite(ref cred, 0);
        }
        finally { Marshal.FreeHGlobal(blob); }
    }
}

public static class FeedSecrets
{
    public static string Redacted(string text, string? key) => string.IsNullOrEmpty(key) ? text : text.Replace(key, "•••");
    public static string SanitizedError(Exception error, string? key)
    {
        // URLError/NSError equivalents on Windows (HttpRequestException,
        // TaskCanceledException) can embed the failing URL — which for keyed
        // feeds contains the Auth-Key. Only our own hand-written messages and
        // bare status codes are ever surfaced.
        if (error is HttpRequestException hre)
            return Redacted($"Feed update failed ({(hre.StatusCode is { } sc ? $"HTTP {(int)sc}" : "network error")}). Check the connection and try again.", key);
        if (error is InvalidDataException ide) return Redacted(ide.Message, key);
        if (error is TaskCanceledException) return "Feed update timed out after 30 seconds.";
        return Redacted($"Feed update failed ({error.GetType().Name}).", key);
    }
    public static string? DownloadUrl(FeedMeta meta, string? key)
    {
        if (!meta.Url.Contains("{AUTH_KEY}")) return meta.Url;
        return string.IsNullOrEmpty(key) ? null : meta.Url.Replace("{AUTH_KEY}", key);
    }
}

// ---------------- Updater ----------------

public static class FeedJson
{
    // Feed models use fields; System.Text.Json skips fields unless told otherwise.
    public static readonly JsonSerializerOptions Options = new() { IncludeFields = true };
}

public sealed class FeedUpdater
{
    public string DirectoryPath { get; }
    public IFeedKeyStore KeyStore { get; }
    private readonly HttpClient _http;
    private Dictionary<string, FeedState> _states = new();
    public const string UserAgent = "PacketScope/0.1.0 (Windows; threat-feed updater)";
    public const int MaxBytes = 50 * 1024 * 1024;

    public FeedUpdater(string directory, IFeedKeyStore keyStore, HttpClient? http = null)
    {
        DirectoryPath = directory;
        KeyStore = keyStore;
        _http = http ?? new HttpClient();
        System.IO.Directory.CreateDirectory(directory);
        LoadStates();
    }

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PacketScope", "ThreatFeeds");

    public FeedState StateFor(FeedMeta meta)
        => _states.TryGetValue(meta.Id, out var s) ? s : new FeedState { FeedId = meta.Id, Enabled = meta.EnabledByDefault };
    public void SetEnabled(bool enabled, FeedMeta meta)
    {
        var s = StateFor(meta); s.Enabled = enabled; _states[meta.Id] = s; SaveStates();
    }
    public DateTimeOffset NextAllowedUpdate(FeedMeta meta)
    {
        var s = StateFor(meta);
        return s.LastAttemptAt is { } last ? last.AddSeconds(meta.MinRefreshSec) : DateTimeOffset.MinValue;
    }
    public static int BackoffSec(int failures) => failures switch { 0 => 0, 1 => 300, 2 => 900, _ => 3600 };
    public static double ScheduledDelaySec(int refreshSec, double randomFraction)
        => refreshSec * (1.0 + 0.10 * Math.Min(1, Math.Max(0, randomFraction)));

    private string StateFile => Path.Combine(DirectoryPath, "state.json");
    private string FeedFile(string id) => Path.Combine(DirectoryPath, $"{id}.feed");
    private string IndexFile(string id) => Path.Combine(DirectoryPath, $"index-{id}.json");
    private void LoadStates()
    {
        try
        {
            if (File.Exists(StateFile))
                _states = JsonSerializer.Deserialize<Dictionary<string, FeedState>>(File.ReadAllText(StateFile), FeedJson.Options) ?? new();
        }
        catch { _states = new(); }
    }
    private void SaveStates()
    {
        try { File.WriteAllText(StateFile, JsonSerializer.Serialize(_states, FeedJson.Options)); } catch { /* state is advisory */ }
    }
    public byte[]? StoredData(FeedMeta meta) => File.Exists(FeedFile(meta.Id)) ? File.ReadAllBytes(FeedFile(meta.Id)) : null;

    public enum UpdateOutcome { Updated, NotModified, TooSoon, Failed, KeyInvalid, Disabled }

    public async Task<(FeedState State, UpdateOutcome Outcome)> UpdateAsync(FeedMeta meta, DateTimeOffset now, bool manual)
    {
        var s = StateFor(meta);
        if (!s.Enabled) return (s, UpdateOutcome.Disabled);
        if (s.LastAttemptAt is { } last && (now - last).TotalSeconds < meta.MinRefreshSec)
            return (s, UpdateOutcome.TooSoon);
        if (s.ConsecutiveFailures > 0 && s.LastAttemptAt is { } lastF && !manual)
        {
            double wait = Math.Max(meta.MinRefreshSec, BackoffSec(s.ConsecutiveFailures));
            if ((now - lastF).TotalSeconds < wait) return (s, UpdateOutcome.TooSoon);
        }
        string? key = meta.RequiresKey ? KeyStore.Get(meta.Id) : null;
        if (FeedSecrets.DownloadUrl(meta, key) is not { } urlString || !Uri.TryCreate(urlString, UriKind.Absolute, out var url))
        {
            s.LastError = "This feed needs an Auth-Key. Add your own key in Settings.";
            s.KeyInvalid = true;
            _states[meta.Id] = s; SaveStates();
            return (s, UpdateOutcome.KeyInvalid);
        }
        if (url.Scheme != "https")
        {
            s.LastError = "Feed URL must use HTTPS.";
            _states[meta.Id] = s; SaveStates();
            return (s, UpdateOutcome.Failed);
        }
        s.LastAttemptAt = now;
        _states[meta.Id] = s; SaveStates();
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.UserAgent.ParseAdd(UserAgent);
            if (s.ETag != null) req.Headers.TryAddWithoutValidation("If-None-Match", s.ETag);
            if (s.LastModified != null) req.Headers.TryAddWithoutValidation("If-Modified-Since", s.LastModified);
            using var resp = await _http.SendAsync(req);
            if (resp.StatusCode == System.Net.HttpStatusCode.NotModified)
            {
                s.LastSuccessAt = now; s.LastError = null; s.ConsecutiveFailures = 0; s.KeyInvalid = false;
                _states[meta.Id] = s; SaveStates();
                return (s, UpdateOutcome.NotModified);
            }
            if (resp.StatusCode is System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.Forbidden)
            {
                s.LastError = FeedSecrets.Redacted($"The feed rejected the request (HTTP {(int)resp.StatusCode}). The Auth-Key may be invalid; add a current key in Settings.", key);
                s.KeyInvalid = true;
                _states[meta.Id] = s; SaveStates();
                return (s, UpdateOutcome.KeyInvalid);
            }
            if ((int)resp.StatusCode == 429)
            {
                s.ConsecutiveFailures++;
                s.LastError = $"The feed asked us to slow down. Next try in about {Math.Max(resp.Headers.RetryAfter?.Delta?.TotalSeconds ?? BackoffSec(s.ConsecutiveFailures), meta.MinRefreshSec):0} seconds.";
                _states[meta.Id] = s; SaveStates();
                return (s, UpdateOutcome.Failed);
            }
            resp.EnsureSuccessStatusCode();
            var data = await resp.Content.ReadAsByteArrayAsync();
            if (data.Length > MaxBytes) throw new InvalidDataException("Feed file is larger than the 50 MB cap.");
            foreach (var extra in meta.AdditionalUrls ?? new List<string>())
            {
                if (!Uri.TryCreate(extra, UriKind.Absolute, out var extraUrl) || extraUrl.Scheme != "https")
                    throw new InvalidDataException("Additional feed URL must use HTTPS.");
                var extraData = await _http.GetByteArrayAsync(extraUrl);
                data = data.Concat(Encoding.UTF8.GetBytes("\n")).Concat(extraData).ToArray();
            }
            var parsed = FeedParser.Parse(meta, data);
            if (parsed.ValidFraction < 0.95)
                throw new InvalidDataException($"Only {parsed.Indicators.Count} of {parsed.TotalRows} rows parsed; keeping the previous copy. First rejected: {parsed.RejectedExamples.FirstOrDefault() ?? "unknown"}");
            if (parsed.TotalRows > 0 && s.IndicatorCount >= 20 && parsed.Indicators.Count < s.IndicatorCount / 5)
                throw new InvalidDataException($"Indicator count collapsed from {s.IndicatorCount} to {parsed.Indicators.Count}; keeping the previous copy.");
            string tmp = Path.Combine(DirectoryPath, $"{meta.Id}.tmp.{Guid.NewGuid():N}");
            await File.WriteAllBytesAsync(tmp, data);
            File.Move(tmp, FeedFile(meta.Id), true);
            s.LastSuccessAt = now;
            s.LastError = null; s.ConsecutiveFailures = 0; s.KeyInvalid = false;
            s.ETag = resp.Headers.ETag?.ToString();
            s.LastModified = resp.Content.Headers.LastModified?.ToString("R");
            s.IndicatorCount = parsed.Indicators.Count;
            s.FileSha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
            s.NewestIndicatorAt = NewestIndicatorDate(parsed.Indicators);
            s.FeedCopyright = parsed.FeedCopyright;
            s.FeedTerms = parsed.FeedTerms;
            _states[meta.Id] = s; SaveStates();
            WriteIndex(meta, s, parsed.Indicators);
            return (s, UpdateOutcome.Updated);
        }
        catch (Exception ex)
        {
            s.ConsecutiveFailures++;
            s.LastError = FeedSecrets.SanitizedError(ex, key);
            _states[meta.Id] = s; SaveStates();
            return (s, UpdateOutcome.Failed);
        }
    }

    public void ImportLocalCopy(FeedMeta meta, byte[] data, string? customType = null)
    {
        var parsed = FeedParser.Parse(meta, data, customType);
        if (parsed.ValidFraction < 0.95)
            throw new InvalidDataException($"Only {parsed.Indicators.Count} of {parsed.TotalRows} rows parsed; the file was not imported.");
        string tmp = Path.Combine(DirectoryPath, $"{meta.Id}.tmp.{Guid.NewGuid():N}");
        File.WriteAllBytes(tmp, data);
        File.Move(tmp, FeedFile(meta.Id), true);
        var s = StateFor(meta);
        s.LastSuccessAt = DateTimeOffset.Now;
        s.LastAttemptAt = s.LastSuccessAt;
        s.LastError = null; s.ConsecutiveFailures = 0;
        s.IndicatorCount = parsed.Indicators.Count;
        s.FileSha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        s.NewestIndicatorAt = NewestIndicatorDate(parsed.Indicators);
        s.Enabled = true;
        _states[meta.Id] = s; SaveStates();
        WriteIndex(meta, s, parsed.Indicators);
    }

    private sealed class StoredIndex { public string FileSha256 = ""; public List<Indicator> Indicators = new(); }
    private void WriteIndex(FeedMeta meta, FeedState state, List<Indicator> indicators)
    {
        try
        {
            var stored = new StoredIndex { FileSha256 = state.FileSha256, Indicators = indicators };
            File.WriteAllText(IndexFile(meta.Id), JsonSerializer.Serialize(stored, FeedJson.Options));
        }
        catch { /* index is an optimization */ }
    }
    private List<Indicator>? ReadIndex(FeedMeta meta)
    {
        try
        {
            if (!File.Exists(IndexFile(meta.Id))) return null;
            return JsonSerializer.Deserialize<StoredIndex>(File.ReadAllText(IndexFile(meta.Id)), FeedJson.Options)?.Indicators;
        }
        catch { return null; }
    }

    public static string? NewestIndicatorDate(List<Indicator> indicators)
    {
        DateTimeOffset? best = null; string? bestRaw = null;
        foreach (var ind in indicators)
        {
            foreach (var raw in new[] { ind.LastSeen, ind.FirstSeen })
            {
                if (raw == null) continue;
                if (DateTimeOffset.TryParse(raw, out var d) && (best == null || d > best)) { best = d; bestRaw = raw; }
            }
        }
        return bestRaw;
    }

    public (IndicatorStore Store, Dictionary<string, int> PerFeed) LoadStore(DateTimeOffset now, List<FeedMeta>? extraMetas = null)
    {
        var store = new IndicatorStore();
        var perFeed = new Dictionary<string, int>();
        var merged = new List<Indicator>();
        foreach (var meta in FeedRegistry.All.Concat(extraMetas ?? new List<FeedMeta>()))
        {
            var s = StateFor(meta);
            if (!s.Enabled || StoredData(meta) == null) { perFeed[meta.Id] = 0; continue; }
            List<Indicator>? indicators = ReadIndex(meta);
            if (indicators == null)
            {
                try { indicators = FeedParser.Parse(meta, StoredData(meta)!).Indicators; }
                catch { perFeed[meta.Id] = 0; continue; }
            }
            List<Indicator> kept = indicators;
            if (meta.RetentionSec is int retention)
            {
                var cutoff = now.AddSeconds(-retention);
                kept = indicators.Where(ind => ind.LastSeen == null || !DateTimeOffset.TryParse(ind.LastSeen, out var d) || d >= cutoff).ToList();
            }
            merged.AddRange(kept);
            perFeed[meta.Id] = kept.Count;
        }
        store.Load(merged, null, now);
        return (store, perFeed);
    }
}

// ---------------- Allowlist ----------------

public sealed class AllowlistEntry
{
    public string Value = "", Reason = "";
    public DateTimeOffset AddedAt;
}

// ---------------- Matcher ----------------

public sealed class ThreatMatch
{
    public string Id = "";
    public Indicator Indicator = new();
    public string MatchedOn = "", Observed = "";
    public string? DestinationIP, DestinationName, DnsName, Sni, Url;
    public int? DestinationPort;
    public string Direction = "outbound";
    public bool Connected;
    public string Severity = "info";
    public List<string> SeverityReasons = new();
    public List<int> Frames = new();
    public string Filter = "";
    public int EvidenceCount;
    public string FeedName = "", FeedHomepage = "";
}

public sealed class ThreatIntelOutcome
{
    public List<ThreatMatch> Matches = new();
    public int IgnoredByAllowlist;
    public List<string> IgnoredValues = new();
    public int CheckedIPs, CheckedIPsTotal, CheckedDomains, CheckedUrls, CheckedCerts, CheckedFingerprints;
    public bool FilesChecked = false;
}

public static class IntelSeverity
{
    private static readonly string[] Order = { "info", "low", "medium", "high" };
    public static string Adjust(string severity, int delta)
    {
        int i = Array.IndexOf(Order, severity);
        return Order[Math.Min(3, Math.Max(0, (i < 0 ? 0 : i) + delta))];
    }
    public static int Rank(string severity) => severity switch { "high" => 0, "medium" => 1, "low" => 2, _ => 3 };
}

public static class PopularDomains
{
    private static readonly HashSet<string> Top = new() { "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com", "x.com", "apple.com", "microsoft.com", "amazon.com", "netflix.com", "wikipedia.org", "cloudflare.com", "github.com", "linkedin.com", "office.com", "live.com", "bing.com", "yahoo.com", "whatsapp.com", "zoom.us", "adobe.com", "salesforce.com", "dropbox.com", "spotify.com", "reddit.com", "tiktok.com", "baidu.com", "wordpress.com", "mozilla.org", "akamai.com" };
    public static bool Contains(string domain)
    {
        var d = Normalize.Domain(domain);
        return d != null && Top.Any(t => d == t || d.EndsWith("." + t));
    }
}

public static class IntelMatcher
{
    public static ThreatIntelOutcome Match(CaptureReport report, IndicatorStore store, Dictionary<string, FeedMeta> metas, List<AllowlistEntry> allowlist, DateTimeOffset now)
    {
        var facts = report.Facts;
        var outcome = new ThreatIntelOutcome();
        var allowValues = new HashSet<string>(allowlist.Select(a => Normalize.Domain(a.Value) ?? a.Value.ToLowerInvariant()));
        var allowIps = new HashSet<string>(allowlist.Select(a => Normalize.Ip(a.Value)).Where(x => x != null).Cast<string>());
        var raw = new List<ThreatMatch>();
        var seen = new HashSet<string>();

        string BaseSeverity(Indicator ind)
        {
            if (ind.Severity != null) return ind.Severity;
            if (ind.FeedId == "threatfox" && ind.Confidence is int c) return c >= 75 ? "high" : c >= 50 ? "medium" : "low";
            return metas.TryGetValue(ind.FeedId, out var m) ? m.BaseSeverity : "medium";
        }
        void Append(ThreatMatch m)
        {
            string key = $"{m.Indicator.FeedId}|{m.Indicator.Type}|{m.Indicator.Value}|{m.Observed}|{m.DestinationIP ?? ""}";
            if (seen.Contains(key)) return;
            string observedNorm = Normalize.Ip(m.Observed) ?? Normalize.Domain(m.Observed) ?? m.Observed.ToLowerInvariant();
            if (allowValues.Contains(observedNorm) || allowValues.Contains(m.Indicator.Value.ToLowerInvariant()) || (m.DestinationIP != null && allowIps.Contains(m.DestinationIP)))
            {
                outcome.IgnoredByAllowlist++;
                if (!outcome.IgnoredValues.Contains(m.Observed)) outcome.IgnoredValues.Add(m.Observed);
                return;
            }
            seen.Add(key);
            raw.Add(m);
        }
        ThreatMatch Make(Indicator ind, string matchedOn, string observed, DestinationRecord? dest, string? dnsName, string? sni, string? url, string direction, bool connected, List<int> frames, string filter, int count)
        {
            var reasons = new List<string> { $"base: {BaseSeverity(ind)}" };
            string sev = BaseSeverity(ind);
            if (!connected) { sev = IntelSeverity.Adjust(sev, -1); reasons.Add("downgraded: contact attempted, not completed"); }
            if (ind.LastSeen != null && DateTimeOffset.TryParse(ind.LastSeen, out var ls) && (now - ls).TotalDays > 30)
            { sev = IntelSeverity.Adjust(sev, -1); reasons.Add("downgraded: indicator last seen over 30 days ago"); }
            if (matchedOn is "ipv4" or "ipv6" or "cidr" or "ip_port")
            {
                string? name = dest?.Name ?? sni ?? dnsName;
                if (name != null && Normalize.Domain(name) is { } nd && nd != Normalize.Domain(ind.Value) && PopularDomains.Contains(nd))
                { sev = IntelSeverity.Adjust(sev, -1); reasons.Add("downgraded: IP-only match on shared hosting"); }
            }
            var m = new ThreatMatch
            {
                Id = $"{ind.FeedId}|{ind.Type}|{ind.Value}|{observed}",
                Indicator = ind, MatchedOn = matchedOn, Observed = observed,
                DestinationIP = dest?.Address, DestinationPort = dest?.Port, DestinationName = dest?.Name,
                DnsName = dnsName, Sni = sni, Url = url, Direction = direction, Connected = connected,
                Severity = sev, SeverityReasons = reasons, Frames = frames.Take(200).ToList(), Filter = filter, EvidenceCount = count,
                FeedName = metas.TryGetValue(ind.FeedId, out var meta) ? meta.Name : ind.FeedId,
                FeedHomepage = metas.TryGetValue(ind.FeedId, out var meta2) ? meta2.Homepage : "",
            };
            return m;
        }

        var destinations = facts?.Destinations ?? new List<DestinationRecord>();
        bool DestConnected(DestinationRecord d) => d.Outcome is "connected" or "reset_later" or "refused";

        var ips = new HashSet<string>();
        var endpointsByIp = new Dictionary<string, ObservableEndpoint>();
        foreach (var e in facts?.ObservableEndpoints ?? new List<ObservableEndpoint>())
        {
            if (Normalize.Ip(e.Address) is not { } ip) continue;
            ips.Add(ip);
            if (!endpointsByIp.TryGetValue(ip, out var cur) || e.Packets > cur.Packets) endpointsByIp[ip] = e;
        }
        foreach (var d in destinations) if (Normalize.Ip(d.Address) is { } dip) ips.Add(dip);
        foreach (var ip in ips)
        {
            if (Normalize.IsNeverFlaggedIp(ip)) continue;
            var dest = destinations.FirstOrDefault(x => Normalize.Ip(x.Address) == ip);
            endpointsByIp.TryGetValue(ip, out var endpoint);
            int port = dest?.Port ?? endpoint?.Port ?? 0;
            bool connected = dest != null && DestConnected(dest);
            var frames = dest?.PacketNumbers ?? endpoint?.Frames ?? new List<int>();
            string filter = dest?.EvidenceFilter ?? $"ip.addr=={ip}";
            int count = dest?.EvidenceCount ?? endpoint?.Packets ?? frames.Count;
            var pseudo = dest ?? new DestinationRecord { Address = ip, Port = port, ProtocolLabel = "Unknown", Outcome = "not_checked", Packets = endpoint?.Packets ?? 0, PacketNumbers = frames, EvidenceFilter = filter, EvidenceCount = count };
            string ipType = Normalize.IsV4(ip) ? "ipv4" : "ipv6";
            if (store.ExactMatch(ipType, ip) is { } ind)
                Append(Make(ind, ipType, ip, pseudo, dest?.Name, dest?.NameSource == "sni" ? dest?.Name : null, null, "outbound", connected, frames, filter, count));
            if (port > 0 && store.IpPortMatch(ip, port) is { } ipInd)
                Append(Make(ipInd, "ip_port", $"{ip}:{port}", pseudo, dest?.Name, null, null, "outbound", connected, frames, $"ip.addr=={ip} && tcp.port=={port}", count));
            else if (store.IpPortByIpLookup(ip) is { } byIp)
            {
                var m = Make(byIp, "ip_port", $"{ip}:{port}", pseudo, dest?.Name, null, null, "outbound", connected, frames, $"ip.addr=={ip}", count);
                m.Severity = IntelSeverity.Adjust(m.Severity, -1);
                m.SeverityReasons.Add($"downgraded: same IP, different port (listed {byIp.Port})");
                Append(m);
            }
            if (store.CidrMatch(ip) is { } cidrInd)
                Append(Make(cidrInd, "cidr", ip, pseudo, dest?.Name, null, null, "outbound", connected, frames, filter, count));
        }
        foreach (var domain in facts?.Domains ?? new List<(string, List<string>, int, int, List<int>)>())
        {
            foreach (var addr in domain.Addresses)
            {
                if (Normalize.Ip(addr) is not { } ip) continue;
                ips.Add(ip);
                if (Normalize.IsNeverFlaggedIp(ip)) continue;
                var dest = destinations.FirstOrDefault(x => x.Address == ip);
                if (dest != null) continue;
                string ipType = Normalize.IsV4(ip) ? "ipv4" : "ipv6";
                if (store.ExactMatch(ipType, ip) is { } ind)
                    Append(Make(ind, ipType, ip, null, domain.Name, null, null, "dns_only", false, domain.PacketNumbers, "dns", domain.PacketNumbers.Count));
                if (store.CidrMatch(ip) is { } cidrInd)
                    Append(Make(cidrInd, "cidr", ip, null, domain.Name, null, null, "dns_only", false, domain.PacketNumbers, "dns", domain.PacketNumbers.Count));
            }
        }
        outcome.CheckedIPs = ips.Count;
        outcome.CheckedIPsTotal = Math.Max(facts?.ObservableIpCount ?? 0, ips.Count);

        var domains = new HashSet<string>();
        void CheckDomain(string rawName, int? frame)
        {
            if (Normalize.Domain(rawName) is not { } name) return;
            domains.Add(name);
            if (store.DomainMatch(name) is not { } ind) return;
            var dest = destinations.FirstOrDefault(x => x.Name == name || (facts?.Domains.Any(dm => dm.Name == name && dm.Addresses.Contains(x.Address)) ?? false));
            bool connected = dest != null && DestConnected(dest);
            Append(Make(ind, "domain", name, dest, name, dest?.NameSource == "sni" ? dest?.Name : null, null, connected ? "outbound" : "dns_only", connected,
                frame is int fr ? new List<int> { fr } : dest?.PacketNumbers ?? new List<int>(), dest?.EvidenceFilter ?? $"dns.qry.name == \"{name}\"", dest?.EvidenceCount ?? 1));
        }
        foreach (var l in facts?.DnsLookups ?? new List<DnsLookup>()) CheckDomain(l.Name, l.Frame);
        foreach (var dm in facts?.Domains ?? new List<(string, List<string>, int, int, List<int>)>()) CheckDomain(dm.Name, dm.PacketNumbers.FirstOrDefault());
        foreach (var target in facts?.CnameTargets ?? new List<string>()) CheckDomain(target, null);
        foreach (var d in destinations.Where(x => x.NameSource == "sni" && x.Name != null)) CheckDomain(d.Name!, d.PacketNumbers.FirstOrDefault());
        foreach (var host in facts?.HttpHosts ?? new List<string>()) CheckDomain(host, null);
        outcome.CheckedDomains = domains.Count;

        int urlCount = 0;
        foreach (var rawUrl in facts?.HttpUrls ?? new List<string>())
        {
            if (Normalize.Url(rawUrl) is not { } url) continue;
            urlCount++;
            if (store.ExactMatch("url", url) is not { } ind) continue;
            string? host = Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.Host : null;
            var dest = destinations.FirstOrDefault(x => x.Name == host);
            Append(Make(ind, "url", url, dest, host, null, url, "outbound", dest == null || DestConnected(dest), dest?.PacketNumbers ?? new List<int>(), $"http.request.full_uri == \"{url}\"", dest?.EvidenceCount ?? 1));
        }
        outcome.CheckedUrls = urlCount;

        int certCount = 0;
        foreach (var cert in facts?.Certificates ?? new List<CertificateObservable>())
        {
            certCount++;
            var dest = destinations.FirstOrDefault(x => x.Address == cert.ServerAddress && x.Port == cert.ServerPort);
            if (store.ExactMatch("cert_sha1", cert.Sha1) is { } ind1)
                Append(Make(ind1, "cert_sha1", cert.Sha1, dest, dest?.Name, null, null, "outbound", true, new List<int> { cert.Frame }, dest?.EvidenceFilter ?? "tls.handshake.certificate", 1));
            if (store.ExactMatch("cert_sha256", cert.Sha256) is { } ind2)
                Append(Make(ind2, "cert_sha256", cert.Sha256, dest, dest?.Name, null, null, "outbound", true, new List<int> { cert.Frame }, dest?.EvidenceFilter ?? "tls.handshake.certificate", 1));
        }
        outcome.CheckedCerts = certCount;

        int fpCount = 0;
        foreach (var fp in facts?.Fingerprints ?? new List<TlsFingerprint>())
        {
            fpCount++;
            var dest = destinations.FirstOrDefault(x => x.Address == fp.ServerAddress && x.Port == fp.ServerPort);
            bool connected = dest != null && DestConnected(dest);
            if (store.ExactMatch("ja3", fp.Ja3) is { } ind3)
                Append(Make(ind3, "ja3", fp.Ja3, dest, dest?.Name, fp.Sni, null, "outbound", connected, new List<int> { fp.Frame }, dest?.EvidenceFilter ?? "tls.handshake.type == 1", 1));
            if (store.ExactMatch("ja4", fp.Ja4) is { } ind4)
                Append(Make(ind4, "ja4", fp.Ja4, dest, dest?.Name, fp.Sni, null, "outbound", connected, new List<int> { fp.Frame }, dest?.EvidenceFilter ?? "tls.handshake.type == 1", 1));
        }
        outcome.CheckedFingerprints = fpCount;

        var byDest = raw.GroupBy(m => m.DestinationIP ?? m.DnsName ?? m.Observed).ToList();
        foreach (var group in byDest)
        {
            var list = group.ToList();
            if (list.Count > 1 && (list.Select(m => m.MatchedOn).Distinct().Count() >= 2 || list.Select(m => m.Indicator.FeedId).Distinct().Count() >= 2))
            {
                foreach (var m in list)
                {
                    m.Severity = IntelSeverity.Adjust(m.Severity, 1);
                    m.SeverityReasons.Add($"upgraded: same destination matched {Math.Max(list.Select(m2 => m2.MatchedOn).Distinct().Count(), list.Select(m2 => m2.Indicator.FeedId).Distinct().Count())} indicator types or feeds");
                }
            }
        }
        raw.Sort((a, b) => IntelSeverity.Rank(a.Severity).CompareTo(IntelSeverity.Rank(b.Severity)));
        outcome.Matches = raw;
        return outcome;
    }
}

// ---------------- ThreatIntelSummary (grouped for the Results page) ----------------

public sealed class ThreatIntelSummary
{
    public string Status = "no_feeds";
    public List<FeedRef> Feeds = new();
    public int CheckedIPs, CheckedIPsTotal, CheckedDomains, CheckedUrls, CheckedCerts, CheckedFingerprints;
    public bool FilesChecked = false;
    public List<ThreatMatch> Matches = new();
    public int IgnoredByAllowlist;
    public string SecurityAlert = "none", SecurityHeadline = "";

    public static List<MatchedDestination> GroupByDestination(List<ThreatMatch> matches)
    {
        var groups = new Dictionary<string, List<ThreatMatch>>();
        var order = new List<string>();
        foreach (var m in matches)
        {
            string key = m.DestinationIP ?? m.DnsName ?? m.Observed;
            if (!groups.ContainsKey(key)) { groups[key] = new List<ThreatMatch>(); order.Add(key); }
            groups[key].Add(m);
        }
        return order.Select(key =>
        {
            var ms = groups[key];
            string sev = ms.Select(m => m.Severity).OrderBy(s => IntelSeverity.Rank(s)).First();
            return new MatchedDestination { Key = key, DisplayName = ms[0].DestinationName ?? ms[0].DnsName ?? ms[0].Observed, Ip = ms[0].DestinationIP, Port = ms[0].DestinationPort, Severity = sev, Matches = ms };
        }).OrderBy(g => IntelSeverity.Rank(g.Severity)).ToList();
    }

    public static ThreatIntelSummary Make(ThreatIntelOutcome outcome, List<FeedRef> feeds, string status)
    {
        var groups = GroupByDestination(outcome.Matches);
        string alert = groups.Any(g => g.Severity == "high") ? "high" : groups.Any(g => g.Severity == "medium") ? "medium" : "none";
        string headline = "";
        if (groups.Count > 0)
        {
            var top = groups[0];
            var first = top.Matches[0];
            string threatText = first.Indicator.Threat switch
            {
                "botnet_c2" => "a botnet server",
                "malware_download" => "a malware download",
                "phishing" => "a phishing site",
                "hijacked_netblock" => "part of a hijacked network block",
                _ => "a flagged address",
            };
            string feedName = string.IsNullOrEmpty(first.FeedName) ? first.Indicator.FeedId : first.FeedName;
            headline = first.Connected
                ? $"This device connected to an address {feedName} lists as {threatText}"
                : $"This device tried to contact an address {feedName} lists as {threatText}";
            if (groups.Count > 1) headline += $" (and {groups.Count - 1} more)";
        }
        return new ThreatIntelSummary
        {
            Status = status, Feeds = feeds,
            CheckedIPs = outcome.CheckedIPs, CheckedIPsTotal = outcome.CheckedIPsTotal,
            CheckedDomains = outcome.CheckedDomains, CheckedUrls = outcome.CheckedUrls,
            CheckedCerts = outcome.CheckedCerts, CheckedFingerprints = outcome.CheckedFingerprints,
            FilesChecked = outcome.FilesChecked, Matches = outcome.Matches,
            IgnoredByAllowlist = outcome.IgnoredByAllowlist,
            SecurityAlert = alert, SecurityHeadline = headline,
        };
    }
}

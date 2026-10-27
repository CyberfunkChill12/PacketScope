using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PacketScope.Windows;

// ---------------- Feed registry (feeds are data, not code) ----------------

public sealed class FeedMeta
{
    public string Id = "", Name = "", Url = "", Homepage = "", License = "";
    public string? Attribution;
    public bool RequiresKey, EnabledByDefault;
    public int RefreshSec, MinRefreshSec, MaxAgeSec;
    public string BaseSeverity = "high", Parser = "";
    public int? RetentionSec;
    public List<string>? AdditionalUrls;
    [JsonIgnore] public bool HiddenInSettings => Id is "threatfox" or "urlhaus";
}

public static class FeedRegistry
{
    public static readonly List<FeedMeta> All = new()
    {
        new() { Id = "feodo_recommended", Name = "Feodo Tracker", Url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json", Homepage = "https://feodotracker.abuse.ch/", License = "CC0", EnabledByDefault = true, RefreshSec = 3600, MinRefreshSec = 300, MaxAgeSec = 86400, BaseSeverity = "high", Parser = "feodo_json" },
        new() { Id = "sslbl_certs", Name = "SSL Blacklist (certificates)", Url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv", Homepage = "https://sslbl.abuse.ch/", License = "CC0", EnabledByDefault = true, RefreshSec = 3600, MinRefreshSec = 300, MaxAgeSec = 86400, BaseSeverity = "high", Parser = "sslbl_certs_csv" },
        new() { Id = "spamhaus_drop", Name = "Spamhaus DROP", Url = "https://www.spamhaus.org/drop/drop_v4.json", Homepage = "https://www.spamhaus.org/drop/", License = "Spamhaus DROP terms", Attribution = "Data from Spamhaus DROP — © Spamhaus. The stored copy keeps the feed's own date and copyright text.", EnabledByDefault = true, RefreshSec = 86400, MinRefreshSec = 86400, MaxAgeSec = 259200, BaseSeverity = "medium", Parser = "spamhaus_drop_json", AdditionalUrls = new() { "https://www.spamhaus.org/drop/drop_v6.json" } },
        new() { Id = "sslbl_ja3", Name = "SSL Blacklist (JA3)", Url = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv", Homepage = "https://sslbl.abuse.ch/", License = "CC0", EnabledByDefault = false, RefreshSec = 3600, MinRefreshSec = 300, MaxAgeSec = 86400, BaseSeverity = "info", Parser = "sslbl_ja3_csv" },
        new() { Id = "threatfox", Name = "ThreatFox", Url = "https://threatfox-api.abuse.ch/v2/files/exports/{AUTH_KEY}/full.csv.zip", Homepage = "https://threatfox.abuse.ch/", License = "abuse.ch terms; free for non-profit use, commercial use may need a paid subscription", RequiresKey = true, EnabledByDefault = false, RefreshSec = 3600, MinRefreshSec = 300, MaxAgeSec = 86400, BaseSeverity = "high", Parser = "threatfox_csv", RetentionSec = 180 * 86400 },
        new() { Id = "urlhaus", Name = "URLhaus", Url = "https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv", Homepage = "https://urlhaus.abuse.ch/", License = "abuse.ch terms; free for non-profit use, commercial use may need a paid subscription", RequiresKey = true, EnabledByDefault = false, RefreshSec = 3600, MinRefreshSec = 300, MaxAgeSec = 86400, BaseSeverity = "high", Parser = "urlhaus_csv", RetentionSec = 30 * 86400 },
    };
    public static FeedMeta? Meta(string id) => All.FirstOrDefault(f => f.Id == id);
}

public sealed class Indicator
{
    public string FeedId = "", Type = "", Value = "";
    public int? Port;
    public string? Threat, MalwareFamily, Severity, FirstSeen, LastSeen, Reference;
    public int? Confidence;
}

public sealed class FeedState
{
    public string FeedId = "";
    public bool Enabled;
    public DateTimeOffset? LastSuccessAt, LastAttemptAt;
    public string? LastError;
    public string? ETag, LastModified;
    public int IndicatorCount;
    public string FileSha256 = "";
    public int ConsecutiveFailures;
    public bool KeyInvalid;
    public string? NewestIndicatorAt, FeedCopyright, FeedTerms;
    public bool IsStale(FeedMeta meta, DateTimeOffset now) => LastSuccessAt is not { } s || (now - s).TotalSeconds > meta.MaxAgeSec;
}

// ---------------- Normalization ----------------

public static class Normalize
{
    private static readonly IdnMapping Idn = new();
    public static string? Ip(string raw)
    {
        string s = raw.Trim().Trim('[', ']').ToLowerInvariant();
        if (s.StartsWith("::ffff:") && IPAddress.TryParse(s[7..], out var mapped) && mapped.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            return mapped.ToString();
        return IPAddress.TryParse(s, out var ip) ? ip.ToString() : null;
    }
    public static bool IsV4(string canonical) => IPAddress.TryParse(canonical, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
    public static uint? Ipv4Value(string canonical)
    {
        if (!IPAddress.TryParse(canonical, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;
        var b = ip.GetAddressBytes();
        return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
    }
    public static string? Domain(string raw)
    {
        string s = raw.Normalize(NormalizationForm.FormC).ToLowerInvariant().Trim();
        if (s.EndsWith('.')) s = s[..^1];
        if (string.IsNullOrEmpty(s) || s.Length > 253 || s.Contains(' ') || s.Contains('/') || s.Contains('_')) return null;
        try { s = Idn.GetAscii(s); } catch { return null; }
        var labels = s.Split('.');
        if (labels.Length < 2) return null;
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63) return null;
            if (label.Any(c => c <= 0x20 || c == 0x7F)) return null;
            if (!label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')) return null;
            if (label.StartsWith('-') || label.EndsWith('-')) return null;
        }
        return s;
    }
    public static bool DomainMatches(string feedDomain, string observed)
    {
        var f = Domain(feedDomain); var o = Domain(observed);
        return f != null && o != null && (o == f || o.EndsWith("." + f));
    }
    // Bundled-list approximation on Windows: the full Public Suffix List is
    // used on macOS; here a conservative common-suffix set guards entries.
    private static readonly HashSet<string> Suffixes = new() { "github.io", "gitlab.io", "herokuapp.com", "netlify.app", "vercel.app", "azurewebsites.net", "appspot.com", "firebaseapp.com", "web.app", "co.uk", "org.uk", "com.au", "net.au", "co.jp", "com.br", "com.cn", "com.tw", "co.kr", "co.in", "com.mx", "s3.amazonaws.com", "cloudfront.net", "example", "test", "invalid", "localhost", "kawasaki.jp" };
    public static bool IsPublicSuffix(string domainName) => Domain(domainName) is { } d && (Suffixes.Contains(d) || !d.Contains('.'));
    public static bool IsNeverFlaggedIp(string canonical)
    {
        if (Ipv4Value(canonical) is uint v)
        {
            uint a = v >> 24, b = (v >> 16) & 0xFF;
            if (a == 10 || a == 127 || a == 0) return true;
            if (a == 172 && b is >= 16 and <= 31) return true;
            if (a == 192 && b == 168) return true;
            if (a == 169 && b == 254) return true;
            if (a >= 224) return true;
            if (a == 100 && b is >= 64 and <= 127) return true;
            if (a == 198 && (b == 18 || b == 19)) return true;
            return false;
        }
        string s = canonical.ToLowerInvariant();
        return s is "::1" or "::" || s.StartsWith("fe80") || s.StartsWith("fc") || s.StartsWith("fd") || s.StartsWith("ff");
    }
    public static string? Url(string raw)
    {
        if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var u)) return null;
        if (u.Scheme is not ("http" or "https")) return null;
        var host = Domain(u.Host);
        if (host == null) return null;
        var builder = new UriBuilder(u) { Host = host, Fragment = "" };
        if ((u.Scheme == "http" && u.Port == 80) || (u.Scheme == "https" && u.Port == 443)) builder.Port = -1;
        return builder.Uri.ToString();
    }
    public static string Defanged(string value, string type)
    {
        string v = value.Replace("http://", "hxxp://").Replace("https://", "hxxps://");
        return type is "url" or "domain" or "ipv4" or "ipv6" or "cidr" ? v.Replace(".", "[.]") : v;
    }
}

// ---------------- Parsers (strict; unknown structure is rejected) ----------------

public sealed class FeedParseResult
{
    public List<Indicator> Indicators = new();
    public int RejectedCount;
    public List<string> RejectedExamples = new();
    public int TotalRows;
    public string? FeedCopyright, FeedTerms;
    public double ValidFraction => TotalRows == 0 ? 1 : (double)Indicators.Count / Math.Max(1, TotalRows);
}

public static class FeedParser
{
    public static FeedParseResult Parse(FeedMeta meta, byte[] data, string? customType = null)
    {
        return meta.Parser switch
        {
            "test_csv" or "custom_csv" => ParseTypedCsv(data, meta.Id),
            "custom_lines" => ParseLines(data, meta.Id, customType ?? "domain", meta.BaseSeverity),
            "feodo_json" => ParseFeodo(data, meta.Id),
            "sslbl_certs_csv" => ParseSslblCerts(data, meta.Id),
            "sslbl_ja3_csv" => ParseSslblJa3(data, meta.Id),
            "spamhaus_drop_json" => ParseSpamhaus(data, meta.Id),
            _ => throw new InvalidDataException($"No parser implemented yet for {meta.Parser}"),
        };
    }

    private static string NormalizedNewlines(string text) => text.Replace("\r\n", "\n").Replace("\r", "\n");
    private static List<string[]> CsvRows(string text)
    {
        var rows = new List<string[]>();
        foreach (var line in NormalizedNewlines(text).Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var fields = new List<string>();
            var sb = new StringBuilder();
            bool inQuotes = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (inQuotes)
                {
                    if (c == '"') { if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; } else inQuotes = false; }
                    else sb.Append(c);
                }
                else if (c == '"') inQuotes = true;
                else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
                else sb.Append(c);
            }
            fields.Add(sb.ToString());
            rows.Add(fields.ToArray());
        }
        return rows;
    }

    private static FeedParseResult ParseTypedCsv(byte[] data, string feedId)
    {
        string text = Encoding.UTF8.GetString(data);
        if (text.ToLowerInvariant().Contains("<html")) throw new InvalidDataException("Feed structure not recognized: not a CSV feed (looks like an error page)");
        var rows = CsvRows(text);
        if (rows.Count == 0 || !rows[0].Select(x => x.Trim().ToLowerInvariant()).SequenceEqual(new[] { "type", "value", "threat", "severity" }))
            throw new InvalidDataException("Feed structure not recognized: expected header type,value,threat,severity");
        var result = new FeedParseResult { TotalRows = rows.Count - 1 };
        foreach (var row in rows.Skip(1))
        {
            if (row.Length >= 2 && MakeIndicator(feedId, row[0].Trim().ToLowerInvariant(), row[1].Trim(), row.ElementAtOrDefault(2)?.Trim(), row.ElementAtOrDefault(3)?.Trim().ToLowerInvariant()) is { } ind)
                result.Indicators.Add(ind);
            else { result.RejectedCount++; if (result.RejectedExamples.Count < 3) result.RejectedExamples.Add(string.Join(",", row)); }
        }
        return result;
    }

    private static FeedParseResult ParseLines(byte[] data, string feedId, string type, string severity)
    {
        string text = Encoding.UTF8.GetString(data);
        if (text.ToLowerInvariant().Contains("<html")) throw new InvalidDataException("Feed structure not recognized: not a text feed (looks like an error page)");
        var lines = NormalizedNewlines(text).Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#') && !l.StartsWith(';')).ToList();
        var result = new FeedParseResult { TotalRows = lines.Count };
        foreach (var line in lines)
        {
            if (MakeIndicator(feedId, type, line, null, severity) is { } ind) result.Indicators.Add(ind);
            else { result.RejectedCount++; if (result.RejectedExamples.Count < 3) result.RejectedExamples.Add(line); }
        }
        return result;
    }

    private static FeedParseResult ParseFeodo(byte[] data, string feedId)
    {
        using var doc = JsonDocument.Parse(data);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Feed structure not recognized: expected a JSON array of Feodo objects");
        var result = new FeedParseResult();
        foreach (var row in doc.RootElement.EnumerateArray())
        {
            result.TotalRows++;
            if (!row.TryGetProperty("ip_address", out var ipEl) || Normalize.Ip(ipEl.GetString() ?? "") is not { } ip)
            { result.RejectedCount++; continue; }
            result.Indicators.Add(new Indicator
            {
                FeedId = feedId, Type = "ipv4", Value = ip,
                Port = row.TryGetProperty("port", out var p) && p.TryGetInt32(out int pv) ? pv : null,
                Threat = "botnet_c2",
                MalwareFamily = row.TryGetProperty("malware", out var m) ? m.GetString() : null,
                Severity = "high",
                FirstSeen = row.TryGetProperty("first_seen", out var fs) ? fs.GetString() : null,
                LastSeen = row.TryGetProperty("last_online", out var ls) ? ls.GetString() : null,
                Reference = "https://feodotracker.abuse.ch/browse/",
            });
        }
        return result;
    }

    private static List<string> NonCommentLines(byte[] data)
    {
        string text = Encoding.UTF8.GetString(data);
        if (text.ToLowerInvariant().Contains("<html")) throw new InvalidDataException("Feed structure not recognized: not a CSV feed (looks like an error page)");
        return NormalizedNewlines(text).Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
    }

    private static FeedParseResult ParseSslblCerts(byte[] data, string feedId)
    {
        var lines = NonCommentLines(data);
        var result = new FeedParseResult { TotalRows = lines.Count };
        foreach (var line in lines)
        {
            var cols = CsvRows(line).FirstOrDefault() ?? Array.Empty<string>();
            if (cols.Length == 3 && MakeIndicator(feedId, "cert_sha1", cols[1].Trim(), "botnet_c2", "high", malwareFamily: cols[2].Trim(), firstSeen: cols[0].Trim()) is { } ind)
                result.Indicators.Add(ind);
            else { result.RejectedCount++; if (result.RejectedExamples.Count < 3) result.RejectedExamples.Add(line); }
        }
        return result;
    }

    private static FeedParseResult ParseSslblJa3(byte[] data, string feedId)
    {
        var lines = NonCommentLines(data);
        var result = new FeedParseResult { TotalRows = lines.Count };
        foreach (var line in lines)
        {
            var cols = CsvRows(line).FirstOrDefault() ?? Array.Empty<string>();
            if (cols.Length == 4 && MakeIndicator(feedId, "ja3", cols[0].Trim(), null, "info", malwareFamily: cols[3].Trim()) is { } ind)
            {
                ind.FirstSeen = cols[1].Trim();
                ind.LastSeen = cols[2].Trim();
                result.Indicators.Add(ind);
            }
            else { result.RejectedCount++; if (result.RejectedExamples.Count < 3) result.RejectedExamples.Add(line); }
        }
        return result;
    }

    private static FeedParseResult ParseSpamhaus(byte[] data, string feedId)
    {
        string text = Encoding.UTF8.GetString(data);
        if (text.ToLowerInvariant().Contains("<html")) throw new InvalidDataException("Feed structure not recognized: not a JSON Lines feed (looks like an error page)");
        var result = new FeedParseResult();
        foreach (var rawLine in NormalizedNewlines(text).Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0) continue;
            JsonDocument doc;
            try { doc = JsonDocument.Parse(line); } catch { result.RejectedCount++; result.TotalRows++; continue; }
            using (doc)
            {
                var obj = doc.RootElement;
                if (obj.TryGetProperty("type", out var t) && t.GetString() == "metadata")
                {
                    result.FeedCopyright = obj.TryGetProperty("copyright", out var c) ? c.GetString() : null;
                    result.FeedTerms = obj.TryGetProperty("terms", out var tm) ? tm.GetString() : null;
                    continue;
                }
                result.TotalRows++;
                if (obj.TryGetProperty("cidr", out var cidrEl) && MakeIndicator(feedId, "cidr", cidrEl.GetString() ?? "", "hijacked_netblock", "medium") is { } ind)
                {
                    ind.Reference = obj.TryGetProperty("sblid", out var sbl) ? $"https://www.spamhaus.org/sbl/query/{sbl.GetString()}" : null;
                    result.Indicators.Add(ind);
                }
                else { result.RejectedCount++; if (result.RejectedExamples.Count < 3) result.RejectedExamples.Add(line); }
            }
        }
        return result;
    }

    public static Indicator? MakeIndicator(string feedId, string type, string rawValue, string? threat, string? severity, int? confidence = null, string? malwareFamily = null, string? firstSeen = null, string? lastSeen = null, string? reference = null)
    {
        string? sev = severity is "high" or "medium" or "low" or "info" ? severity : null;
        switch (type)
        {
            case "ipv4": case "ipv6":
            {
                var ip = Normalize.Ip(rawValue);
                if (ip == null || (type == "ipv4") != Normalize.IsV4(ip)) return null;
                return new Indicator { FeedId = feedId, Type = type, Value = ip, Threat = threat, MalwareFamily = malwareFamily, Confidence = confidence, Severity = sev, FirstSeen = firstSeen, LastSeen = lastSeen, Reference = reference };
            }
            case "cidr":
                return Cidr.TryParse(rawValue, out _) ? new Indicator { FeedId = feedId, Type = type, Value = rawValue, Threat = threat, MalwareFamily = malwareFamily, Confidence = confidence, Severity = sev, FirstSeen = firstSeen, LastSeen = lastSeen, Reference = reference } : null;
            case "ip_port":
            {
                string ipPart; int port;
                if (rawValue.StartsWith('['))
                {
                    int close = rawValue.IndexOf(']');
                    if (close < 0 || !int.TryParse(rawValue.AsSpan(close + 2), out port)) return null;
                    ipPart = rawValue[1..close];
                }
                else
                {
                    int idx = rawValue.LastIndexOf(':');
                    if (idx < 0 || !int.TryParse(rawValue.AsSpan(idx + 1), out port)) return null;
                    ipPart = rawValue[..idx];
                }
                if (port is < 1 or > 65535 || Normalize.Ip(ipPart) is not { } pip) return null;
                return new Indicator { FeedId = feedId, Type = type, Value = pip, Port = port, Threat = threat, MalwareFamily = malwareFamily, Confidence = confidence, Severity = sev, FirstSeen = firstSeen, LastSeen = lastSeen, Reference = reference };
            }
            case "domain":
            {
                var d = Normalize.Domain(rawValue);
                return d != null && !Normalize.IsPublicSuffix(d) ? new Indicator { FeedId = feedId, Type = type, Value = d, Threat = threat, MalwareFamily = malwareFamily, Confidence = confidence, Severity = sev, FirstSeen = firstSeen, LastSeen = lastSeen, Reference = reference } : null;
            }
            case "url":
            {
                var u = Normalize.Url(rawValue);
                return u != null ? new Indicator { FeedId = feedId, Type = type, Value = u, Threat = threat, MalwareFamily = malwareFamily, Confidence = confidence, Severity = sev, FirstSeen = firstSeen, LastSeen = lastSeen, Reference = reference } : null;
            }
            case "cert_sha1": case "cert_sha256": case "file_md5": case "file_sha256": case "ja3": case "ja4":
            {
                string hex = new(rawValue.Where(char.IsAsciiHexDigit).Select(char.ToLowerInvariant).ToArray());
                int expected = type switch { "cert_sha1" => 40, "file_md5" => 32, "ja3" => 32, "ja4" => 0, _ => 64 };
                if (expected > 0 && hex.Length != expected) return null;
                if (expected == 0 && (hex.Length < 16 || hex.Length > 128)) return null;
                return new Indicator { FeedId = feedId, Type = type, Value = hex, Threat = threat, MalwareFamily = malwareFamily, Confidence = confidence, Severity = sev, FirstSeen = firstSeen, LastSeen = lastSeen, Reference = reference };
            }
            default: return null;
        }
    }
}

public readonly struct Cidr
{
    public readonly uint Start, End;
    public readonly bool IsV6;
    public readonly (ulong Hi, ulong Lo) Start6, End6;
    private Cidr(uint s, uint e) { Start = s; End = e; IsV6 = false; Start6 = End6 = (0, 0); }
    private Cidr((ulong, ulong) s, (ulong, ulong) e) { Start = End = 0; IsV6 = true; Start6 = s; End6 = e; }
    public static bool TryParse(string raw, out Cidr range)
    {
        range = default;
        var parts = raw.Split('/');
        if (parts.Length != 2 || !int.TryParse(parts[1], out int bits)) return false;
        var ip = Normalize.Ip(parts[0]);
        if (ip == null) return false;
        if (Normalize.Ipv4Value(ip) is uint v)
        {
            if (bits is < 0 or > 32) return false;
            uint mask = bits == 0 ? 0u : uint.MaxValue << (32 - bits);
            uint start = v & mask;
            range = new Cidr(start, start | ~mask);
            return true;
        }
        if (bits is < 0 or > 128 || !IPAddress.TryParse(ip, out var ip6)) return false;
        var bytes = ip6.GetAddressBytes();
        if (bytes.Length != 16) return false;
        ulong hi = 0, lo = 0;
        for (int i = 0; i < 8; i++) hi = hi << 8 | bytes[i];
        for (int i = 8; i < 16; i++) lo = lo << 8 | bytes[i];
        ulong sHi, sLo, eHi, eLo;
        if (bits <= 64)
        {
            ulong mask = bits == 0 ? 0UL : ulong.MaxValue << (64 - bits);
            sHi = hi & mask; sLo = 0; eHi = sHi | ~mask; eLo = ulong.MaxValue;
        }
        else
        {
            ulong mask = ulong.MaxValue << (128 - bits);
            sHi = hi; sLo = lo & mask; eHi = hi; eLo = sLo | ~mask;
        }
        range = new Cidr((sHi, sLo), (eHi, eLo));
        return true;
    }
    public bool Contains(string canonical)
    {
        if (!IsV6)
            return Normalize.Ipv4Value(canonical) is uint v && v >= Start && v <= End;
        if (!IPAddress.TryParse(canonical, out var ip6)) return false;
        var bytes = ip6.GetAddressBytes();
        if (bytes.Length != 16) return false;
        ulong hi = 0, lo = 0;
        for (int i = 0; i < 8; i++) hi = hi << 8 | bytes[i];
        for (int i = 8; i < 16; i++) lo = lo << 8 | bytes[i];
        if (hi < Start6.Hi || hi > End6.Hi) return false;
        if (hi == Start6.Hi && lo < Start6.Lo) return false;
        if (hi == End6.Hi && lo > End6.Lo) return false;
        return true;
    }
}

// ---------------- Indicator store ----------------

public sealed class IndicatorStore
{
    public Dictionary<string, Dictionary<string, Indicator>> Exact = new();
    public Dictionary<string, Indicator> IpPorts = new(), IpPortByIp = new();
    public List<(Cidr Range, Indicator Ind)> Cidrs = new();
    private List<(uint Start, uint End, Indicator Ind)> _v4Ranges = new();
    public List<Indicator> All = new();
    public int Count => All.Count;

    public void Load(List<Indicator> indicators, int? retentionSec, DateTimeOffset now)
    {
        Exact.Clear(); IpPorts.Clear(); IpPortByIp.Clear(); Cidrs.Clear(); All.Clear();
        DateTimeOffset? cutoff = retentionSec is int r ? now.AddSeconds(-r) : null;
        foreach (var ind in indicators)
        {
            if (cutoff is { } c && ind.LastSeen != null && DateTimeOffset.TryParse(ind.LastSeen, out var d) && d < c) continue;
            All.Add(ind);
            switch (ind.Type)
            {
                case "cidr":
                    if (Cidr.TryParse(ind.Value, out var range)) Cidrs.Add((range, ind));
                    break;
                case "ip_port":
                    if (ind.Port is int p)
                    {
                        IpPorts[$"{ind.Value}|{p}"] = ind;
                        IpPortByIp[ind.Value] = ind;
                        string t = Normalize.IsV4(ind.Value) ? "ipv4" : "ipv6";
                        if (!Exact.TryGetValue(t, out var byIp)) { byIp = new(); Exact[t] = byIp; }
                        byIp[ind.Value] = ind;
                    }
                    break;
                default:
                    if (!Exact.TryGetValue(ind.Type, out var map)) { map = new(); Exact[ind.Type] = map; }
                    map[ind.Value] = ind;
                    break;
            }
        }
        _v4Ranges = Cidrs.Where(c => !c.Range.IsV6).Select(c => (c.Range.Start, c.Range.End, c.Ind)).OrderBy(r => r.Start).ToList();
    }

    public Indicator? ExactMatch(string type, string value) => Exact.TryGetValue(type, out var m) && m.TryGetValue(value, out var i) ? i : null;
    public Indicator? IpPortMatch(string ip, int port) => IpPorts.GetValueOrDefault($"{ip}|{port}");
    public Indicator? IpPortByIpLookup(string ip) => IpPortByIp.GetValueOrDefault(ip);
    public Indicator? CidrMatch(string canonical)
    {
        if (Normalize.Ipv4Value(canonical) is uint v)
        {
            int lo = 0, hi = _v4Ranges.Count;
            while (lo < hi) { int mid = (lo + hi) / 2; if (_v4Ranges[mid].Start <= v) lo = mid + 1; else hi = mid; }
            for (int i = lo - 1, scanned = 0; i >= 0 && scanned < 128; i--, scanned++)
            {
                var r = _v4Ranges[i];
                if (v >= r.Start && v <= r.End) return r.Ind;
            }
            return null;
        }
        foreach (var (range, ind) in Cidrs) if (range.IsV6 && range.Contains(canonical)) return ind;
        return null;
    }
    public Indicator? DomainMatch(string observed)
    {
        if (!Exact.TryGetValue("domain", out var domains) || Normalize.Domain(observed) is not { } o) return null;
        string? candidate = o;
        while (candidate != null)
        {
            if (domains.TryGetValue(candidate, out var ind)) return ind;
            int dot = candidate.IndexOf('.');
            if (dot < 0) break;
            candidate = candidate[(dot + 1)..];
        }
        return null;
    }
    public IndicatorStore Snapshot()
    {
        var copy = new IndicatorStore();
        copy.Exact = Exact.ToDictionary(kv => kv.Key, kv => new Dictionary<string, Indicator>(kv.Value));
        copy.IpPorts = new Dictionary<string, Indicator>(IpPorts);
        copy.IpPortByIp = new Dictionary<string, Indicator>(IpPortByIp);
        copy.Cidrs = Cidrs.ToList();
        copy._v4Ranges = _v4Ranges.ToList();
        copy.All = All.ToList();
        return copy;
    }
}

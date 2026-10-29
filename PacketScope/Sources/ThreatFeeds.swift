import Foundation
import CryptoKit
import Security

// MARK: - Feed registry (feeds are data, not code)

public struct FeedMeta: Codable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var url: String // may contain {AUTH_KEY}
    public var homepage: String
    public var license: String
    public var attribution: String?
    public var requiresKey: Bool
    public var enabledByDefault: Bool
    public var refreshSec: Int
    public var minRefreshSec: Int
    public var maxAgeSec: Int
    public var baseSeverity: String // high | medium | low | info
    public var parser: String
    public var retentionSec: Int? // indicators last seen longer ago than this are dropped at load
    public var additionalUrls: [String]? // e.g. Spamhaus DROP v6, downloaded and parsed with the main file
    public init(id: String, name: String, url: String, homepage: String, license: String, attribution: String? = nil, requiresKey: Bool, enabledByDefault: Bool, refreshSec: Int, minRefreshSec: Int, maxAgeSec: Int, baseSeverity: String, parser: String, retentionSec: Int? = nil, additionalUrls: [String]? = nil) {
        self.id = id; self.name = name; self.url = url; self.homepage = homepage; self.license = license
        self.attribution = attribution; self.requiresKey = requiresKey; self.enabledByDefault = enabledByDefault
        self.refreshSec = refreshSec; self.minRefreshSec = minRefreshSec; self.maxAgeSec = maxAgeSec
        self.baseSeverity = baseSeverity; self.parser = parser; self.retentionSec = retentionSec; self.additionalUrls = additionalUrls
    }
}

public enum FeedRegistry {
    public static let all: [FeedMeta] = [
        FeedMeta(id: "feodo_recommended", name: "Feodo Tracker", url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json", homepage: "https://feodotracker.abuse.ch/", license: "CC0", requiresKey: false, enabledByDefault: true, refreshSec: 3600, minRefreshSec: 300, maxAgeSec: 86400, baseSeverity: "high", parser: "feodo_json"),
        FeedMeta(id: "sslbl_certs", name: "SSL Blacklist (certificates)", url: "https://sslbl.abuse.ch/blacklist/sslblacklist.csv", homepage: "https://sslbl.abuse.ch/", license: "CC0", requiresKey: false, enabledByDefault: true, refreshSec: 3600, minRefreshSec: 300, maxAgeSec: 86400, baseSeverity: "high", parser: "sslbl_certs_csv"),
        FeedMeta(id: "spamhaus_drop", name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop_v4.json", homepage: "https://www.spamhaus.org/drop/", license: "Spamhaus DROP terms", attribution: "Data from Spamhaus DROP — © Spamhaus. The stored copy keeps the feed's own date and copyright text.", requiresKey: false, enabledByDefault: true, refreshSec: 86400, minRefreshSec: 86400, maxAgeSec: 259200, baseSeverity: "medium", parser: "spamhaus_drop_json", additionalUrls: ["https://www.spamhaus.org/drop/drop_v6.json"]),
        FeedMeta(id: "sslbl_ja3", name: "SSL Blacklist (JA3)", url: "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv", homepage: "https://sslbl.abuse.ch/", license: "CC0", requiresKey: false, enabledByDefault: false, refreshSec: 3600, minRefreshSec: 300, maxAgeSec: 86400, baseSeverity: "info", parser: "sslbl_ja3_csv"),
        FeedMeta(id: "threatfox", name: "ThreatFox", url: "https://threatfox-api.abuse.ch/v2/files/exports/{AUTH_KEY}/full.csv.zip", homepage: "https://threatfox.abuse.ch/", license: "abuse.ch terms; free for non-profit use, commercial use may need a paid subscription", requiresKey: true, enabledByDefault: false, refreshSec: 3600, minRefreshSec: 300, maxAgeSec: 86400, baseSeverity: "high", parser: "threatfox_csv", retentionSec: 180 * 86400),
        FeedMeta(id: "urlhaus", name: "URLhaus", url: "https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv", homepage: "https://urlhaus.abuse.ch/", license: "abuse.ch terms; free for non-profit use, commercial use may need a paid subscription", requiresKey: true, enabledByDefault: false, refreshSec: 3600, minRefreshSec: 300, maxAgeSec: 86400, baseSeverity: "high", parser: "urlhaus_csv", retentionSec: 30 * 86400),
    ]
    public static func meta(_ id: String) -> FeedMeta? { all.first { $0.id == id } }
}

// MARK: - Indicators and state

public struct Indicator: Codable, Equatable, Hashable {
    public var feedId: String
    public var type: String // ipv4 ipv6 cidr ip_port domain url cert_sha1 cert_sha256 ja3 ja4 file_md5 file_sha256
    public var value: String
    public var port: Int?
    public var threat: String?
    public var malwareFamily: String?
    public var confidence: Int?
    public var severity: String?
    public var firstSeen: String?
    public var lastSeen: String?
    public var reference: String?
    public init(feedId: String, type: String, value: String, port: Int? = nil, threat: String? = nil, malwareFamily: String? = nil, confidence: Int? = nil, severity: String? = nil, firstSeen: String? = nil, lastSeen: String? = nil, reference: String? = nil) {
        self.feedId = feedId; self.type = type; self.value = value; self.port = port; self.threat = threat
        self.malwareFamily = malwareFamily; self.confidence = confidence; self.severity = severity
        self.firstSeen = firstSeen; self.lastSeen = lastSeen; self.reference = reference
    }
}

public struct FeedState: Codable, Equatable {
    public var feedId: String
    public var enabled: Bool
    public var lastSuccessAt: Double?
    public var lastAttemptAt: Double?
    public var lastError: String?
    public var etag: String?
    public var lastModified: String?
    public var indicatorCount: Int = 0
    public var fileSha256: String = ""
    public var consecutiveFailures: Int = 0
    public var keyInvalid: Bool = false
    public var newestIndicatorAt: String?
    public var feedCopyright: String?
    public var feedTerms: String?
    public init(feedId: String, enabled: Bool) { self.feedId = feedId; self.enabled = enabled }
    public func isStale(meta: FeedMeta, now: Double) -> Bool {
        guard let s = lastSuccessAt else { return true }
        return now - s > Double(meta.maxAgeSec)
    }
}

// MARK: - Normalization (shared by feeds and, later, observables)

public enum Normalize {
    public static func ip(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if s.hasPrefix("[") && s.hasSuffix("]") { s = String(s.dropFirst().dropLast()) }
        if s.hasPrefix("::ffff:"), let v4 = ipv4(String(s.dropFirst(7))) { return v4 }
        if let v4 = ipv4(s) { return v4 }
        return ipv6(s)
    }
    public static func ipv4(_ s: String) -> String? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var nums: [Int] = []
        for part in parts {
            guard !part.isEmpty, part.allSatisfy({ $0.isNumber }), let v = Int(part), v <= 255 else { return nil }
            if part.count > 1 && part.hasPrefix("0") { return nil } // reject ambiguous leading zeros
            nums.append(v)
        }
        return nums.map(String.init).joined(separator: ".")
    }
    public static func ipv4Value(_ canonical: String) -> UInt32? {
        guard let ip = ipv4(canonical) else { return nil }
        return ip.split(separator: ".").reduce(UInt32(0)) { $0 << 8 | UInt32($1)! }
    }
    public static func ipv6(_ s: String) -> String? {
        // Parse into 8 groups, then emit RFC 5952 compressed lowercase form.
        var head: [String] = [], tail: [String] = []
        var rest = s
        var usedDouble = false
        if let range = s.range(of: "::") {
            usedDouble = true
            head = s[s.startIndex..<range.lowerBound].split(separator: ":", omittingEmptySubsequences: false).map(String.init).filter { !$0.isEmpty }
            let tailStr = s[range.upperBound...]
            tail = tailStr.split(separator: ":", omittingEmptySubsequences: false).map(String.init).filter { !$0.isEmpty }
            rest = ""
        } else {
            head = s.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        }
        _ = rest
        func parseGroups(_ gs: [String]) -> [UInt16]? {
            var out: [UInt16] = []
            for (i, g) in gs.enumerated() {
                if g.contains("."), i == gs.count - 1, let v4 = ipv4Value(g) {
                    out.append(UInt16(v4 >> 16)); out.append(UInt16(v4 & 0xFFFF)); continue
                }
                guard !g.isEmpty, g.count <= 4, g.allSatisfy({ $0.isHexDigit }), let v = UInt16(g, radix: 16) else { return nil }
                out.append(v)
            }
            return out
        }
        guard let h = parseGroups(head), let t2 = usedDouble ? parseGroups(tail) : [] else { return nil }
        var groups: [UInt16] = []
        if usedDouble {
            guard h.count + t2.count < 8 else { return nil }
            groups = h + Array(repeating: 0, count: 8 - h.count - t2.count) + t2
        } else {
            guard h.count == 8 else { return nil }
            groups = h
        }
        if groups[0..<5].allSatisfy({ $0 == 0 }) && groups[5] == 0xFFFF {
            let v4 = "\(groups[6] >> 8).\(groups[6] & 0xFF).\(groups[7] >> 8).\(groups[7] & 0xFF)"
            return v4
        }
        var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0
        for i in 0..<8 {
            if groups[i] == 0 { if curStart < 0 { curStart = i; curLen = 1 } else { curLen += 1 }; if curLen > bestLen { bestLen = curLen; bestStart = curStart } }
            else { curStart = -1; curLen = 0 }
        }
        func hex(_ g: UInt16) -> String { String(g, radix: 16) }
        if bestLen >= 2 {
            return groups[0..<bestStart].map(hex).joined(separator: ":") + "::" + groups[(bestStart + bestLen)..<8].map(hex).joined(separator: ":")
        }
        return groups.map(hex).joined(separator: ":")
    }
    public static func domain(_ raw: String) -> String? {
        // UTS #46-style preparation: Unicode NFC, then case folding.
        var s = raw.precomposedStringWithCanonicalMapping
            .folding(options: [.caseInsensitive], locale: nil)
            .lowercased()
            .trimmingCharacters(in: .whitespaces)
        if s.hasSuffix(".") { s = String(s.dropLast()) }
        guard !s.isEmpty, s.count <= 253, !s.contains(" "), !s.contains("/"), !s.contains("_") else { return nil }
        let labels = s.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return nil }
        var out: [String] = []
        for label in labels {
            guard !label.isEmpty, label.count <= 63 else { return nil }
            if label.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }) {
                if label.hasPrefix("-") || label.hasSuffix("-") { return nil }
                out.append(String(label))
            } else {
                guard let ascii = punycodeEncode(String(label)) else { return nil }
                out.append("xn--" + ascii)
            }
        }
        return out.joined(separator: ".")
    }
    /// RFC 3492 punycode encoding for one label (without the xn-- prefix).
    public static func punycodeEncode(_ label: String) -> String? {
        let label = label.precomposedStringWithCanonicalMapping
        let base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128
        func adapt(_ deltaIn: Int, _ numPoints: Int, _ first: Bool) -> Int {
            var delta = first ? deltaIn / damp : deltaIn / 2
            delta += delta / numPoints
            var k = 0
            while delta > ((base - tmin) * tmax) / 2 { delta /= base - tmin; k += base }
            return k + (base - tmin + 1) * delta / (delta + skew)
        }
        func encodeDigit(_ d: Int) -> Character { d < 26 ? Character(UnicodeScalar(97 + d)!) : Character(UnicodeScalar(48 + d - 26)!) }
        let scalars = Array(label.unicodeScalars)
        var output = scalars.filter { $0.value < 128 }.map { Character($0) }
        let basicCount = output.count
        var handled = basicCount
        if basicCount > 0 && handled < scalars.count { output.append("-") }
        var n = initialN, delta = 0, bias = initialBias
        while handled < scalars.count {
            var m = Int.max
            for sc in scalars where Int(sc.value) >= n { m = min(m, Int(sc.value)) }
            guard m != Int.max else { return nil }
            delta += (m - n) * (handled + 1)
            n = m
            for sc in scalars {
                let c = Int(sc.value)
                if c < n { delta += 1 }
                if c == n {
                    var q = delta
                    var k = base
                    while true {
                        let tt: Int
                        if k <= bias { tt = tmin } else if k >= bias + tmax { tt = tmax } else { tt = k - bias }
                        if q < tt { break }
                        output.append(encodeDigit(tt + (q - tt) % (base - tt)))
                        q = (q - tt) / (base - tt)
                        k += base
                    }
                    output.append(encodeDigit(q))
                    bias = adapt(delta, handled + 1, handled == basicCount)
                    delta = 0
                    handled += 1
                }
            }
            delta += 1; n += 1
        }
        return String(output)
    }
    public static func domainMatches(feedDomain: String, observed: String) -> Bool {
        guard let f = domain(feedDomain), let o = domain(observed) else { return false }
        return o == f || o.hasSuffix("." + f)
    }
    public static func isPublicSuffix(_ domainName: String) -> Bool {
        guard let d = domain(domainName) else { return true }
        return PublicSuffix.isPublicSuffix(d)
    }
    public static func isNeverFlaggedIP(_ canonicalIP: String) -> Bool {
        if let v4 = ipv4Value(canonicalIP) {
            let a = v4 >> 24, b = (v4 >> 16) & 0xFF
            if a == 10 || a == 127 || a == 0 { return true }              // private / loopback / unspecified
            if a == 172 && (16...31).contains(b) { return true }          // private
            if a == 192 && b == 168 { return true }                       // private
            if a == 169 && b == 254 { return true }                       // link-local
            if a >= 224 { return true }                                   // multicast + reserved
            if a == 100 && (64...127).contains(b) { return true }         // CGNAT shared space
            if a == 192 && b == 0 && (v4 >> 8) & 0xFF == 0 { return true } // 192.0.0.0/24 only
            if a == 198 && (b == 18 || b == 19) { return true }           // benchmarking
            return false
        }
        let s = canonicalIP
        if s == "::1" || s == "::" { return true }
        if s.hasPrefix("fe80:") || s.hasPrefix("fe80::") { return true }  // link-local
        if s.hasPrefix("fc") || s.hasPrefix("fd") { return true }         // unique local (approximation; checked on parsed groups below too)
        if s.hasPrefix("ff") { return true }                              // multicast
        return false
    }
    public static func url(_ raw: String) -> String? {
        guard var c = URLComponents(string: raw.trimmingCharacters(in: .whitespaces)) else { return nil }
        guard let scheme = c.scheme?.lowercased(), scheme == "http" || scheme == "https", let hostRaw = c.host, let host = domain(hostRaw) else { return nil }
        c.scheme = scheme
        c.host = host
        if (scheme == "http" && c.port == 80) || (scheme == "https" && c.port == 443) { c.port = nil }
        c.fragment = nil
        return c.string
    }
    public static func defanged(_ value: String, type: String) -> String {
        switch type {
        case "url":
            var v = value.replacingOccurrences(of: "http://", with: "hxxp://").replacingOccurrences(of: "https://", with: "hxxps://")
            v = v.replacingOccurrences(of: ".", with: "[.]")
            return v
        case "domain", "ipv4", "ipv6", "cidr":
            return value.replacingOccurrences(of: ".", with: "[.]")
        default: return value
        }
    }
}


// MARK: - Public Suffix List (full bundled copy, MPL 2.0)

public enum PublicSuffix {
    /// Version date parsed from the bundled list header, e.g. "2026-10-22".
    public static var versionDate: String { loader.versionDate }
    public static var ruleCount: Int { loader.rules.count + loader.wildcards.count }

    private final class Loader {
        var rules: Set<String> = []
        var wildcards: Set<String> = [] // suffix after "*."
        var exceptions: Set<String> = []
        var versionDate: String = "unknown"
        init() {
            guard let text = Self.loadText() else { return }
            for rawLine in text.split(whereSeparator: { $0 == "\n" }) {
                let line = rawLine.trimmingCharacters(in: .whitespaces)
                if line.hasPrefix("// VERSION:") {
                    // "// VERSION: 2026-10-22_08-36-41_UTC"
                    if let date = line.split(separator: " ").last?.split(separator: "_").first { versionDate = String(date) }
                    continue
                }
                if line.isEmpty || line.hasPrefix("//") { continue }
                if line.hasPrefix("!") { exceptions.insert(String(line.dropFirst())) }
                else if line.hasPrefix("*.") { wildcards.insert(String(line.dropFirst(2))) }
                else { rules.insert(line) }
            }
        }
        static func loadText() -> String? {
            if let url = Bundle.main.url(forResource: "public_suffix_list", withExtension: "dat"),
               let text = try? String(contentsOf: url, encoding: .utf8) { return text }
            // Test/development fallback: the source tree next to the working directory.
            for candidate in ["PacketScope/Resources/public_suffix_list.dat", "../PacketScope/Resources/public_suffix_list.dat"] {
                if let text = try? String(contentsOfFile: candidate, encoding: .utf8) { return text }
            }
            return nil
        }
        func publicSuffix(of domain: String) -> String {
            let labels = domain.split(separator: ".").map(String.init)
            guard !labels.isEmpty else { return domain }
            // Exception rules: the public suffix is the rule minus its leftmost label.
            for i in labels.indices {
                let candidate = labels[i...].joined(separator: ".")
                if exceptions.contains(candidate) {
                    return labels[(i + 1)...].joined(separator: ".")
                }
            }
            var suffix = labels.last!
            var longest = 1
            for i in labels.indices {
                let candidate = labels[i...].joined(separator: ".")
                let n = labels.count - i
                if rules.contains(candidate), n >= longest { suffix = candidate; longest = n }
                if i + 1 < labels.count {
                    let wildBase = labels[(i + 1)...].joined(separator: ".")
                    if wildcards.contains(wildBase), n >= longest { suffix = candidate; longest = n }
                }
            }
            return suffix
        }
    }
    private static let loader = Loader()
    public static func isPublicSuffix(_ domain: String) -> Bool {
        if loader.rules.isEmpty {
            // Bundled list missing (should not happen): conservative small fallback.
            let fallback: Set<String> = ["github.io", "gitlab.io", "herokuapp.com", "co.uk", "com.au"]
            return fallback.contains(domain) || !domain.contains(".")
        }
        return loader.publicSuffix(of: domain) == domain
    }
}


/// One shared parser for indicator dates. abuse.ch feeds use
/// "yyyy-MM-dd" and "yyyy-MM-dd HH:mm:ss"; ISO8601DateFormatter alone
/// rejects both, which silently disabled the 30-day downgrade and the
/// retention filters. Used by the matcher, the store, and the updater.
public enum FeedDates {
    public static func parse(_ raw: String) -> Date? {
        if let d = ISO8601DateFormatter().date(from: raw) { return d }
        for format in ["yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd"] {
            let df = DateFormatter()
            df.dateFormat = format
            df.timeZone = TimeZone(identifier: "UTC")
            df.locale = Locale(identifier: "en_US_POSIX")
            if let d = df.date(from: raw) { return d }
        }
        return nil
    }
}

// MARK: - CIDR ranges (sorted interval list)

public struct CIDRRange {
    public var start: UInt32, end: UInt32 // IPv4
    public var start6: (UInt64, UInt64), end6: (UInt64, UInt64) // IPv6 hi/lo
    public var isV6: Bool
    public var text: String
    public static func parse(_ raw: String) -> (range: CIDRRange, network: String)? {
        let parts = raw.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let bits = Int(parts[1]) else { return nil }
        guard let ip = Normalize.ip(String(parts[0])) else { return nil }
        if let v = Normalize.ipv4Value(ip) {
            guard bits >= 0, bits <= 32 else { return nil }
            let mask: UInt32 = bits == 0 ? 0 : UInt32.max << (32 - bits)
            let start = v & mask
            let end = start | ~mask
            return (CIDRRange(start: start, end: end, start6: (0, 0), end6: (0, 0), isV6: false, text: raw), ip)
        }
        guard bits >= 0, bits <= 128 else { return nil }
        guard let (hi, lo) = ipv6Pair(ip) else { return nil }
        var sHi = hi, sLo = lo
        if bits <= 64 {
            let mask: UInt64 = bits == 0 ? 0 : UInt64.max << (64 - bits)
            sHi = hi & mask; sLo = 0
            let eHi = sHi | ~mask
            return (CIDRRange(start: 0, end: 0, start6: (sHi, sLo), end6: (eHi, UInt64.max), isV6: true, text: raw), ip)
        } else {
            let mask: UInt64 = UInt64.max << (128 - bits)
            sLo = lo & mask
            return (CIDRRange(start: 0, end: 0, start6: (sHi, sLo), end6: (hi, sLo | ~mask), isV6: true, text: raw), ip)
        }
    }
    static func ipv6Pair(_ canonical: String) -> (UInt64, UInt64)? {
        // Expand compressed form via Foundation's inet_pton for exactness.
        var addr = in6_addr()
        let ok = canonical.withCString { inet_pton(AF_INET6, $0, &addr) }
        guard ok == 1 else { return nil }
        let bytes = withUnsafeBytes(of: addr) { Array($0) }
        guard bytes.count == 16 else { return nil }
        var hi: UInt64 = 0, lo: UInt64 = 0
        for i in 0..<8 { hi = hi << 8 | UInt64(bytes[i]) }
        for i in 8..<16 { lo = lo << 8 | UInt64(bytes[i]) }
        return (hi, lo)
    }
    public func contains(ip canonical: String) -> Bool {
        if isV6 {
            guard let (hi, lo) = Self.ipv6Pair(canonical) else { return false }
            if hi != start6.0 && hi != end6.0 { return hi > start6.0 && hi < end6.0 }
            if hi == start6.0 && hi == end6.0 { return lo >= start6.1 && lo <= end6.1 }
            if hi == start6.0 { return lo >= start6.1 }
            return lo <= end6.1
        }
        guard let v = Normalize.ipv4Value(canonical) else { return false }
        return v >= start && v <= end
    }
}

// MARK: - Feed parsers (strict: unknown structure is rejected)

public struct FeedParseResult {
    public var feedCopyright: String?
    public var feedTerms: String?
    public var indicators: [Indicator]
    public var rejectedCount: Int
    public var rejectedExamples: [String]
    public var totalRows: Int
    public var validFraction: Double { totalRows == 0 ? 1 : Double(indicators.count) / Double(max(1, totalRows)) }
}

public enum FeedParseError: Error, LocalizedError {
    case badStructure(String)
    case unsupportedParser(String)
    public var errorDescription: String? {
        switch self { case .badStructure(let m): return "Feed structure not recognized: \(m)"; case .unsupportedParser(let p): return "No parser implemented yet for \(p)" }
    }
}

public enum FeedParser {
    public static func parse(meta: FeedMeta, data: Data, customType: String? = nil, customColumn: Int = 0) throws -> FeedParseResult {
        switch meta.parser {
        case "test_csv", "custom_csv": return try parseTypedCSV(data: data, feedId: meta.id)
        case "custom_lines": return try parseLines(data: data, feedId: meta.id, type: customType ?? "domain", severity: meta.baseSeverity)
        case "feodo_json": return try parseFeodo(data: data, feedId: meta.id)
        case "sslbl_certs_csv": return try parseSSLBLCerts(data: data, feedId: meta.id)
        case "sslbl_ja3_csv": return try parseSSLBLJA3(data: data, feedId: meta.id)
        case "spamhaus_drop_json": return try parseSpamhausDROP(data: data, feedId: meta.id)
        default: throw FeedParseError.unsupportedParser(meta.parser)
        }
    }

    static func normalizedNewlines(_ text: String) -> String {
        // Swift Characters merge CR+LF into one grapheme cluster, so line
        // splitting must happen after normalizing CRLF/CR to LF.
        text.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
    }

    static func csvRows(_ text: String) -> [[String]] {
        let text = normalizedNewlines(text)
        var rows: [[String]] = []
        var row: [String] = [], field = "", inQuotes = false
        var chars = Array(text)
        var i = 0
        func endField() { row.append(field); field = "" }
        func endRow() { endField(); rows.append(row); row = [] }
        while i < chars.count {
            let c = chars[i]
            if inQuotes {
                if c == "\"" {
                    if i + 1 < chars.count && chars[i + 1] == "\"" { field.append("\""); i += 1 } else { inQuotes = false }
                } else { field.append(c) }
            } else if c == "\"" { inQuotes = true }
            else if c == "," { endField() }
            else if c == "\n" { endRow() }
            else if c != "\r" { field.append(c) }
            i += 1
        }
        if !field.isEmpty || !row.isEmpty { endRow() }
        return rows.filter { !$0.allSatisfy { $0.trimmingCharacters(in: .whitespaces).isEmpty } }
    }

    /// The synthetic test feed and user CSVs with the documented header:
    /// type,value,threat,severity
    static func parseTypedCSV(data: Data, feedId: String) throws -> FeedParseResult {
        guard let text = String(data: data, encoding: .utf8), !text.lowercased().contains("<html") else {
            throw FeedParseError.badStructure("not a CSV feed (looks like an error page)")
        }
        let rows = csvRows(text)
        guard let header = rows.first, header.map({ $0.trimmingCharacters(in: .whitespaces).lowercased() }) == ["type", "value", "threat", "severity"] else {
            throw FeedParseError.badStructure("expected header type,value,threat,severity")
        }
        var out: [Indicator] = [], rejected: [String] = []
        var rejectedCount = 0
        for row in rows.dropFirst() {
            guard row.count >= 2 else { rejectedCount += 1; if rejected.count <= 3 { rejected.append(row.joined(separator: ",")) }; continue }
            let type = row[0].trimmingCharacters(in: .whitespaces).lowercased()
            let rawValue = row[1].trimmingCharacters(in: .whitespaces)
            let threat = row.count > 2 ? row[2].trimmingCharacters(in: .whitespaces) : nil
            let severity = row.count > 3 ? row[3].trimmingCharacters(in: .whitespaces).lowercased() : nil
            if let ind = makeIndicator(feedId: feedId, type: type, rawValue: rawValue, threat: threat, severity: severity) {
                out.append(ind)
            } else {
                rejectedCount += 1
                if rejected.count <= 3 { rejected.append(row.joined(separator: ",")) }
            }
        }
        return FeedParseResult(indicators: out, rejectedCount: rejectedCount, rejectedExamples: rejected, totalRows: max(0, rows.count - 1))
    }


    /// Feodo Tracker recommended: a JSON array of objects with ip_address,
    /// port, status, hostname, as_number, as_name, country, first_seen,
    /// last_online, malware. Anything else is rejected.
    static func parseFeodo(data: Data, feedId: String) throws -> FeedParseResult {
        guard let obj = try? JSONSerialization.jsonObject(with: data), let rows = obj as? [[String: Any]] else {
            throw FeedParseError.badStructure("expected a JSON array of Feodo objects")
        }
        var out: [Indicator] = [], rejected = 0, examples: [String] = []
        for row in rows {
            guard let ipRaw = row["ip_address"] as? String, let ip = Normalize.ip(ipRaw) else {
                rejected += 1; if examples.count < 3 { examples.append(String(describing: row)) }
                continue
            }
            out.append(Indicator(feedId: feedId, type: "ipv4", value: ip, port: row["port"] as? Int,
                                 threat: "botnet_c2", malwareFamily: row["malware"] as? String, severity: "high",
                                 firstSeen: row["first_seen"] as? String, lastSeen: row["last_online"] as? String,
                                 reference: "https://feodotracker.abuse.ch/browse/"))
        }
        return FeedParseResult(indicators: out, rejectedCount: rejected, rejectedExamples: examples, totalRows: rows.count)
    }

    static func nonCommentLines(_ data: Data) throws -> [String] {
        guard let text = String(data: data, encoding: .utf8), !text.lowercased().contains("<html") else {
            throw FeedParseError.badStructure("not a CSV feed (looks like an error page)")
        }
        return normalizedNewlines(text).split(whereSeparator: { $0 == "\n" }).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty && !$0.hasPrefix("#") }
    }

    /// SSLBL certificates: "ListingDate,SHA1,Reason" under a # comment header.
    static func parseSSLBLCerts(data: Data, feedId: String) throws -> FeedParseResult {
        let lines = try nonCommentLines(data)
        var out: [Indicator] = [], rejected = 0, examples: [String] = []
        for line in lines {
            let cols = csvRows(line).first ?? []
            guard cols.count == 3, let ind = makeIndicator(feedId: feedId, type: "cert_sha1", rawValue: cols[1].trimmingCharacters(in: .whitespaces), threat: "botnet_c2", severity: "high", malwareFamily: cols[2].trimmingCharacters(in: .whitespaces), firstSeen: cols[0].trimmingCharacters(in: .whitespaces)) else {
                rejected += 1; if examples.count < 3 { examples.append(line) }
                continue
            }
            out.append(ind)
        }
        return FeedParseResult(indicators: out, rejectedCount: rejected, rejectedExamples: examples, totalRows: lines.count)
    }

    /// SSLBL JA3: "JA3,FirstSeen,LastSeen,Reason" under a # comment header.
    static func parseSSLBLJA3(data: Data, feedId: String) throws -> FeedParseResult {
        let lines = try nonCommentLines(data)
        var out: [Indicator] = [], rejected = 0, examples: [String] = []
        for line in lines {
            let cols = csvRows(line).first ?? []
            guard cols.count == 4, var ind = makeIndicator(feedId: feedId, type: "ja3", rawValue: cols[0].trimmingCharacters(in: .whitespaces), threat: nil, severity: "info", malwareFamily: cols[3].trimmingCharacters(in: .whitespaces)) else {
                rejected += 1; if examples.count < 3 { examples.append(line) }
                continue
            }
            ind.firstSeen = cols[1].trimmingCharacters(in: .whitespaces)
            ind.lastSeen = cols[2].trimmingCharacters(in: .whitespaces)
            out.append(ind)
        }
        return FeedParseResult(indicators: out, rejectedCount: rejected, rejectedExamples: examples, totalRows: lines.count)
    }

    /// Spamhaus DROP: JSON Lines, one {"cidr","sblid","rir"} object per line,
    /// ending with a {"type":"metadata",...,"copyright","terms"} line whose
    /// copyright and terms are kept with the stored copy.
    static func parseSpamhausDROP(data: Data, feedId: String) throws -> FeedParseResult {
        guard let text = String(data: data, encoding: .utf8), !text.lowercased().contains("<html") else {
            throw FeedParseError.badStructure("not a JSON Lines feed (looks like an error page)")
        }
        var out: [Indicator] = [], rejected = 0, examples: [String] = []
        var copyright: String?, terms: String?
        var total = 0
        for rawLine in normalizedNewlines(text).split(whereSeparator: { $0 == "\n" }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            total += 1
            guard let lineData = line.data(using: .utf8), let obj = (try? JSONSerialization.jsonObject(with: lineData)) as? [String: Any] else {
                rejected += 1; if examples.count < 3 { examples.append(line) }
                continue
            }
            if (obj["type"] as? String) == "metadata" {
                copyright = obj["copyright"] as? String
                terms = obj["terms"] as? String
                total -= 1 // the metadata line is not a data row
                continue
            }
            guard let cidr = obj["cidr"] as? String, var ind = makeIndicator(feedId: feedId, type: "cidr", rawValue: cidr, threat: "hijacked_netblock", severity: "medium") else {
                rejected += 1; if examples.count < 3 { examples.append(line) }
                continue
            }
            ind.reference = (obj["sblid"] as? String).map { "https://www.spamhaus.org/sbl/query/\($0)" }
            out.append(ind)
        }
        var result = FeedParseResult(indicators: out, rejectedCount: rejected, rejectedExamples: examples, totalRows: total)
        result.feedCopyright = copyright
        result.feedTerms = terms
        return result
    }

    static func parseLines(data: Data, feedId: String, type: String, severity: String) throws -> FeedParseResult {
        guard let text = String(data: data, encoding: .utf8), !text.lowercased().contains("<html") else {
            throw FeedParseError.badStructure("not a text feed (looks like an error page)")
        }
        var out: [Indicator] = [], rejectedCount = 0, examples: [String] = []
        let lines = normalizedNewlines(text).split(whereSeparator: { $0 == "\n" }).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty && !$0.hasPrefix("#") && !$0.hasPrefix(";") }
        for line in lines {
            if let ind = makeIndicator(feedId: feedId, type: type, rawValue: line, threat: nil, severity: severity) { out.append(ind) }
            else { rejectedCount += 1; if examples.count < 3 { examples.append(line) } }
        }
        return FeedParseResult(indicators: out, rejectedCount: rejectedCount, rejectedExamples: examples, totalRows: lines.count)
    }

    public static func makeIndicator(feedId: String, type: String, rawValue: String, threat: String?, severity: String?, confidence: Int? = nil, malwareFamily: String? = nil, firstSeen: String? = nil, lastSeen: String? = nil, reference: String? = nil) -> Indicator? {
        let sev = severity.flatMap { ["high", "medium", "low", "info"].contains($0) ? $0 : nil }
        switch type {
        case "ipv4", "ipv6":
            guard let ip = Normalize.ip(rawValue), (type == "ipv4") == (Normalize.ipv4(ip) != nil) else { return nil }
            return Indicator(feedId: feedId, type: type, value: ip, threat: threat, malwareFamily: malwareFamily, confidence: confidence, severity: sev, firstSeen: firstSeen, lastSeen: lastSeen, reference: reference)
        case "cidr":
            guard let parsed = CIDRRange.parse(rawValue) else { return nil }
            _ = parsed
            return Indicator(feedId: feedId, type: type, value: rawValue, threat: threat, malwareFamily: malwareFamily, confidence: confidence, severity: sev, firstSeen: firstSeen, lastSeen: lastSeen, reference: reference)
        case "ip_port":
            // Accept 1.2.3.4:8443 and [v6]:8443.
            var ipPart: String, portPart: String
            if rawValue.hasPrefix("["), let close = rawValue.firstIndex(of: "]") {
                ipPart = String(rawValue[rawValue.index(after: rawValue.startIndex)..<close])
                let rest = rawValue[rawValue.index(after: close)...]
                guard rest.hasPrefix(":"), let p = Int(rest.dropFirst()), (1...65535).contains(p) else { return nil }
                portPart = String(p)
            } else {
                guard let idx = rawValue.lastIndex(of: ":"), let p = Int(rawValue[rawValue.index(after: idx)...]), (1...65535).contains(p) else { return nil }
                ipPart = String(rawValue[..<idx]); portPart = String(p)
            }
            guard let ip = Normalize.ip(ipPart), let port = Int(portPart) else { return nil }
            return Indicator(feedId: feedId, type: type, value: ip, port: port, threat: threat, malwareFamily: malwareFamily, confidence: confidence, severity: sev, firstSeen: firstSeen, lastSeen: lastSeen, reference: reference)
        case "domain":
            guard let d = Normalize.domain(rawValue), !Normalize.isPublicSuffix(d) else { return nil }
            return Indicator(feedId: feedId, type: type, value: d, threat: threat, malwareFamily: malwareFamily, confidence: confidence, severity: sev, firstSeen: firstSeen, lastSeen: lastSeen, reference: reference)
        case "url":
            guard let u = Normalize.url(rawValue) else { return nil }
            return Indicator(feedId: feedId, type: type, value: u, threat: threat, malwareFamily: malwareFamily, confidence: confidence, severity: sev, firstSeen: firstSeen, lastSeen: lastSeen, reference: reference)
        case "cert_sha1", "cert_sha256", "file_md5", "file_sha256", "ja3", "ja4":
            let hex = rawValue.lowercased().filter { $0.isHexDigit }
            let expected = ["cert_sha1": 40, "file_md5": 32, "ja3": 32][type] ?? (type == "ja4" ? 0 : 64)
            if expected > 0 { guard hex.count == expected, hex == rawValue.lowercased().filter({ !$0.isWhitespace }) else { return nil } }
            else { guard hex.count >= 16, hex.count <= 128 else { return nil } }
            return Indicator(feedId: feedId, type: type, value: hex, threat: threat, malwareFamily: malwareFamily, confidence: confidence, severity: sev, firstSeen: firstSeen, lastSeen: lastSeen, reference: reference)
        default: return nil
    }
}
}

// MARK: - Indicator store (hash sets + sorted CIDR intervals)

/// A store is an immutable snapshot once loading finishes. Callers that
/// start work (for example, an analysis) keep their own snapshot; a feed
/// swap afterwards builds a new store and never mutates theirs.
public final class IndicatorStore {
    public private(set) var exact: [String: [String: Indicator]] = [:] // type -> value -> indicator
    public private(set) var ipPorts: [String: Indicator] = [:]          // "ip|port"
    public private(set) var ipPortByIP: [String: Indicator] = [:]       // ip -> ip_port indicator (port-differs match)
    public private(set) var cidrs: [(range: CIDRRange, indicator: Indicator)] = []
    private var v4Ranges: [(start: UInt32, end: UInt32, indicator: Indicator)] = []
    public private(set) var allIndicators: [Indicator] = []
    public var count: Int { allIndicators.count }

    public init() {}
    public func load(indicators: [Indicator], retentionSec: Int?, now: Date) {
        exact = [:]; ipPorts = [:]; ipPortByIP = [:]; cidrs = []; allIndicators = []
        let cutoff = retentionSec.map { now.addingTimeInterval(-Double($0)) }
        for ind in indicators {
            if let cutoff = cutoff, let ls = ind.lastSeen, let d = FeedDates.parse(ls), d < cutoff { continue }
            allIndicators.append(ind)
            switch ind.type {
            case "cidr":
                if let parsed = CIDRRange.parse(ind.value) { cidrs.append((parsed.range, ind)) }
            case "ip_port":
                if let p = ind.port { ipPorts["\(ind.value)|\(p)"] = ind; ipPortByIP[ind.value] = ind }
                if Normalize.ipv4(ind.value) != nil { exact["ipv4", default: [:]][ind.value] = ind }
                else { exact["ipv6", default: [:]][ind.value] = ind }
            default:
                exact[ind.type, default: [:]][ind.value] = ind
            }
        }
        cidrs.sort { a, b in
            if a.range.isV6 != b.range.isV6 { return !a.range.isV6 }
            return a.range.isV6 ? (a.range.start6.0, a.range.start6.1) < (b.range.start6.0, b.range.start6.1) : a.range.start < b.range.start
        }
        v4Ranges = cidrs.filter { !$0.range.isV6 }.map { (start: $0.range.start, end: $0.range.end, indicator: $0.indicator) }
    }
    public func snapshot() -> IndicatorStore {
        let copy = IndicatorStore()
        copy.exact = exact; copy.ipPorts = ipPorts; copy.ipPortByIP = ipPortByIP; copy.cidrs = cidrs; copy.v4Ranges = v4Ranges; copy.allIndicators = allIndicators
        return copy
    }
    public func exactMatch(type: String, value: String) -> Indicator? { exact[type]?[value] }
    public func ipPortMatch(ip: String, port: Int) -> Indicator? { ipPorts["\(ip)|\(port)"] }
    public func ipPortByIP(_ ip: String) -> Indicator? { ipPortByIP[ip] }
    public func cidrMatch(ip canonical: String) -> Indicator? {
        if let v = Normalize.ipv4Value(canonical) {
            // Binary search the sorted v4 range index, then walk back over
            // any overlapping ranges that start at or before this address.
            var lo = 0, hi = v4Ranges.count
            while lo < hi {
                let mid = (lo + hi) / 2
                if v4Ranges[mid].start <= v { lo = mid + 1 } else { hi = mid }
            }
            var i = lo - 1
            var scanned = 0
            while i >= 0 && scanned < 128 {
                let r = v4Ranges[i]
                if v >= r.start && v <= r.end { return r.indicator }
                i -= 1; scanned += 1
            }
            return nil
        }
        for entry in cidrs where entry.range.isV6 && entry.range.contains(ip: canonical) { return entry.indicator }
        return nil
    }
    public func domainMatch(observed: String) -> Indicator? {
        guard let domains = exact["domain"], let o = Normalize.domain(observed) else { return nil }
        var candidate: String? = o
        while let c = candidate {
            if let ind = domains[c] { return ind }
            guard let dot = c.firstIndex(of: ".") else { break }
            candidate = String(c[c.index(after: dot)...])
        }
        return nil
    }
}

// MARK: - Keychain (Auth-Keys never touch plain config or logs)

public protocol FeedKeyStore {
    func key(for feedId: String) -> String?
    func setKey(_ key: String?, for feedId: String)
}

public final class InMemoryKeyStore: FeedKeyStore {
    private var values: [String: String] = [:]
    public init() {}
    public func key(for feedId: String) -> String? { values[feedId] }
    public func setKey(_ key: String?, for feedId: String) { values[feedId] = key }
}

public final class KeychainKeyStore: FeedKeyStore {
    private let service = "local.packetscope.demo.threatfeeds"
    public init() {}
    public func key(for feedId: String) -> String? {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: feedId, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    public func setKey(_ key: String?, for feedId: String) {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: feedId]
        SecItemDelete(base as CFDictionary)
        guard let key = key, !key.isEmpty, let data = key.data(using: .utf8) else { return }
        var add = base; add[kSecValueData as String] = data
        SecItemAdd(add as CFDictionary, nil)
    }
}

public enum FeedSecrets {
    /// Converts any error into text that is safe to log, store, and display.
    /// URLError/NSError embed the failing URL (which may contain an Auth-Key)
    /// in their descriptions and userInfo, so those strings are never used.
    public static func sanitizedError(_ error: Error, key: String?) -> String {
        if let urlError = error as? URLError {
            return "Feed update failed (network error \(urlError.code.rawValue)). Check the connection and try again."
        }
        if let parseError = error as? FeedParseError {
            return redacted(parseError.localizedDescription, key: key)
        }
        let ns = error as NSError
        if ns.domain == "PacketScopeFeeds" {
            // Our own errors carry hand-written messages without URLs.
            return redacted(ns.localizedDescription, key: key)
        }
        if ns.domain == NSURLErrorDomain {
            return "Feed update failed (network error \(ns.code)). Check the connection and try again."
        }
        // Unknown error type: describe it without its userInfo or description.
        return redacted("Feed update failed (\(ns.domain) error \(ns.code)).", key: key)
    }
    public static func redacted(_ text: String, key: String?) -> String {
        guard let key = key, !key.isEmpty else { return text }
        return text.replacingOccurrences(of: key, with: "•••")
    }
    public static func downloadURL(meta: FeedMeta, key: String?) -> String? {
        if meta.url.contains("{AUTH_KEY}") {
            guard let key = key, !key.isEmpty else { return nil }
            return meta.url.replacingOccurrences(of: "{AUTH_KEY}", with: key)
        }
        return meta.url
    }
}

// MARK: - Updater

public struct FeedTransportResponse {
    public var status: Int
    public var data: Data?
    public var etag: String?
    public var lastModified: String?
    public var retryAfterSec: Int?
    public init(status: Int, data: Data? = nil, etag: String? = nil, lastModified: String? = nil, retryAfterSec: Int? = nil) {
        self.status = status; self.data = data; self.etag = etag; self.lastModified = lastModified; self.retryAfterSec = retryAfterSec
    }
}

public protocol FeedTransport {
    func fetch(url: URL, etag: String?, lastModified: String?, userAgent: String, timeoutSec: Int, maxBytes: Int) async throws -> FeedTransportResponse
}

public final class URLSessionFeedTransport: FeedTransport {
    public init() {}
    public func fetch(url: URL, etag: String?, lastModified: String?, userAgent: String, timeoutSec: Int, maxBytes: Int) async throws -> FeedTransportResponse {
        guard url.scheme == "https" else { throw NSError(domain: "PacketScopeFeeds", code: 10, userInfo: [NSLocalizedDescriptionKey: "Feed URLs must use HTTPS"]) }
        var req = URLRequest(url: url, timeoutInterval: TimeInterval(timeoutSec))
        req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        if let etag = etag { req.setValue(etag, forHTTPHeaderField: "If-None-Match") }
        if let lm = lastModified { req.setValue(lm, forHTTPHeaderField: "If-Modified-Since") }
        let (data, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw NSError(domain: "PacketScopeFeeds", code: 11, userInfo: [NSLocalizedDescriptionKey: "No HTTP response"]) }
        if http.statusCode == 200 && data.count > maxBytes {
            throw NSError(domain: "PacketScopeFeeds", code: 12, userInfo: [NSLocalizedDescriptionKey: "Feed file is larger than the 50 MB cap"])
        }
        let retry = http.value(forHTTPHeaderField: "Retry-After").flatMap(Int.init)
        return FeedTransportResponse(status: http.statusCode, data: http.statusCode == 200 ? data : nil,
                                     etag: http.value(forHTTPHeaderField: "ETag"), lastModified: http.value(forHTTPHeaderField: "Last-Modified"),
                                     retryAfterSec: retry)
    }
}

public final class FeedUpdater {
    public let directory: URL
    public let transport: FeedTransport
    public let keyStore: FeedKeyStore
    public let userAgent = "PacketScope/0.2.0 (macOS; threat-feed updater)"
    public let maxBytes = 50 * 1024 * 1024
    private var states: [String: FeedState] = [:]

    public init(directory: URL, transport: FeedTransport, keyStore: FeedKeyStore) {
        self.directory = directory
        self.transport = transport
        self.keyStore = keyStore
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [FileAttributeKey.posixPermissions: 0o700])
        loadStates()
    }

    public static var defaultDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("PacketScope/ThreatFeeds", isDirectory: true)
    }

    public func state(for meta: FeedMeta) -> FeedState {
        states[meta.id] ?? FeedState(feedId: meta.id, enabled: meta.enabledByDefault)
    }
    public func setEnabled(_ enabled: Bool, for meta: FeedMeta) {
        var s = state(for: meta); s.enabled = enabled; states[meta.id] = s; saveStates()
    }
    public func nextAllowedUpdate(for meta: FeedMeta, now: Date) -> Date {
        let s = state(for: meta)
        guard let last = s.lastAttemptAt else { return now }
        return Date(timeIntervalSince1970: last + Double(meta.minRefreshSec))
    }
    /// Scheduled refreshes wait refreshSec plus a random 0-10% delay so
    /// installs do not all contact the provider in the same second.
    public static func scheduledDelaySec(refreshSec: Int, randomFraction: Double) -> Double {
        Double(refreshSec) * (1.0 + 0.10 * min(1, max(0, randomFraction)))
    }
    public func nextScheduledRefresh(for meta: FeedMeta, after: Date, randomFraction: Double) -> Date {
        let s = state(for: meta)
        let base = s.lastSuccessAt.map { Date(timeIntervalSince1970: $0) } ?? after
        return base.addingTimeInterval(Self.scheduledDelaySec(refreshSec: meta.refreshSec, randomFraction: randomFraction))
    }
    /// Starts a refresh without blocking the caller. Analysis never awaits
    /// this; it matches against whatever store snapshot it already loaded.
    public func refreshInBackground(feeds: [FeedMeta], now: Date) {
        Task.detached { [weak self] in
            guard let self = self else { return }
            for meta in feeds {
                let s = self.state(for: meta)
                let due = (s.lastSuccessAt.map { now.timeIntervalSince1970 - $0 > Double(meta.refreshSec) } ?? true)
                if due { _ = await self.update(feed: meta, now: now, manual: false) }
            }
        }
    }
    public func backoffSec(consecutiveFailures: Int) -> Int {
        switch consecutiveFailures { case 0: return 0; case 1: return 300; case 2: return 900; default: return 3600 }
    }

    private var stateFile: URL { directory.appendingPathComponent("state.json") }
    private func feedFile(_ id: String) -> URL { directory.appendingPathComponent("\(id).feed") }
    private func loadStates() {
        guard let data = try? Data(contentsOf: stateFile),
              let decoded = try? JSONDecoder().decode([String: FeedState].self, from: data) else { return }
        states = decoded
    }
    private func saveStates() {
        if let data = try? JSONEncoder().encode(states) { try? data.write(to: stateFile, options: [.atomic]) }
    }
    public func storedData(for meta: FeedMeta) -> Data? { try? Data(contentsOf: feedFile(meta.id)) }

    public enum UpdateOutcome: Equatable { case updated, notModified, tooSoon(Date), failed(String), keyInvalid, disabled }

    @discardableResult
    public func update(feed meta: FeedMeta, now: Date, manual: Bool) async -> (FeedState, UpdateOutcome) {
        var s = state(for: meta)
        guard s.enabled else { return (s, .disabled) }
        // Hard floor: never fetch sooner than minRefreshSec, even manually.
        if let last = s.lastAttemptAt, now.timeIntervalSince1970 - last < Double(meta.minRefreshSec) {
            return (s, .tooSoon(Date(timeIntervalSince1970: last + Double(meta.minRefreshSec))))
        }
        // Respect failure backoff as well (also floored by the minimum interval).
        if s.consecutiveFailures > 0, let last = s.lastAttemptAt {
            let wait = max(Double(meta.minRefreshSec), Double(backoffSec(consecutiveFailures: s.consecutiveFailures)))
            if now.timeIntervalSince1970 - last < wait && !manual {
                return (s, .tooSoon(Date(timeIntervalSince1970: last + wait)))
            }
        }
        let key = meta.requiresKey ? keyStore.key(for: meta.id) : nil
        guard let urlString = FeedSecrets.downloadURL(meta: meta, key: key), let url = URL(string: urlString) else {
            s.lastError = "This feed needs an Auth-Key. Add your own key in Settings."
            s.keyInvalid = true
            states[meta.id] = s; saveStates()
            return (s, .keyInvalid)
        }
        guard url.scheme == "https" else {
            s.lastError = "Feed URL must use HTTPS."
            states[meta.id] = s; saveStates()
            return (s, .failed("Feed URL must use HTTPS."))
        }
        s.lastAttemptAt = now.timeIntervalSince1970
        states[meta.id] = s; saveStates()
        do {
            let resp = try await transport.fetch(url: url, etag: s.etag, lastModified: s.lastModified, userAgent: userAgent, timeoutSec: 30, maxBytes: maxBytes)
            switch resp.status {
            case 304:
                s.lastSuccessAt = now.timeIntervalSince1970
                s.lastError = nil; s.consecutiveFailures = 0; s.keyInvalid = false
                states[meta.id] = s; saveStates()
                return (s, .notModified)
            case 401, 403:
                s.lastError = FeedSecrets.redacted("The feed rejected the request (HTTP \(resp.status)). The Auth-Key may be invalid; add a current key in Settings.", key: key)
                s.keyInvalid = true
                states[meta.id] = s; saveStates()
                return (s, .keyInvalid)
            case 429:
                s.consecutiveFailures += 1
                let wait = resp.retryAfterSec ?? backoffSec(consecutiveFailures: s.consecutiveFailures)
                s.lastError = "The feed asked us to slow down. Next try in about \(max(wait, meta.minRefreshSec)) seconds."
                states[meta.id] = s; saveStates()
                return (s, .failed(s.lastError!))
            case 200:
                guard var data = resp.data else { throw NSError(domain: "PacketScopeFeeds", code: 13, userInfo: [NSLocalizedDescriptionKey: "Empty response"]) }
                // Additional files (e.g. Spamhaus DROP v6) are downloaded and
                // parsed together with the main file.
                for extra in meta.additionalUrls ?? [] {
                    guard let extraURL = URL(string: extra), extraURL.scheme == "https" else {
                        throw NSError(domain: "PacketScopeFeeds", code: 16, userInfo: [NSLocalizedDescriptionKey: "Additional feed URL must use HTTPS"])
                    }
                    let extraResp = try await transport.fetch(url: extraURL, etag: nil, lastModified: nil, userAgent: userAgent, timeoutSec: 30, maxBytes: maxBytes)
                    guard extraResp.status == 200, let extraData = extraResp.data else {
                        throw NSError(domain: "PacketScopeFeeds", code: extraResp.status, userInfo: [NSLocalizedDescriptionKey: "Additional feed file failed (HTTP \(extraResp.status))"])
                    }
                    data.append(contentsOf: "\n".data(using: .utf8)!)
                    data.append(extraData)
                }
                // Download to a temporary file, validate, then swap atomically.
                let tmp = directory.appendingPathComponent("\(meta.id).tmp.\(UUID().uuidString)")
                try data.write(to: tmp)
                defer { try? FileManager.default.removeItem(at: tmp) }
                let parsed = try FeedParser.parse(meta: meta, data: data)
                guard parsed.validFraction >= 0.95 else {
                    throw NSError(domain: "PacketScopeFeeds", code: 14, userInfo: [NSLocalizedDescriptionKey: "Only \(parsed.indicators.count) of \(parsed.totalRows) rows parsed; keeping the previous copy. First rejected: \(parsed.rejectedExamples.first ?? "unknown")"])
                }
                if parsed.totalRows > 0 && s.indicatorCount >= 20 && parsed.indicators.count < s.indicatorCount / 5 {
                    throw NSError(domain: "PacketScopeFeeds", code: 15, userInfo: [NSLocalizedDescriptionKey: "Indicator count collapsed from \(s.indicatorCount) to \(parsed.indicators.count); keeping the previous copy."])
                }
                // Atomic swap via replaceItem where available, else move.
                let dest = feedFile(meta.id)
                if FileManager.default.fileExists(atPath: dest.path) {
                    _ = try FileManager.default.replaceItemAt(dest, withItemAt: tmp)
                } else {
                    try FileManager.default.moveItem(at: tmp, to: dest)
                }
                s.lastSuccessAt = now.timeIntervalSince1970
                s.lastError = nil; s.consecutiveFailures = 0; s.keyInvalid = false
                s.etag = resp.etag; s.lastModified = resp.lastModified
                s.indicatorCount = parsed.indicators.count
                s.fileSha256 = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                s.newestIndicatorAt = Self.newestIndicatorDate(parsed.indicators)
                s.feedCopyright = parsed.feedCopyright
                s.feedTerms = parsed.feedTerms
                states[meta.id] = s; saveStates()
                writeIndex(for: meta, state: s, indicators: parsed.indicators)
                return (s, .updated)
            default:
                throw NSError(domain: "PacketScopeFeeds", code: resp.status, userInfo: [NSLocalizedDescriptionKey: "HTTP \(resp.status)"])
            }
        } catch {
            s.consecutiveFailures += 1
            s.lastError = FeedSecrets.sanitizedError(error, key: key)
            states[meta.id] = s; saveStates()
            return (s, .failed(s.lastError ?? "Update failed"))
        }
    }

    private func indexFile(_ id: String) -> URL { directory.appendingPathComponent("index-\(id).json") }
    private struct StoredIndex: Codable { var fileSha256: String; var indicators: [Indicator] }
    private func writeIndex(for meta: FeedMeta, state: FeedState, indicators: [Indicator]) {
        let stored = StoredIndex(fileSha256: state.fileSha256, indicators: indicators)
        if let data = try? JSONEncoder().encode(stored) { try? data.write(to: indexFile(meta.id), options: [.atomic]) }
    }
    private func readIndex(for meta: FeedMeta) -> [Indicator]? {
        guard let data = try? Data(contentsOf: indexFile(meta.id)),
              let stored = try? JSONDecoder().decode(StoredIndex.self, from: data) else { return nil }
        return stored.indicators
    }
    public static func newestIndicatorDate(_ indicators: [Indicator]) -> String? {
        let fmts = ["yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd"]
        var best: (Date, String)?
        _ = fmts
        for ind in indicators {
            for raw in [ind.lastSeen, ind.firstSeen].compactMap({ $0 }) {
                if let d = FeedDates.parse(raw), best == nil || d > best!.0 { best = (d, raw) }
            }
        }
        return best?.1
    }

    /// Parses the stored copies of all enabled feeds into one store.
    /// A copy that no longer parses is skipped; the last good parse wins
    /// because files are only ever swapped after validation.
    /// Stores a user-provided feed file (custom local feeds) after validation.
    public func importLocalCopy(feed meta: FeedMeta, data: Data, customType: String? = nil) throws {
        let parsed = try FeedParser.parse(meta: meta, data: data, customType: customType)
        guard parsed.validFraction >= 0.95 else {
            throw NSError(domain: "PacketScopeFeeds", code: 14, userInfo: [NSLocalizedDescriptionKey: "Only \(parsed.indicators.count) of \(parsed.totalRows) rows parsed; the file was not imported."])
        }
        let dest = feedFile(meta.id)
        let tmp = directory.appendingPathComponent("\(meta.id).tmp.\(UUID().uuidString)")
        try data.write(to: tmp)
        if FileManager.default.fileExists(atPath: dest.path) { _ = try FileManager.default.replaceItemAt(dest, withItemAt: tmp) }
        else { try FileManager.default.moveItem(at: tmp, to: dest) }
        var s = state(for: meta)
        s.lastSuccessAt = Date().timeIntervalSince1970
        s.lastAttemptAt = s.lastSuccessAt
        s.lastError = nil; s.consecutiveFailures = 0
        s.indicatorCount = parsed.indicators.count
        s.fileSha256 = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        s.newestIndicatorAt = Self.newestIndicatorDate(parsed.indicators)
        s.enabled = true
        states[meta.id] = s; saveStates()
        writeIndex(for: meta, state: s, indicators: parsed.indicators)
    }

    public func loadStore(now: Date, extraMetas: [FeedMeta] = []) -> (store: IndicatorStore, perFeed: [String: (meta: FeedMeta, state: FeedState, count: Int)]) {
        let store = IndicatorStore()
        var perFeed: [String: (FeedMeta, FeedState, Int)] = [:]
        var merged: [Indicator] = []
        for meta in FeedRegistry.all + extraMetas {
            let s = state(for: meta)
            guard s.enabled, storedData(for: meta) != nil else {
                perFeed[meta.id] = (meta, s, 0)
                continue
            }
            // Prefer the persisted normalized index; fall back to parsing.
            let indicators: [Indicator]
            if let indexed = readIndex(for: meta) { indicators = indexed }
            else if let data = storedData(for: meta), let parsed = try? FeedParser.parse(meta: meta, data: data) { indicators = parsed.indicators }
            else { perFeed[meta.id] = (meta, s, 0); continue }
            // Per-feed retention windows are applied while merging.
            let kept: [Indicator]
            if let retention = meta.retentionSec {
                let cutoff = now.addingTimeInterval(-Double(retention))
                kept = indicators.filter { ind in
                    guard let ls = ind.lastSeen, let d = FeedDates.parse(ls) else { return true }
                    return d >= cutoff
                }
            } else { kept = indicators }
            merged.append(contentsOf: kept)
            perFeed[meta.id] = (meta, s, kept.count)
        }
        store.load(indicators: merged, retentionSec: nil, now: now)
        return (store, perFeed)
    }
}

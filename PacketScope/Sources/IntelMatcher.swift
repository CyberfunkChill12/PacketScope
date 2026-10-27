import Foundation

// MARK: - Threat-intel matching (all local, against the on-device store)

public struct AllowlistEntry: Codable, Equatable, Identifiable {
    public var id: String { value }
    public var value: String // normalized IP, domain, URL, or hash
    public var reason: String
    public var addedAt: Double
    public init(value: String, reason: String = "", addedAt: Double = 0) {
        self.value = value; self.reason = reason; self.addedAt = addedAt
    }
}

public struct ThreatMatch: Codable, Equatable, Identifiable {
    public var id: String
    public var indicator: Indicator
    public var matchedOn: String
    public var observed: String
    public var destinationIP: String?
    public var destinationPort: Int?
    public var destinationName: String?
    public var dnsName: String?
    public var sni: String?
    public var url: String?
    public var direction: String // outbound | inbound | dns_only
    public var connected: Bool
    public var severity: String // high | medium | low | info
    public var severityReasons: [String]
    public var frames: [Int]
    public var filter: String
    public var evidenceCount: Int
    public var feedName: String = ""
    public var feedHomepage: String = ""
}

public struct ThreatIntelOutcome: Equatable {
    public var matches: [ThreatMatch] = []
    public var ignoredByAllowlist: Int = 0
    public var ignoredValues: [String] = []
    public var checkedIPs: Int = 0
    public var checkedIPsTotal: Int = 0
    public var checkedDomains: Int = 0
    public var checkedURLs: Int = 0
    public var checkedCerts: Int = 0
    public var checkedFingerprints: Int = 0
    public var filesChecked: Bool = false // file reconstruction is deferred by design
}

public enum IntelSeverity {
    public static let order = ["info", "low", "medium", "high"]
    public static func adjust(_ severity: String, by delta: Int) -> String {
        let i = order.firstIndex(of: severity) ?? 0
        return order[min(3, max(0, i + delta))]
    }
}

public enum PopularDomains {
    // Small sample used only for the shared-hosting downgrade. A full
    // popularity list (for example Tranco, license permitting) can replace it.
    static let top: Set<String> = ["google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com", "x.com", "apple.com", "microsoft.com", "amazon.com", "netflix.com", "wikipedia.org", "cloudflare.com", "github.com", "linkedin.com", "office.com", "live.com", "bing.com", "yahoo.com", "whatsapp.com", "zoom.us", "adobe.com", "salesforce.com", "dropbox.com", "spotify.com", "reddit.com", "tiktok.com", "baidu.com", "wordpress.com", "mozilla.org", "akamai.com"]
    public static func contains(_ domain: String) -> Bool {
        guard let d = Normalize.domain(domain) else { return false }
        if top.contains(d) { return true }
        // A subdomain of a listed domain counts as the same site.
        return top.contains { d == $0 || d.hasSuffix("." + $0) }
    }
}

public enum IntelMatcher {
    public static func match(report: CaptureReport, store: IndicatorStore, metas: [String: FeedMeta], allowlist: [AllowlistEntry], now: Date) -> ThreatIntelOutcome {
        let facts = report.facts
        var outcome = ThreatIntelOutcome()
        let allowValues = Set(allowlist.map { Normalize.domain($0.value) ?? $0.value.lowercased() })
        let allowIPs = Set(allowlist.compactMap { Normalize.ip($0.value) })
        var raw: [ThreatMatch] = []
        var seen = Set<String>()

        func meta(for ind: Indicator) -> FeedMeta? { metas[ind.feedId] }
        func baseSeverity(for ind: Indicator) -> String {
            if let s = ind.severity { return s }
            if ind.feedId == "threatfox", let c = ind.confidence {
                return c >= 75 ? "high" : (c >= 50 ? "medium" : "low")
            }
            return meta(for: ind)?.baseSeverity ?? "medium"
        }
        func append(_ m: ThreatMatch) {
            let key = "\(m.indicator.feedId)|\(m.indicator.type)|\(m.indicator.value)|\(m.observed)|\(m.destinationIP ?? "")"
            guard !seen.contains(key) else { return }
            // Allowlist: counted, never silently dropped.
            let observedNorm = Normalize.ip(m.observed) ?? (Normalize.domain(m.observed) ?? m.observed.lowercased())
            if allowValues.contains(observedNorm) || allowValues.contains(m.indicator.value.lowercased()) || (m.destinationIP.map { allowIPs.contains($0) } ?? false) {
                outcome.ignoredByAllowlist += 1
                if !outcome.ignoredValues.contains(m.observed) { outcome.ignoredValues.append(m.observed) }
                return
            }
            seen.insert(key)
            raw.append(m)
        }
        func makeMatch(ind: Indicator, matchedOn: String, observed: String, dest: DestinationRecord?, dnsName: String?, sni: String?, url: String?, direction: String, connected: Bool, frames: [Int], filter: String, count: Int) -> ThreatMatch {
            var reasons = ["base: \(baseSeverity(for: ind))"]
            var sev = baseSeverity(for: ind)
            if !connected {
                sev = IntelSeverity.adjust(sev, by: -1)
                reasons.append("downgraded: contact attempted, not completed")
            }
            if let ls = ind.lastSeen, let date = ISO8601DateFormatter().date(from: ls), now.timeIntervalSince(date) > 30 * 86400 {
                sev = IntelSeverity.adjust(sev, by: -1)
                reasons.append("downgraded: indicator last seen over 30 days ago")
            }
            // IP-only match where the visible name is a different, popular site.
            if ["ipv4", "ipv6", "cidr", "ip_port"].contains(matchedOn), let name = dest?.name ?? sni ?? dnsName,
               let nd = Normalize.domain(name), nd != Normalize.domain(ind.value), PopularDomains.contains(nd) {
                sev = IntelSeverity.adjust(sev, by: -1)
                reasons.append("downgraded: IP-only match on shared hosting")
            }
            var m = ThreatMatch(id: "\(ind.feedId)|\(ind.type)|\(ind.value)|\(observed)", indicator: ind, matchedOn: matchedOn, observed: observed,
                               destinationIP: dest?.address, destinationPort: dest?.port, destinationName: dest?.name,
                               dnsName: dnsName, sni: sni, url: url, direction: direction, connected: connected,
                               severity: sev, severityReasons: reasons, frames: Array(frames.prefix(200)), filter: filter, evidenceCount: count)
            m.feedName = meta(for: ind)?.name ?? ind.feedId
            m.feedHomepage = meta(for: ind)?.homepage ?? ""
            return m
        }

        let destinations = facts?.destinations ?? []
        func destConnected(_ d: DestinationRecord) -> Bool { d.outcome == "connected" || d.outcome == "reset_later" || d.outcome == "refused" }

        // --- Destination IPs and ports over the FULL observable set ---
        // (retained destinations merged with every observed endpoint; a match
        // outside the retained table still produces a finding)
        var ips = Set<String>()
        var endpointsByIP: [String: ObservableEndpoint] = [:]
        for e in facts?.observableEndpoints ?? [] {
            guard let ip = Normalize.ip(e.address) else { continue }
            ips.insert(ip)
            if let cur = endpointsByIP[ip] {
                if e.packets > cur.packets { endpointsByIP[ip] = e }
            } else { endpointsByIP[ip] = e }
        }
        for d in destinations { if let ip = Normalize.ip(d.address) { ips.insert(ip) } }
        for ip in ips {
            if Normalize.isNeverFlaggedIP(ip) { continue }
            let dest = destinations.first { Normalize.ip($0.address) == ip }
            let endpoint = endpointsByIP[ip]
            let port = dest?.port ?? endpoint?.port ?? 0
            let connected = dest.map(destConnected) ?? false
            let frames = dest?.packetNumbers ?? endpoint?.frames ?? []
            let filter = dest?.evidenceFilter ?? "ip.addr==\(ip)"
            let count = dest?.evidenceCount ?? endpoint?.packets ?? frames.count
            let pseudoDest = dest ?? DestinationRecord(address: ip, port: port, protocolLabel: "Unknown", outcome: "not_checked", packets: endpoint?.packets ?? 0, packetNumbers: frames, evidenceFilter: filter, evidenceCount: count)
            if let ind = store.exactMatch(type: Normalize.ipv4(ip) != nil ? "ipv4" : "ipv6", value: ip) {
                append(makeMatch(ind: ind, matchedOn: Normalize.ipv4(ip) != nil ? "ipv4" : "ipv6", observed: ip, dest: pseudoDest, dnsName: dest?.name, sni: dest?.nameSource == "sni" ? dest?.name : nil, url: nil, direction: "outbound", connected: connected, frames: frames, filter: filter, count: count))
            }
            if port > 0, let ind = store.ipPortMatch(ip: ip, port: port) {
                append(makeMatch(ind: ind, matchedOn: "ip_port", observed: "\(ip):\(port)", dest: pseudoDest, dnsName: dest?.name, sni: nil, url: nil, direction: "outbound", connected: connected, frames: frames, filter: "ip.addr==\(ip) && tcp.port==\(port)", count: count))
            } else if let ind = store.ipPortByIP(ip) {
                var m = makeMatch(ind: ind, matchedOn: "ip_port", observed: "\(ip):\(port)", dest: pseudoDest, dnsName: dest?.name, sni: nil, url: nil, direction: "outbound", connected: connected, frames: frames, filter: "ip.addr==\(ip)", count: count)
                m.severity = IntelSeverity.adjust(m.severity, by: -1)
                m.severityReasons.append("downgraded: same IP, different port (listed \(ind.port ?? 0))")
                append(m)
            }
            if let ind = store.cidrMatch(ip: ip) {
                append(makeMatch(ind: ind, matchedOn: "cidr", observed: ip, dest: pseudoDest, dnsName: dest?.name, sni: nil, url: nil, direction: "outbound", connected: connected, frames: frames, filter: filter, count: count))
            }
        }
        outcome.checkedIPs = ips.count
        outcome.checkedIPsTotal = max(facts?.observableIPCount ?? 0, ips.count)

        // --- Domains: lookups, observed names, CNAME targets, SNI, HTTP hosts ---
        var domains = Set<String>()
        func checkDomain(_ rawName: String, frame: Int?, dnsOnlyIfUnconnected: Bool) {
            guard let name = Normalize.domain(rawName) else { return }
            domains.insert(name)
            guard let ind = store.domainMatch(observed: name) else { return }
            // Which destination, if any, did this name lead to?
            let dest = destinations.first { d in
                d.name == name || (facts?.domains.first { $0.name == name }?.addresses.contains(d.address) ?? false)
            }
            let connected = dest.map(destConnected) ?? false
            append(makeMatch(ind: ind, matchedOn: "domain", observed: name, dest: dest, dnsName: name, sni: dest?.nameSource == "sni" ? dest?.name : nil, url: nil,
                             direction: connected ? "outbound" : "dns_only", connected: connected,
                             frames: frame.map { [$0] } ?? dest?.packetNumbers ?? [], filter: dest?.evidenceFilter ?? "dns.qry.name == \"\(name)\"", count: dest?.evidenceCount ?? 1))
        }
        for lookup in facts?.dnsLookups ?? [] { checkDomain(lookup.name, frame: lookup.frame, dnsOnlyIfUnconnected: true) }
        for domain in facts?.domains ?? [] { checkDomain(domain.name, frame: domain.packetNumbers.first, dnsOnlyIfUnconnected: true) }
        for target in facts?.cnameTargets ?? [] { checkDomain(target, frame: nil, dnsOnlyIfUnconnected: true) }
        for d in destinations where d.nameSource == "sni" { if let n = d.name { checkDomain(n, frame: d.packetNumbers.first, dnsOnlyIfUnconnected: false) } }
        for host in facts?.httpHosts ?? [] { checkDomain(host, frame: nil, dnsOnlyIfUnconnected: false) }
        outcome.checkedDomains = domains.count

        // --- URLs (exact match only) ---
        var urlCount = 0
        for rawURL in facts?.httpURLs ?? [] {
            guard let url = Normalize.url(rawURL) else { continue }
            urlCount += 1
            guard let ind = store.exactMatch(type: "url", value: url) else { continue }
            let host = URLComponents(string: url)?.host
            let dest = destinations.first { $0.name == host }
            append(makeMatch(ind: ind, matchedOn: "url", observed: url, dest: dest, dnsName: host, sni: nil, url: url, direction: "outbound", connected: dest.map(destConnected) ?? true, frames: dest?.packetNumbers ?? [], filter: "http.request.full_uri == \"\(url)\"", count: dest?.evidenceCount ?? 1))
        }
        outcome.checkedURLs = urlCount

        // --- Certificates ---
        var certCount = 0
        for cert in facts?.certificates ?? [] {
            certCount += 1
            let dest = destinations.first { $0.address == cert.serverAddress && $0.port == cert.serverPort }
            if let ind = store.exactMatch(type: "cert_sha1", value: cert.sha1) {
                append(makeMatch(ind: ind, matchedOn: "cert_sha1", observed: cert.sha1, dest: dest, dnsName: dest?.name, sni: nil, url: nil, direction: "outbound", connected: true, frames: [cert.frame], filter: dest?.evidenceFilter ?? "tls.handshake.certificate", count: 1))
            }
            if let ind = store.exactMatch(type: "cert_sha256", value: cert.sha256) {
                append(makeMatch(ind: ind, matchedOn: "cert_sha256", observed: cert.sha256, dest: dest, dnsName: dest?.name, sni: nil, url: nil, direction: "outbound", connected: true, frames: [cert.frame], filter: dest?.evidenceFilter ?? "tls.handshake.certificate", count: 1))
            }
        }
        outcome.checkedCerts = certCount

        // --- TLS fingerprints ---
        var fpCount = 0
        for fp in facts?.fingerprints ?? [] {
            fpCount += 1
            let dest = destinations.first { $0.address == fp.serverAddress && $0.port == fp.serverPort }
            let connected = dest.map(destConnected) ?? false
            if let ind = store.exactMatch(type: "ja3", value: fp.ja3) {
                append(makeMatch(ind: ind, matchedOn: "ja3", observed: fp.ja3, dest: dest, dnsName: dest?.name, sni: fp.sni, url: nil, direction: "outbound", connected: connected, frames: [fp.frame], filter: dest?.evidenceFilter ?? "tls.handshake.type == 1", count: 1))
            }
            if let ind = store.exactMatch(type: "ja4", value: fp.ja4) {
                append(makeMatch(ind: ind, matchedOn: "ja4", observed: fp.ja4, dest: dest, dnsName: dest?.name, sni: fp.sni, url: nil, direction: "outbound", connected: connected, frames: [fp.frame], filter: dest?.evidenceFilter ?? "tls.handshake.type == 1", count: 1))
            }
        }
        outcome.checkedFingerprints = fpCount

        // --- Upgrade: same destination matched by 2+ types or 2+ feeds ---
        var byDest: [String: [Int]] = [:]
        for (i, m) in raw.enumerated() {
            let key = m.destinationIP ?? m.dnsName ?? m.observed
            byDest[key, default: []].append(i)
        }
        for (_, indices) in byDest where indices.count > 1 {
            let types = Set(indices.map { raw[$0].matchedOn })
            let feeds = Set(indices.map { raw[$0].indicator.feedId })
            if types.count >= 2 || feeds.count >= 2 {
                for i in indices {
                    raw[i].severity = IntelSeverity.adjust(raw[i].severity, by: 1)
                    raw[i].severityReasons.append("upgraded: same destination matched \(max(types.count, feeds.count)) indicator types or feeds")
                }
            }
        }
        let sevRank = ["high": 0, "medium": 1, "low": 2, "info": 3]
        raw.sort { (sevRank[$0.severity] ?? 4) < (sevRank[$1.severity] ?? 4) }
        outcome.matches = raw
        return outcome
    }
}

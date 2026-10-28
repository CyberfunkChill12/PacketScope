import Foundation

// MARK: - Structured capture results (the Results page renders only from this)

public enum ResultFormat {
    public static func bytes(_ n: Int) -> String {
        let d = Double(n)
        if d >= 1_073_741_824 { return String(format: "%.1f GB", d / 1_073_741_824) }
        if d >= 1_048_576 { return String(format: "%.1f MB", d / 1_048_576) }
        if d >= 1024 { return String(format: "%.1f KB", d / 1024) }
        return "\(n) B"
    }
    public static func duration(_ s: Double) -> String {
        if s < 60 { return String(format: "%.1f s", s) }
        let total = Int(s.rounded())
        return String(format: "%d:%02d", total / 60, total % 60)
    }
    public static func packetTime(_ s: Double) -> String {
        let m = Int(s) / 60
        let sec = s - Double(m * 60)
        return String(format: "%d:%05.2f", m, sec)
    }
    public static func count(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }
    public static func ms(_ v: Double) -> String { String(format: "%.0f ms", v) }
}

public struct EvidenceRef: Codable, Equatable {
    public var filter: String
    public var frames: [Int]
    public var count: Int
    public init(filter: String, frames: [Int], count: Int) { self.filter = filter; self.frames = Array(frames.prefix(200)); self.count = count }
}

public struct PathStage: Codable, Identifiable, Equatable {
    public var id: String // local | dns | tcp | tls | app
    public var status: String // passed | failed | warning | not_visible | not_reached
    public var result: String
    public var detail: String
    public var evidence: EvidenceRef?
    public init(id: String, status: String, result: String, detail: String, evidence: EvidenceRef? = nil) {
        self.id = id; self.status = status; self.result = result; self.detail = detail; self.evidence = evidence
    }
    public var title: String {
        switch id { case "local": return "Local network"; case "dns": return "Name lookup (DNS)"; case "tcp": return "Connection (TCP)"; case "tls": return "Secure setup (TLS)"; default: return "App response" }
    }
}

public struct ConnectionPathResult: Codable, Identifiable, Equatable {
    public var id: String { destination }
    public var destination: String
    public var stages: [PathStage]
    public init(destination: String, stages: [PathStage]) { self.destination = destination; self.stages = stages }
}

public struct ResultFinding: Codable, Identifiable, Equatable {
    public var id: String
    public var severity: String // likely_cause | warning | info
    public var title: String
    public var observed: String
    public var interpretation: String
    public var confidence: String // high | medium | low
    public var evidence: EvidenceRef
    public var nextSteps: [String]
    public var category: String = "connectivity" // connectivity | performance | security
    public var matchedIndicators: [ThreatMatch] = []
    public init(id: String, severity: String, title: String, observed: String, interpretation: String, confidence: String, evidence: EvidenceRef, nextSteps: [String]) {
        self.id = id; self.severity = severity; self.title = title; self.observed = observed; self.interpretation = interpretation
        self.confidence = confidence; self.evidence = evidence; self.nextSteps = nextSteps
    }
}

public struct ResultSummary: Codable, Equatable {
    public var headline: String
    public var body: String
    public var nextStep: String
    public var citations: [Citation]
    public var fromTemplate: Bool
    public struct Citation: Codable, Equatable { public var text: String; public var anchor: String; public init(text: String, anchor: String) { self.text = text; self.anchor = anchor } }
    public init(headline: String, body: String, nextStep: String, citations: [Citation], fromTemplate: Bool = true) {
        self.headline = headline; self.body = body; self.nextStep = nextStep; self.citations = citations; self.fromTemplate = fromTemplate
    }
}


public struct FeedRef: Codable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var updatedAt: Double?
    public var stale: Bool
    public var indicatorCount: Int
    public init(id: String, name: String, updatedAt: Double?, stale: Bool, indicatorCount: Int) {
        self.id = id; self.name = name; self.updatedAt = updatedAt; self.stale = stale; self.indicatorCount = indicatorCount
    }
}

/// One matched destination: several IntelMatch records grouped for display.
public struct MatchedDestination: Equatable {
    public var key: String
    public var displayName: String
    public var ip: String?
    public var port: Int?
    public var severity: String
    public var matches: [ThreatMatch]
}

public struct ThreatIntelSummary: Codable, Equatable {
    public var status: String // checked | no_feeds | disabled
    public var feeds: [FeedRef]
    public var checkedIPs: Int
    public var checkedIPsTotal: Int = 0
    public var checkedDomains: Int
    public var checkedURLs: Int
    public var checkedCerts: Int
    public var checkedFingerprints: Int
    public var filesChecked: Bool
    public var matches: [ThreatMatch]
    public var ignoredByAllowlist: Int
    public var securityAlert: String // none | medium | high
    public var securityHeadline: String

    public static func groupByDestination(_ matches: [ThreatMatch]) -> [MatchedDestination] {
        var groups: [String: [ThreatMatch]] = [:]
        var order: [String] = []
        for m in matches {
            let key = m.destinationIP ?? m.dnsName ?? m.observed
            if groups[key] == nil { order.append(key) }
            groups[key, default: []].append(m)
        }
        let rank = ["high": 0, "medium": 1, "low": 2, "info": 3]
        return order.compactMap { key in
            guard let ms = groups[key] else { return nil }
            let sev = ms.map { $0.severity }.min { (rank[$0] ?? 4) < (rank[$1] ?? 4) } ?? "info"
            let first = ms[0]
            return MatchedDestination(key: key, displayName: first.destinationName ?? first.dnsName ?? first.observed, ip: first.destinationIP, port: first.destinationPort, severity: sev, matches: ms)
        }.sorted { (rank[$0.severity] ?? 4) < (rank[$1.severity] ?? 4) }
    }

    public static func make(outcome: ThreatIntelOutcome, feeds: [FeedRef], status: String) -> ThreatIntelSummary {
        let groups = groupByDestination(outcome.matches)
        let alert: String = groups.contains { $0.severity == "high" } ? "high" : (groups.contains { $0.severity == "medium" } ? "medium" : "none")
        var headline = ""
        if let top = groups.first, let first = top.matches.first {
            let threatText: String = {
                switch first.indicator.threat {
                case "botnet_c2": return "a botnet server"
                case "malware_download": return "a malware download"
                case "phishing": return "a phishing site"
                case "hijacked_netblock": return "part of a hijacked network block"
                default: return "a flagged address"
                }
            }()
            let feedName = first.feedName.isEmpty ? first.indicator.feedId : first.feedName
            headline = first.connected
                ? "This device connected to an address \(feedName) lists as \(threatText)"
                : "This device tried to contact an address \(feedName) lists as \(threatText)"
            if groups.count > 1 { headline += " (and \(groups.count - 1) more)" }
        }
        var summary = ThreatIntelSummary(status: status, feeds: feeds, checkedIPs: outcome.checkedIPs, checkedDomains: outcome.checkedDomains,
                                  checkedURLs: outcome.checkedURLs, checkedCerts: outcome.checkedCerts, checkedFingerprints: outcome.checkedFingerprints,
                                  filesChecked: outcome.filesChecked, matches: outcome.matches, ignoredByAllowlist: outcome.ignoredByAllowlist,
                                  securityAlert: alert, securityHeadline: headline)
        summary.checkedIPsTotal = outcome.checkedIPsTotal
        return summary
    }
}

public struct CaptureResults: Codable, Equatable {
    public var goalId: String
    public var goalLabel: String
    public var startedAt: Double?
    public var durationSec: Double
    public var packets: Int
    public var bytes: Int
    public var interfaceName: String
    public var interfaceKind: String
    public var kernelDrops: Int
    public var markedMomentsSec: [Double]
    public var checkedPackets: Int
    public var skipped: [(reason: String, packets: Int)]
    public var tooShort: Bool
    public var mix: [ProtocolCount]
    public var mixChecked: [String: Bool]
    public var paths: [ConnectionPathResult]
    public var dnsResolvers: [String]
    public var dnsQueries: Int
    public var dnsAnswered: Int
    public var dnsUnanswered: Int
    public var dnsErrors: [String]
    public var dnsAvgMs: Double?
    public var dnsP95Ms: Double?
    public var dnsMaxMs: Double?
    public var dnsLookups: [DNSLookup]
    public var dnsEvidenceCount: Int
    public var destinations: [DestinationRecord]
    public var checks: [CheckRecord]
    public var findings: [ResultFinding]
    public var timelineBinSec: Double
    public var timelineBuckets: [TrafficBucket]
    public var timelineEvents: [(atSec: Double, endSec: Double?, kind: String, label: String)]
    public var verdict: String // cause_found | possible_issue | inconclusive | no_problem_seen | not_enough_traffic
    public var templateSummary: ResultSummary
    public var threatIntel: ThreatIntelSummary?
    public var securityAlert: String { threatIntel?.securityAlert ?? "none" }

    public static func == (a: CaptureResults, b: CaptureResults) -> Bool { a.packets == b.packets && a.verdict == b.verdict && a.durationSec == b.durationSec && a.findings.count == b.findings.count }
    public var checkedPercent: Double { packets > 0 ? 100.0 * Double(checkedPackets) / Double(packets) : 0 }

    private enum CodingKeys: String, CodingKey {
        case goalId, goalLabel, startedAt, durationSec, packets, bytes, interfaceName, interfaceKind, kernelDrops, markedMomentsSec, checkedPackets, tooShort, mix, paths, dnsResolvers, dnsQueries, dnsAnswered, dnsUnanswered, dnsErrors, dnsAvgMs, dnsP95Ms, dnsMaxMs, dnsLookups, dnsEvidenceCount, destinations, checks, findings, timelineBinSec, timelineBuckets, verdict, templateSummary, threatIntel
    }
    // skipped/timelineEvents/mixChecked are derived presentation data; they are
    // encoded alongside for the (optional) summarizer input.
    public init(from decoder: Decoder) throws { fatalError("CaptureResults is built in code, not decoded") }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(goalId, forKey: .goalId); try c.encode(goalLabel, forKey: .goalLabel)
        try c.encodeIfPresent(startedAt, forKey: .startedAt)
        try c.encode(durationSec, forKey: .durationSec); try c.encode(packets, forKey: .packets); try c.encode(bytes, forKey: .bytes)
        try c.encode(interfaceName, forKey: .interfaceName); try c.encode(interfaceKind, forKey: .interfaceKind)
        try c.encode(kernelDrops, forKey: .kernelDrops); try c.encode(markedMomentsSec, forKey: .markedMomentsSec)
        try c.encode(checkedPackets, forKey: .checkedPackets); try c.encode(tooShort, forKey: .tooShort)
        try c.encode(mix, forKey: .mix); try c.encode(paths, forKey: .paths)
        try c.encode(dnsResolvers, forKey: .dnsResolvers); try c.encode(dnsQueries, forKey: .dnsQueries)
        try c.encode(dnsAnswered, forKey: .dnsAnswered); try c.encode(dnsUnanswered, forKey: .dnsUnanswered)
        try c.encode(dnsErrors, forKey: .dnsErrors)
        try c.encodeIfPresent(dnsAvgMs, forKey: .dnsAvgMs); try c.encodeIfPresent(dnsP95Ms, forKey: .dnsP95Ms); try c.encodeIfPresent(dnsMaxMs, forKey: .dnsMaxMs)
        try c.encode(dnsLookups, forKey: .dnsLookups); try c.encode(dnsEvidenceCount, forKey: .dnsEvidenceCount)
        try c.encode(destinations, forKey: .destinations); try c.encode(checks, forKey: .checks); try c.encode(findings, forKey: .findings)
        try c.encode(timelineBinSec, forKey: .timelineBinSec); try c.encode(timelineBuckets, forKey: .timelineBuckets)
        try c.encode(verdict, forKey: .verdict)
        var summaryCopy = templateSummary; summaryCopy = ResultSummary(headline: summaryCopy.headline, body: summaryCopy.body, nextStep: summaryCopy.nextStep, citations: summaryCopy.citations, fromTemplate: summaryCopy.fromTemplate)
        try c.encode(summaryCopy, forKey: .templateSummary)
        try c.encodeIfPresent(threatIntel, forKey: .threatIntel)
    }
    public init(goalId: String, goalLabel: String, startedAt: Double?, durationSec: Double, packets: Int, bytes: Int, interfaceName: String, interfaceKind: String, kernelDrops: Int, markedMomentsSec: [Double], checkedPackets: Int, skipped: [(reason: String, packets: Int)], tooShort: Bool, mix: [ProtocolCount], mixChecked: [String: Bool], paths: [ConnectionPathResult], dnsResolvers: [String], dnsQueries: Int, dnsAnswered: Int, dnsUnanswered: Int, dnsErrors: [String], dnsAvgMs: Double?, dnsP95Ms: Double?, dnsMaxMs: Double?, dnsLookups: [DNSLookup], dnsEvidenceCount: Int, destinations: [DestinationRecord], checks: [CheckRecord], findings: [ResultFinding], timelineBinSec: Double, timelineBuckets: [TrafficBucket], timelineEvents: [(atSec: Double, endSec: Double?, kind: String, label: String)], verdict: String, templateSummary: ResultSummary) {
        self.goalId = goalId; self.goalLabel = goalLabel; self.startedAt = startedAt; self.durationSec = durationSec
        self.packets = packets; self.bytes = bytes; self.interfaceName = interfaceName; self.interfaceKind = interfaceKind
        self.kernelDrops = kernelDrops; self.markedMomentsSec = markedMomentsSec; self.checkedPackets = checkedPackets
        self.skipped = skipped; self.tooShort = tooShort; self.mix = mix; self.mixChecked = mixChecked; self.paths = paths
        self.dnsResolvers = dnsResolvers; self.dnsQueries = dnsQueries; self.dnsAnswered = dnsAnswered; self.dnsUnanswered = dnsUnanswered
        self.dnsErrors = dnsErrors; self.dnsAvgMs = dnsAvgMs; self.dnsP95Ms = dnsP95Ms; self.dnsMaxMs = dnsMaxMs
        self.dnsLookups = dnsLookups; self.dnsEvidenceCount = dnsEvidenceCount; self.destinations = destinations
        self.checks = checks; self.findings = findings; self.timelineBinSec = timelineBinSec; self.timelineBuckets = timelineBuckets
        self.timelineEvents = timelineEvents; self.verdict = verdict; self.templateSummary = templateSummary
        self.threatIntel = nil
    }
}

// MARK: - Builder (verdict decided here, in code, in spec order)

public enum CaptureResultsBuilder {
    public static let tooShortThresholdSec: Double = 15

    public static func interfaceKind(_ name: String) -> String {
        let n = name.lowercased()
        if n.hasPrefix("en") { return "Wi-Fi" }
        if n.hasPrefix("utun") || n.hasPrefix("ipsec") { return "VPN" }
        if n.hasPrefix("lo") { return "this Mac only" }
        return "this Mac only"
    }

    public static func build(report: CaptureReport, context: SessionContext, kernelDrops: Int, threatIntel: ThreatIntelSummary? = nil) -> CaptureResults {
        let facts = report.facts
        let duration = report.duration
        let total = report.packetCount
        let quic = facts?.quicPackets ?? (report.protocols.first(where: { $0.name == "QUIC" })?.count ?? 0)
        let encOther = facts?.encryptedOtherPackets ?? 0
        let unsupported = max(0, total - (facts?.checkedPackets ?? total) - quic - encOther)
        let checked = facts?.checkedPackets ?? max(0, total - quic)
        var skipped: [(reason: String, packets: Int)] = []
        if quic > 0 { skipped.append(("encrypted_quic", quic)) }
        if encOther > 0 { skipped.append(("encrypted_other", encOther)) }
        if unsupported > 0 { skipped.append(("unsupported", unsupported)) }

        // Mix (must add up to the packet total).
        var mix: [ProtocolCount] = []
        var mixChecked: [String: Bool] = [:]
        if let tm = facts?.trafficMix, !tm.isEmpty {
            mix = tm
            var accounted = tm.reduce(0) { $0 + $1.count }
            if accounted < total { mix.append(ProtocolCount(name: "OTHER", count: total - accounted, bytes: 0)); accounted = total }
            if accounted > total, let idx = mix.indices.last { /* keep as parsed; totals still shown from capture */ }
        } else {
            mix = report.protocols.map { ProtocolCount(name: mixName($0.name), count: $0.count, bytes: $0.bytes) }
            let accounted = mix.reduce(0) { $0 + $1.count }
            if accounted < total { mix.append(ProtocolCount(name: "OTHER", count: total - accounted, bytes: 0)) }
        }
        for m in mix { mixChecked[m.name] = (m.name != "QUIC") }

        let destinations = facts?.destinations ?? report.endpoints.prefix(20).map {
            DestinationRecord(name: nil, address: $0.address, port: 0, protocolLabel: "Unknown", outcome: "not_checked", packets: $0.packets, bytes: $0.bytes, evidenceFilter: "ip.addr==\($0.address)", evidenceCount: $0.packets)
        }
        let paths = buildPaths(report: report, facts: facts, destinations: destinations)
        let findings = buildFindings(report: report, facts: facts)

        let hasFailedConnection = findings.contains { $0.severity == "likely_cause" } || destinations.contains { $0.outcome == "no_reply" || $0.outcome == "refused" }
        let tooShort = context.goal == .website && !hasFailedConnection && context.markers.isEmpty && duration < tooShortThresholdSec && total >= 10

        // Verdict, in spec order.
        let verdict: String
        if total < 10 { verdict = "not_enough_traffic" }
        else if findings.contains(where: { $0.severity == "likely_cause" }) { verdict = "cause_found" }
        else if findings.contains(where: { $0.severity == "warning" }) { verdict = "possible_issue" }
        else if tooShort || context.markers.isEmpty || (total > 0 && Double(checked) / Double(total) < 0.7) { verdict = "inconclusive" }
        else { verdict = "no_problem_seen" }

        // Checks, with the real kernel-drop count substituted.
        var checks = facts?.checks ?? defaultChecks(report: report, facts: facts)
        if let idx = checks.firstIndex(where: { $0.id == "kernel-drops" }) {
            checks[idx].count = kernelDrops
            checks[idx].flagged = kernelDrops > 0
            checks[idx].note = kernelDrops > 0 ? "Some packets were lost" : "Nothing lost"
        }
        checks.sort { a, b in a.flagged != b.flagged ? a.flagged && !b.flagged : false }

        // Timeline events.
        var events: [(atSec: Double, endSec: Double?, kind: String, label: String)] = []
        if let first = facts?.firstTimestamp {
            for m in context.markers { events.append((m.timestamp - first, nil, "marked", "You marked the moment")) }
            if let dnsFirst = report.packets.first(where: { $0.protocolName == "DNS" }) { events.append((dnsFirst.timestamp - first, nil, "milestone", "First name lookups")) }
            if let tcpFirst = report.packets.first(where: { $0.protocolName == "TCP" }) { events.append((tcpFirst.timestamp - first, nil, "milestone", "First connection")) }
            for f in findings {
                if let firstFrame = f.evidence.frames.first, let pkt = report.packets.first(where: { $0.id == firstFrame }) {
                    let lastFrame = f.evidence.frames.last ?? firstFrame
                    let endPkt = report.packets.first(where: { $0.id == lastFrame })
                    events.append((pkt.timestamp - first, endPkt.map { $0.timestamp - first }, "finding", f.title))
                }
            }
        }
        let buckets = facts?.timeline ?? []
        let binSec: Double = {
            guard buckets.count >= 2 else { return 1 }
            return Double(buckets[1].second - buckets[0].second)
        }()

        var results = CaptureResults(
            goalId: context.goal.rawValue, goalLabel: context.goal.title,
            startedAt: context.startedAt, durationSec: duration, packets: total, bytes: report.capturedBytes,
            interfaceName: context.interface, interfaceKind: interfaceKind(context.interface), kernelDrops: kernelDrops,
            markedMomentsSec: (facts?.firstTimestamp).map { first in context.markers.map { $0.timestamp - first } } ?? [],
            checkedPackets: checked, skipped: skipped, tooShort: tooShort,
            mix: mix, mixChecked: mixChecked, paths: paths,
            dnsResolvers: facts?.dnsResolvers ?? [], dnsQueries: facts?.dnsQueries ?? (facts?.matchedDNSPairs ?? 0),
            dnsAnswered: facts?.dnsAnswered ?? (facts?.matchedDNSPairs ?? 0), dnsUnanswered: facts?.dnsUnanswered ?? 0,
            dnsErrors: (facts?.dnsErrors ?? 0) > 0 ? ["\(facts?.dnsErrors ?? 0) error replies"] : [],
            dnsAvgMs: facts?.averageDNSMilliseconds, dnsP95Ms: facts?.dnsP95Milliseconds, dnsMaxMs: facts?.dnsMaxMilliseconds,
            dnsLookups: facts?.dnsLookups ?? [], dnsEvidenceCount: (facts?.dnsResponses ?? 0) + (facts?.dnsQueries ?? 0),
            destinations: destinations, checks: checks, findings: findings,
            timelineBinSec: binSec, timelineBuckets: buckets, timelineEvents: events,
            verdict: verdict, templateSummary: ResultSummary(headline: "", body: "", nextStep: "", citations: []))
        results.templateSummary = templateSummary(results: results, context: context)
        if let ti = threatIntel {
            results.threatIntel = ti
            attachThreatIntel(&results, intel: ti, report: report)
        }
        return results
    }

    // Groups matches into one security finding per destination and marks the
    // destination rows. The goal verdict and template summary are already
    // computed at this point and are deliberately left untouched.
    static func attachThreatIntel(_ results: inout CaptureResults, intel: ThreatIntelSummary, report: CaptureReport) {
        let groups = ThreatIntelSummary.groupByDestination(intel.matches)
        // Destination pills + failed-first ordering for matched destinations.
        var enriched = results.destinations
        for i in enriched.indices {
            let mine = intel.matches.filter { $0.destinationIP == enriched[i].address }
            if !mine.isEmpty {
                enriched[i].intelMatchIds = mine.map { $0.id }
                let rank = ["high": 0, "medium": 1, "low": 2, "info": 3]
                enriched[i].intelTopSeverity = mine.map { $0.severity }.min { (rank[$0] ?? 4) < (rank[$1] ?? 4) }
            }
        }
        let sevRank = ["high": 0, "medium": 1, "low": 2, "info": 3]
        enriched = enriched.enumerated().sorted { a, b in
            let ra = a.element.intelTopSeverity.map { sevRank[$0] ?? 9 } ?? 9
            let rb = b.element.intelTopSeverity.map { sevRank[$0] ?? 9 } ?? 9
            return ra != rb ? ra < rb : a.offset < b.offset
        }.map { $0.element }
        results.destinations = enriched

        var securityFindings: [ResultFinding] = []
        for group in groups {
            let first = group.matches[0]
            let dest = results.destinations.first { $0.address == group.ip }
            let feedNames = Array(Set(group.matches.map { $0.feedName.isEmpty ? $0.indicator.feedId : $0.feedName })).sorted().joined(separator: ", ")
            let observed: String = {
                if let d = dest {
                    let verb = first.connected ? "Connected to" : "Tried to contact"
                    return "\(verb) \(d.address):\(d.port) — \(d.packets) packets, \(d.attempts) connection attempt(s). Matched \(group.matches.count) indicator(s)."
                }
                return "Matched \(group.matches.count) indicator(s) for \(group.displayName) (\(first.direction == "dns_only" ? "name lookup only; no connection followed" : "observed in this capture"))."
            }()
            let interpretation: String = {
                switch first.indicator.threat {
                case "botnet_c2": return "This address or name is listed as a botnet command-and-control server. Malware on a device uses such servers to receive instructions and send stolen data."
                case "malware_download": return "This address, name, or file is listed as distributing malware."
                case "phishing": return "This name or address is listed as a phishing site."
                case "hijacked_netblock": return "This address sits inside a network block listed as run or hijacked by criminal operations. Ordinary services can occasionally share such ranges, so treat it as a prompt to check, not proof."
                default: return "A threat feed lists this destination. A listing is evidence to investigate, not proof that this device is infected."
                }
            }()
            let sevMap = ["high": "likely_cause", "medium": "warning", "low": "info", "info": "info"]
            var f = ResultFinding(id: "security-\(group.key)", severity: sevMap[group.severity] ?? "info",
                                  title: "\(group.displayName) is listed by \(feedNames)",
                                  observed: observed, interpretation: interpretation,
                                  confidence: group.severity == "high" ? "high" : (group.severity == "medium" ? "medium" : "low"),
                                  evidence: EvidenceRef(filter: dest?.evidenceFilter ?? first.filter, frames: Array(Set(group.matches.flatMap { $0.frames })).sorted(), count: dest?.evidenceCount ?? group.matches.reduce(0) { $0 + $1.evidenceCount }),
                                  nextSteps: ["Run a malware scan on this device.", "If this is a work device, tell your IT or security team and share this report with them.", "Note what app was running at the marked time, then capture again after scanning."])
            f.category = "security"
            f.matchedIndicators = group.matches
            securityFindings.append(f)
        }
        // Security findings lead the findings list; connectivity findings follow.
        results.findings = securityFindings + results.findings
    }

    static func mixName(_ n: String) -> String {
        switch n { case "TCP", "HTTP": return "TCP"; case "DNS": return "DNS"; case "QUIC": return "QUIC"; case "UDP", "mDNS": return n == "DNS" ? "DNS" : "UDP_OTHER"; case "ICMP", "ICMPv6": return "ICMP"; default: return "OTHER" }
    }

    static func defaultChecks(report: CaptureReport, facts: CaptureFacts?) -> [CheckRecord] {
        [
            CheckRecord(id: "dns-errors", label: "DNS errors (NXDOMAIN, SERVFAIL)", count: facts?.dnsErrors ?? 0, flagged: (facts?.dnsErrors ?? 0) > 0, note: (facts?.dnsErrors ?? 0) > 0 ? "See findings" : "None", filter: "dns.flags.response == 1 && dns.flags.rcode != 0"),
            CheckRecord(id: "dns-unanswered", label: "DNS lookups with no answer", count: facts?.dnsUnanswered ?? 0, flagged: (facts?.dnsUnanswered ?? 0) > 0, note: "None", filter: "dns.flags.response == 0"),
            CheckRecord(id: "tcp-refused", label: "Refused connections (TCP reset)", count: facts?.tcpResets ?? 0, flagged: (facts?.tcpResets ?? 0) > 0, note: (facts?.tcpResets ?? 0) > 0 ? "See findings" : "None", filter: "tcp.flags.reset == 1"),
            CheckRecord(id: "tcp-unanswered", label: "Unanswered connection attempts", count: 0, flagged: false, note: "None", filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0"),
            CheckRecord(id: "icmp-unreachable", label: "ICMP unreachable messages", count: facts?.icmpUnreachable ?? 0, flagged: (facts?.icmpUnreachable ?? 0) > 0, note: "None", filter: "icmp.type == 3 || icmpv6.type == 1"),
            CheckRecord(id: "tls-alerts", label: "TLS alerts or failed handshakes", count: facts?.tlsAlerts ?? 0, flagged: (facts?.tlsAlerts ?? 0) > 0, note: "None", filter: "tls.record.content_type == 21"),
            CheckRecord(id: "tcp-retransmissions", label: "TCP retransmissions", count: facts?.tcpRetransmissions ?? 0, flagged: (facts?.tcpRetransmissions ?? 0) > 20, note: (facts?.tcpRetransmissions ?? 0) == 0 ? "None" : "Normal level", filter: "tcp.analysis.retransmission"),
            CheckRecord(id: "kernel-drops", label: "Packets dropped by capture", count: 0, flagged: false, note: "Nothing lost", filter: ""),
        ]
    }

    // MARK: Paths

    static func buildPaths(report: CaptureReport, facts: CaptureFacts?, destinations: [DestinationRecord]) -> [ConnectionPathResult] {
        var paths = destinations.prefix(12).map { dest in
            ConnectionPathResult(destination: dest.name ?? dest.address, stages: genericStages(report: report, facts: facts, destination: dest))
        }
        // A name that does not exist has no connection destination, but the
        // failed lookup still needs a path whose step 2 fails, stating the name.
        if let nx = facts?.dnsLookups.first(where: { $0.rcode == "NXDOMAIN" }) {
            let fake = DestinationRecord(name: nx.name, address: "—", port: 0, protocolLabel: "DNS", outcome: "not_checked")
            paths.insert(ConnectionPathResult(destination: nx.name, stages: genericStages(report: report, facts: facts, destination: fake)), at: 0)
        }
        if paths.isEmpty {
            return [ConnectionPathResult(destination: "This device", stages: genericStages(report: report, facts: facts, destination: nil))]
        }
        return paths
    }

    static func genericStages(report: CaptureReport, facts: CaptureFacts?, destination: DestinationRecord?) -> [PathStage] {
        var stages: [PathStage] = []
        // Local
        if let gw = facts?.arpResponder {
            stages.append(PathStage(id: "local", status: "passed", result: "Router answered", detail: "ARP reply from \(gw)"))
        } else if report.packetCount > 0 && (facts?.loopbackPackets ?? 0) < report.packetCount {
            stages.append(PathStage(id: "local", status: "passed", result: "Traffic left this Mac", detail: "Packets were exchanged beyond loopback"))
        } else if report.packetCount > 0 {
            stages.append(PathStage(id: "local", status: "passed", result: "Local traffic seen", detail: "All observed traffic stayed on this Mac"))
        } else {
            stages.append(PathStage(id: "local", status: "not_visible", result: "Not visible", detail: "No packets were captured"))
        }
        // DNS
        var dnsFailed = false
        if let dest = destination, let name = dest.name {
            let lookups = facts?.dnsLookups.filter { $0.name == name } ?? []
            if let err = lookups.first(where: { $0.rcode == "NXDOMAIN" || $0.rcode == "SERVFAIL" || $0.rcode == "REFUSED" }) {
                stages.append(PathStage(id: "dns", status: "failed", result: "\(name) was reported as not existing (\(err.rcode))", detail: "The name lookup failed, so no connection could start"))
                dnsFailed = true
            } else if let ok = lookups.first(where: { $0.milliseconds != nil }) {
                stages.append(PathStage(id: "dns", status: "passed", result: "Resolved to \(dest.address)", detail: "Answered in \(ResultFormat.ms(ok.milliseconds ?? 0))"))
            } else if facts?.domains.contains(where: { $0.name == name && $0.addresses.contains(dest.address) }) ?? false {
                stages.append(PathStage(id: "dns", status: "passed", result: "Resolved to \(dest.address)", detail: "The answer was seen in this capture"))
            } else {
                stages.append(PathStage(id: "dns", status: "not_visible", result: "No lookup seen", detail: "The address may already have been cached"))
            }
        } else if let f = facts, f.dnsQueries > 0 {
            if f.dnsErrors > 0 && f.dnsAnswered == 0 {
                stages.append(PathStage(id: "dns", status: "failed", result: "Name lookups failed", detail: "\(f.dnsErrors) error replies were seen"))
                dnsFailed = true
            } else {
                stages.append(PathStage(id: "dns", status: "passed", result: "\(f.dnsAnswered) of \(f.dnsQueries) answered", detail: f.averageDNSMilliseconds.map { "Average \(ResultFormat.ms($0))" } ?? ""))
            }
        } else {
            stages.append(PathStage(id: "dns", status: "not_visible", result: "No lookup seen", detail: "Names may already have been cached, or encrypted DNS was used"))
        }
        // TCP
        var tcpFailed = false
        if let dest = destination {
            switch dest.outcome {
            case "connected":
                stages.append(PathStage(id: "tcp", status: "passed", result: "Connected", detail: "\(dest.packets) packets exchanged with \(dest.address):\(dest.port)"))
            case "refused":
                stages.append(PathStage(id: "tcp", status: "failed", result: "Refused", detail: "The destination answered with a reset on port \(dest.port)"))
                tcpFailed = true
            case "no_reply":
                stages.append(PathStage(id: "tcp", status: "failed", result: "0 of \(dest.attempts) answered", detail: "No reply on port \(dest.port)"))
                tcpFailed = true
            case "reset_later":
                stages.append(PathStage(id: "tcp", status: "warning", result: "Connected, then reset", detail: "The connection started, then was cut short"))
            default:
                stages.append(PathStage(id: "tcp", status: "not_visible", result: "Not checked", detail: "This destination's traffic could not be checked (for example, encrypted QUIC)"))
            }
        } else if let f = facts, f.tcpPackets > 0 {
            stages.append(PathStage(id: "tcp", status: f.tcpResets > 0 ? "warning" : "passed", result: "\(f.tcpPackets) TCP packets checked", detail: f.tcpResets > 0 ? "\(f.tcpResets) carried a reset" : "No resets seen"))
        } else {
            stages.append(PathStage(id: "tcp", status: "not_visible", result: "Not visible", detail: "No TCP traffic was captured"))
        }
        let failedSoFar = dnsFailed || tcpFailed
        // TLS
        if failedSoFar {
            stages.append(PathStage(id: "tls", status: "not_reached", result: "Not reached", detail: "Needs the earlier step to succeed first"))
        } else if let dest = destination {
            switch dest.tlsStatus {
            case "passed": stages.append(PathStage(id: "tls", status: "passed", result: "Secure setup completed", detail: "The encrypted session was established"))
            case "failed": stages.append(PathStage(id: "tls", status: "failed", result: "Secure setup failed", detail: "A TLS alert was seen before the setup completed"))
            default:
                if dest.protocolLabel.contains("QUIC") { stages.append(PathStage(id: "tls", status: "not_visible", result: "Inside QUIC", detail: "QUIC encrypts its setup; it can't be checked separately")) }
                else if dest.protocolLabel.contains("TLS") { stages.append(PathStage(id: "tls", status: "not_visible", result: "Not seen completed", detail: "The setup may have finished outside the capture window")) }
                else { stages.append(PathStage(id: "tls", status: "not_visible", result: "Not encrypted or not seen", detail: "No TLS setup was observed for this destination")) }
            }
        } else {
            stages.append(PathStage(id: "tls", status: "not_visible", result: "Not visible", detail: "Encrypted setup can't be verified beyond the handshake"))
        }
        // App
        if failedSoFar || stages.last(where: { $0.id == "tls" })?.status == "failed" {
            stages.append(PathStage(id: "app", status: "not_reached", result: "Not reached", detail: "Needs a connection first"))
        } else if let dest = destination, dest.protocolLabel.contains("HTTP") && !dest.protocolLabel.contains("TLS") {
            stages.append(PathStage(id: "app", status: "passed", result: "Visible (not encrypted)", detail: "The app response was readable plaintext"))
        } else {
            stages.append(PathStage(id: "app", status: "not_visible", result: "Encrypted", detail: "Contents can't be read without keys"))
        }
        // Enforce: everything after the first failure is not_reached.
        var seenFailure = false
        for i in stages.indices {
            if seenFailure && stages[i].status != "not_reached" {
                stages[i] = PathStage(id: stages[i].id, status: "not_reached", result: "Not reached", detail: "Needs the earlier step to succeed first")
            }
            if stages[i].status == "failed" { seenFailure = true }
        }
        return stages
    }

    // MARK: Findings

    static func buildFindings(report: CaptureReport, facts: CaptureFacts?) -> [ResultFinding] {
        var out: [ResultFinding] = []
        for f in report.findings {
            let sev: String
            switch f.severity { case "likely_cause": sev = "likely_cause"; case "warning", "notice": sev = "warning"; default: sev = "info" }
            let interpretation: String
            let steps: [String]
            switch f.id {
            case "unanswered-connection":
                interpretation = "A silent drop. A refused connection would have returned a reset; a missing route would usually return an ICMP error. Silence typically comes from a firewall rule, a VPN or filter, or a server that is offline."
                steps = ["Open the same website or app on a different network, such as a phone hotspot.", "If it works there, a firewall, VPN or content filter on this network is likely blocking it. Share this report with whoever runs the network.", "If it fails everywhere, the service may be down. Check its status page or contact its support."]
            case "refused-connection":
                interpretation = "The destination was reachable but actively refused the connection. The service may not be running, or a firewall on that device is rejecting it."
                steps = ["Check whether the service is running on that device.", "Check for a firewall on that device rejecting this port, then try again."]
            case "dns-name-not-found":
                interpretation = "The name does not exist according to the DNS server, so the app never got an address to connect to."
                steps = ["Check the spelling of the name.", "Check whether the service changed or removed the name, then try the correct name."]
            case "dns-errors":
                interpretation = "Name lookups are failing, which can make apps look like they have no connection even when the link is up."
                steps = [f.recommendation]
            case "slow-dns":
                interpretation = "Slow name lookups delay every new connection before any data moves."
                steps = [f.recommendation]
            case "plaintext-remote":
                interpretation = "Readable application data left this Mac without encryption. Devices on the network path could potentially see it."
                steps = [f.recommendation]
            case "plaintext-local":
                interpretation = "Readable traffic between addresses on this Mac. It stays on the device and is listed for awareness."
                steps = [f.recommendation]
            default:
                interpretation = f.evidence
                steps = [f.recommendation]
            }
            var evidence = EvidenceRef(filter: filter(for: f.id, report: report), frames: f.packetNumbers, count: f.packetNumbers.count)
            if f.id == "unanswered-connection", let dest = report.facts?.destinations.first(where: { $0.outcome == "no_reply" }) {
                let frames = Array(dest.packetNumbers.prefix(200))
                evidence = EvidenceRef(filter: frames.isEmpty ? "" : "frame.number in {" + frames.map(String.init).joined(separator: ", ") + "}", frames: frames, count: dest.attempts)
            }
            if f.id == "refused-connection", let dest = report.facts?.destinations.first(where: { $0.outcome == "refused" }) {
                evidence = EvidenceRef(filter: "ip.addr==\(dest.address) && tcp.port==\(dest.port) && tcp.flags.reset==1", frames: f.packetNumbers, count: f.packetNumbers.count)
            }
            _ = evidence
            out.append(ResultFinding(id: f.id, severity: sev, title: f.title, observed: f.evidence, interpretation: interpretation,
                                     confidence: sev == "likely_cause" ? "high" : (sev == "warning" ? "medium" : "low"),
                                     evidence: evidence,
                                     nextSteps: steps))
        }
        let rank = ["likely_cause": 0, "warning": 1, "info": 2]
        out.sort { (rank[$0.severity] ?? 3) < (rank[$1.severity] ?? 3) }
        return out
    }

    static func filter(for findingId: String, report: CaptureReport) -> String {
        switch findingId {
        case "dns-errors", "dns-name-not-found": return "dns.flags.response == 1 && dns.flags.rcode != 0"
        case "tcp-resets", "refused-connection": return "tcp.flags.reset == 1"
        case "unanswered-connection": return "tcp.flags.syn == 1 && tcp.flags.ack == 0"
        case "tls-alerts": return "tls.record.content_type == 21"
        case "plaintext-remote", "plaintext-local": return "http || ftp || smtp"
        default: return ""
        }
    }

    // MARK: Template summary (always available; AI may only reword it)

    public static func templateSummary(results r: CaptureResults, context: SessionContext) -> ResultSummary {
        let top = r.findings.first
        switch r.verdict {
        case "not_enough_traffic":
            return ResultSummary(headline: "Not enough traffic was captured", body: "Only \(ResultFormat.count(r.packets)) packets were recorded, which is too little to answer your question. The selected interface may not be the one carrying the traffic.", nextStep: "Check the selected interface, then capture again while you reproduce the problem.", citations: [])
        case "cause_found":
            let f = top!
            let name = r.destinations.first(where: { $0.outcome == "no_reply" || $0.outcome == "refused" }).map { $0.name ?? $0.address } ?? "The destination"
            let headline = headlineFor(f: f, destinationName: name)
            var body = "\(f.observed)"
            if body.count > 300 { body = String(body.prefix(300)) }
            return ResultSummary(headline: headline, body: body, nextStep: f.nextSteps.first ?? "Share this report with support.",
                                 citations: [ResultSummary.Citation(text: f.title, anchor: "#evidence")])
        case "possible_issue":
            let f = top!
            return ResultSummary(headline: headlineFor(f: f, destinationName: r.destinations.first?.name ?? "This capture"), body: "\(f.observed) \(f.interpretation)", nextStep: f.nextSteps.first ?? "Capture again and compare.", citations: [ResultSummary.Citation(text: f.title, anchor: "#evidence")])
        case "inconclusive":
            let dnsText = r.dnsQueries > 0 ? "\(r.dnsAnswered) of \(r.dnsQueries) name lookups were answered" : "No name lookups were seen"
            let connText: String = {
                let connected = r.destinations.filter { $0.outcome == "connected" }.count
                return connected > 0 ? " and the connections your device started succeeded" : ""
            }()
            let skippedText: String = {
                guard let s = r.skipped.first else { return "" }
                return ", and \(ResultFormat.count(s.packets)) of \(ResultFormat.count(r.packets)) packets were QUIC traffic whose contents can't be read (server names were read where visible)"
            }()
            let shortText = r.tooShort ? " But the capture ran for only \(ResultFormat.duration(r.durationSec))" : ""
            let body = "All measured checks passed: \(dnsText)\(connText). Nothing was refused, reset or left unanswered.\(shortText)\(skippedText), so the failing attempt was most likely not recorded."
            return ResultSummary(headline: "No connection failure was seen, but this capture probably missed it", body: body,
                                 nextStep: "Capture for 60 seconds while you reproduce the problem. Start the capture, open the website or app that won't connect, and press Mark the moment when it fails.",
                                 citations: [ResultSummary.Citation(text: dnsText, anchor: "#dns")])
        default: // no_problem_seen
            let dest = r.destinations.first(where: { $0.outcome == "connected" })
            let headline = dest.map { "All connections to \($0.name ?? $0.address) succeeded in this capture" } ?? "No problem was seen in this capture"
            let body = "\(r.dnsAnswered) of \(r.dnsQueries) name lookups were answered, and the connections your device started completed. This covers only what could be seen during these \(ResultFormat.duration(r.durationSec))."
            return ResultSummary(headline: String(headline.prefix(90)), body: body, nextStep: "If the problem comes back, capture again and mark the moment it happens.", citations: [])
        }
    }

    static func headlineFor(f: ResultFinding, destinationName: String) -> String {
        let h: String
        switch f.id {
        case "unanswered-connection": h = "\(destinationName) never answered your device's connection attempts"
        case "refused-connection": h = "\(destinationName) refused your device's connection"
        case "dns-name-not-found": h = "The name could not be found, so nothing could connect"
        case "dns-errors": h = "Name lookups failed during this capture"
        case "slow-dns": h = "Name lookups were slow during this capture"
        case "plaintext-remote": h = "Some traffic left this Mac without encryption"
        case "tls-alerts": h = "Secure connections were rejected during this capture"
        default: h = f.title
        }
        return String(h.prefix(90))
    }
}

import Foundation

// MARK: - Guided capture context

public enum CaptureGoal: String, Codable, CaseIterable, Identifiable {
    case website, slow, calls, background
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .website: return "A website or app won’t connect"
        case .slow: return "My connection feels slow"
        case .calls: return "A call or stream is interrupted"
        case .background: return "Understand background activity"
        }
    }
    public var guidance: String {
        switch self {
        case .website: return "Start the capture, retry the affected operation, and press “It happened just now” when the error appears."
        case .slow: return "Repeat the slow action during the capture. Captured volume shows what was observed here; it is not a measure of your connection’s capacity."
        case .calls: return "Mark each freeze or dropout. Encrypted call and stream media stays encrypted; this shows timing and volume, not call content."
        case .background: return "Let the capture run and observe which processes and destinations are active. Unknown ownership is not automatically suspicious."
        }
    }
    public var symbol: String {
        switch self { case .website: return "globe"; case .slow: return "gauge.with.dots.needle.33percent"; case .calls: return "phone.badge.waveform"; case .background: return "eye" }
    }
}

public struct ProblemMarker: Codable, Identifiable, Equatable {
    public var id: UUID
    public var timestamp: Double // absolute epoch seconds
    public var note: String
    public init(id: UUID = UUID(), timestamp: Double, note: String = "Problem noticed") { self.id = id; self.timestamp = timestamp; self.note = note }
}

public struct SessionContext: Codable, Equatable {
    public var goal: CaptureGoal
    public var symptom: String
    public var interface: String
    public var startedAt: Double?
    public var endedAt: Double?
    public var markers: [ProblemMarker]
    public var changeNote: String
    public var isImported: Bool
    public init(goal: CaptureGoal = .website, symptom: String = "", interface: String = "", startedAt: Double? = nil, endedAt: Double? = nil, markers: [ProblemMarker] = [], changeNote: String = "", isImported: Bool = false) {
        self.goal = goal; self.symptom = symptom; self.interface = interface; self.startedAt = startedAt
        self.endedAt = endedAt; self.markers = markers; self.changeNote = changeNote; self.isImported = isImported
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        goal = try c.decodeIfPresent(CaptureGoal.self, forKey: .goal) ?? .website
        symptom = try c.decodeIfPresent(String.self, forKey: .symptom) ?? ""
        interface = try c.decodeIfPresent(String.self, forKey: .interface) ?? ""
        startedAt = try c.decodeIfPresent(Double.self, forKey: .startedAt)
        endedAt = try c.decodeIfPresent(Double.self, forKey: .endedAt)
        markers = try c.decodeIfPresent([ProblemMarker].self, forKey: .markers) ?? []
        changeNote = try c.decodeIfPresent(String.self, forKey: .changeNote) ?? ""
        isImported = try c.decodeIfPresent(Bool.self, forKey: .isImported) ?? false
    }
    private enum CodingKeys: String, CodingKey { case goal, symptom, interface, startedAt, endedAt, markers, changeNote, isImported }
    public static var unknownImported: SessionContext { SessionContext(goal: .background, symptom: "", interface: "Imported capture", isImported: true) }
}

// MARK: - Explanations

public struct ExplanationCard: Identifiable, Equatable {
    public var id: String
    public var severity: String
    public var title: String
    public var observed: String
    public var whyItMatters: String
    public var checkNext: String
    public var cannotEstablish: String
    public var packetNumbers: [Int]
    /// Plain-language summary shown under "What's happening:" in the Results page.
    public var bullets: [String]
    public init(id: String, severity: String, title: String, observed: String, whyItMatters: String, checkNext: String, cannotEstablish: String, packetNumbers: [Int] = [], bullets: [String] = []) {
        self.id = id; self.severity = severity; self.title = title; self.observed = observed; self.whyItMatters = whyItMatters
        self.checkNext = checkNext; self.cannotEstablish = cannotEstablish; self.packetNumbers = packetNumbers
        self.bullets = bullets.isEmpty ? ExplanationBuilder.plainBullets(id: id, observed: observed, whyItMatters: whyItMatters, checkNext: checkNext, cannotEstablish: cannotEstablish) : bullets
    }
}

public enum ExplanationBuilder {
    public static func cards(report: CaptureReport, context: SessionContext) -> [ExplanationCard] {
        var out: [ExplanationCard] = []
        if report.packetCount == 0 {
            out.append(ExplanationCard(id: "empty", severity: "info", title: "No packets were captured",
                observed: "The capture file contains no packets on interface \(context.interface.isEmpty ? "the selected interface" : context.interface).",
                whyItMatters: "There is no traffic evidence to explain the symptom from this attempt.",
                checkNext: "Confirm the selected interface is the one carrying the traffic, then capture again while reproducing the symptom.",
                cannotEstablish: "An empty capture does not prove the network is healthy or faulty."))
            return out
        }
        for f in report.findings {
            let cannot: String
            switch f.id {
            case "dns-errors": cannot = "A DNS error reply alone cannot establish a bad ISP, malware, or why the app failed."
            case "tcp-resets": cannot = "A reset alone cannot establish who closed the connection or that an application-level failure occurred."
            case "plaintext-local": cannot = "This local finding does not mean every packet in the session stayed inside this Mac."
            case "plaintext-remote": cannot = "Visible plaintext does not by itself establish that data was intercepted or harmed."
            default: cannot = "This observation alone cannot establish a root cause."
            }
            out.append(ExplanationCard(id: f.id, severity: f.severity, title: f.title, observed: f.evidence, whyItMatters: why(f.id), checkNext: f.recommendation, cannotEstablish: cannot, packetNumbers: f.packetNumbers))
        }
        // Marker context from retained rows only (±3 s), clearly scoped.
        if let marker = context.markers.last, let facts = report.facts, let first = facts.firstTimestamp {
            let nearby = report.packets.filter { abs($0.timestamp - marker.timestamp) <= 3 }
            let offset = marker.timestamp - first
            let when = offset >= 0 ? String(format: "%.1f s after the first observed packet", offset) : String(format: "%.1f s before the first observed packet (quiet time is possible)", -offset)
            out.append(ExplanationCard(id: "marker", severity: "info", title: "Near your latest marked moment",
                observed: "Your latest marker was \(when). \(nearby.count) of the retained packet rows fall within ±3 seconds of it" + (nearby.isEmpty ? "." : ": " + nearby.prefix(5).map { "#\($0.id) \($0.protocolName)" }.joined(separator: ", ") + "."),
                whyItMatters: "Packets close in time to a symptom are a useful place to start looking.",
                checkNext: "Open the packet log for those rows and compare the app and destination with what you were doing.",
                cannotEstablish: "This window covers only the retained rows (first \(PacketAnalyzer.displayLimit)); the full-file timeline may show more. A marker records when you noticed a problem — it is not proof of a network fault.",
                packetNumbers: Array(nearby.prefix(6).map { $0.id })))
        }
        if report.findings.isEmpty {
            out.append(ExplanationCard(id: "no-findings", severity: "info", title: "No matching checks fired",
                observed: "Across \(report.packetCount) packets we saw \(report.facts?.dnsResponses ?? 0) visible DNS replies and \(report.facts?.tcpPackets ?? 0) decoded TCP packets, with no DNS error replies, TCP resets, or recognizable plaintext matching the built-in checks.",
                whyItMatters: "The symptom may involve encrypted traffic, an app-level issue, or something outside this capture window.",
                checkNext: "Capture again while reproducing the symptom, mark the moment it happens, and check the Apps and Timeline views.",
                cannotEstablish: "No matching findings does not prove the network is healthy."))
        }
        if let facts = report.facts, let avg = facts.averageDNSMilliseconds {
            out.append(ExplanationCard(id: "dns-timing", severity: "info", title: "DNS exchange time",
                observed: String(format: "Matched DNS exchanges averaged %.0f ms across %d complete query/reply pair(s).", avg, facts.matchedDNSPairs),
                whyItMatters: "Slow name lookups can delay apps before any data flows.",
                checkNext: "Compare this value before and after a change, using the same goal and interface.",
                cannotEstablish: "This is DNS exchange time, not page-load time or connection speed."))
        }
        return out
    }
    static func why(_ id: String) -> String {
        switch id {
        case "dns-errors": return "If names cannot be resolved, apps may appear unable to connect even when the link is up."
        case "tcp-resets": return "Resets can accompany refused connections or peers closing abruptly."
        case "plaintext-local": return "It identifies a local service exchanging readable data on this Mac."
        case "plaintext-remote": return "Readable application data could be visible to other devices on the path."
        default: return "It is measured evidence from this capture."
        }
    }

    /// Short, plain-language bullets for the Results page. These summarize the
    /// measured finding; they never upgrade an observation into a verdict.
    public static func plainBullets(id: String, observed: String, whyItMatters: String, checkNext: String, cannotEstablish: String) -> [String] {
        switch id {
        case "dns-errors":
            return [
                "Some name lookups failed. " + observed,
                "In plain terms: an app may look like it has “no connection” when it cannot turn a name into an address, even if the link itself is up.",
                "Try this: " + checkNext,
                "Keep in mind: this does not prove a bad ISP, malware, or why a particular app failed."
            ]
        case "tcp-resets":
            return [
                "Some connections were cut short. " + observed,
                "In plain terms: one side abruptly closed or refused a connection. This is sometimes normal, but repeated resets can line up with apps failing to connect.",
                "Try this: " + checkNext,
                "Keep in mind: a reset does not show who caused it, and it is not by itself a sign of an attack."
            ]
        case "plaintext-remote":
            return [
                "Some traffic left this Mac in readable form instead of encrypted form. " + observed,
                "In plain terms: devices on the network path could potentially see that content. Treat this as the main item to review in this capture.",
                "Try this: " + checkNext,
                "Keep in mind: this does not prove anyone actually intercepted or misused the data."
            ]
        case "plaintext-local":
            return [
                "Readable traffic was exchanged between addresses on this Mac. " + observed,
                "In plain terms: this is usually a local app talking to a local service. It did not, by itself, leave the Mac.",
                "Try this: " + checkNext,
                "Keep in mind: this only describes the local packets — it does not mean every packet in the capture stayed on this Mac."
            ]
        case "marker":
            return [
                observed,
                "In plain terms: packets around the time you noticed the problem are the best place to start looking.",
                "Try this: " + checkNext,
                "Keep in mind: a marker shows when you noticed a problem. It is not proof that the network caused it."
            ]
        case "no-findings":
            return [
                "Nothing matched the built-in checks. " + observed,
                "In plain terms: the issue may be inside an app, inside encrypted traffic, or outside the time and interface captured.",
                "Try this: " + checkNext,
                "Keep in mind: no flagged items does not prove the network is healthy or secure."
            ]
        case "dns-timing":
            return [
                observed,
                "In plain terms: this is how long name lookups took. Slow lookups can make apps feel slow before any real data starts moving.",
                "Try this: " + checkNext,
                "Keep in mind: this is not a page-load time or an internet speed result."
            ]
        case "empty":
            return [
                "No traffic was recorded, so there is nothing to explain yet.",
                "Try this: " + checkNext,
                "Keep in mind: an empty capture does not prove the network is healthy or faulty."
            ]
        default:
            return [observed, whyItMatters, "Try this: " + checkNext, "Keep in mind: " + cannotEstablish]
        }
    }
}

// MARK: - Potential causes for concern

public struct ConcernItem: Identifiable, Equatable {
    public var id: String
    public var level: String // "Potential concern" | "Worth checking" | "For awareness"
    public var title: String
    public var summary: String
    public var action: String
    public var packetNumbers: [Int]
    public init(id: String, level: String, title: String, summary: String, action: String, packetNumbers: [Int] = []) {
        self.id = id; self.level = level; self.title = title; self.summary = summary; self.action = action; self.packetNumbers = packetNumbers
    }
}

/// Flags *potential* causes for concern from measured findings. These are
/// prompts to investigate, not proof of a threat, compromise, or malware.
public enum ConcernBuilder {
    public static func items(report: CaptureReport) -> [ConcernItem] {
        var out: [ConcernItem] = []
        for f in report.findings {
            switch f.id {
            case "plaintext-remote":
                out.append(ConcernItem(id: f.id, level: "Potential concern", title: "Unencrypted traffic beyond this Mac",
                    summary: "Readable application data was seen beyond loopback. If it contains sign-ins or private content, other devices on the path could potentially see it.",
                    action: "Identify the app, prefer its encrypted (HTTPS/TLS) option, and avoid using that service on networks you do not trust until you understand it.",
                    packetNumbers: f.packetNumbers))
            case "dns-errors":
                out.append(ConcernItem(id: f.id, level: "Worth checking", title: "Failing name lookups",
                    summary: "DNS error replies can make apps appear offline. This is usually a name, DNS server, or service problem — it is not, by itself, a sign of an attack.",
                    action: f.recommendation, packetNumbers: f.packetNumbers))
            case "tcp-resets":
                out.append(ConcernItem(id: f.id, level: "Worth checking", title: "Connections cut short",
                    summary: "TCP resets can be normal, but a cluster around the time an app fails can point to a refused, blocked, or abruptly closed connection.",
                    action: f.recommendation, packetNumbers: f.packetNumbers))
            case "plaintext-local":
                out.append(ConcernItem(id: f.id, level: "For awareness", title: "Readable traffic on this Mac only",
                    summary: "Plaintext between loopback addresses stays on this Mac. It is listed for awareness, not as a network exposure.",
                    action: f.recommendation, packetNumbers: f.packetNumbers))
            default:
                out.append(ConcernItem(id: f.id, level: f.severity == "warning" ? "Potential concern" : "Worth checking", title: f.title, summary: f.evidence, action: f.recommendation, packetNumbers: f.packetNumbers))
            }
        }
        return out
    }
}

// MARK: - Comparison

public struct ComparisonMetric: Identifiable, Equatable {
    public var id: String { name }
    public var name: String
    public var baselineText: String
    public var currentText: String
    public var note: String
    public init(name: String, baselineText: String, currentText: String, note: String) { self.name = name; self.baselineText = baselineText; self.currentText = currentText; self.note = note }
}

public struct ComparisonResult: Equatable {
    public var metrics: [ComparisonMetric]
    public var warnings: [String]
    public var hasDetailedFacts: Bool
}

public enum ComparisonEngine {
    static func share(_ num: Int, _ den: Int) -> String {
        den > 0 ? String(format: "%.1f%% (%d of %d)", 100.0 * Double(num) / Double(den), num, den) : "No observed sample"
    }
    public static func compare(baseline: CaptureReport, current: CaptureReport, baselineContext: SessionContext, currentContext: SessionContext) -> ComparisonResult {
        var warnings: [String] = []
        if baselineContext.goal != currentContext.goal { warnings.append("The two captures used different goals (\(baselineContext.goal.title) vs \(currentContext.goal.title)).") }
        if !baselineContext.interface.isEmpty && !currentContext.interface.isEmpty && baselineContext.interface != currentContext.interface { warnings.append("Different network interfaces were used (\(baselineContext.interface) vs \(currentContext.interface)).") }
        if baselineContext.isImported || currentContext.isImported { warnings.append("An imported capture is included; its original capture conditions are unknown.") }
        let bd = baseline.duration, cd = current.duration
        if bd > 0 && cd > 0 && (max(bd, cd) / max(min(bd, cd), 0.001)) > 2 { warnings.append("The observed packet spans differ substantially (\(String(format: "%.0f", bd))s vs \(String(format: "%.0f", cd))s).") }
        if let bf = baseline.facts, let cf = current.facts {
            if bf.dnsResponses < 5 || cf.dnsResponses < 5 { warnings.append("Fewer than five visible DNS replies in at least one capture; DNS shares are based on a small sample.") }
            if bf.tcpPackets < 20 || cf.tcpPackets < 20 { warnings.append("Fewer than twenty decoded TCP packets in at least one capture; reset shares are based on a small sample.") }
        }
        guard let bf = baseline.facts, let cf = current.facts else {
            // Older reports without detailed facts: volume/span only.
            return ComparisonResult(metrics: [
                ComparisonMetric(name: "Captured bytes", baselineText: "\(baseline.capturedBytes) bytes", currentText: "\(current.capturedBytes) bytes", note: "Captured volume only; not a speed test."),
                ComparisonMetric(name: "Observed packet span", baselineText: spanText(baseline.duration), currentText: spanText(current.duration), note: "Last packet timestamp minus first packet timestamp."),
                ComparisonMetric(name: "Captured traffic rate", baselineText: rateText(baseline), currentText: rateText(current), note: "Captured bytes / observed packet span."),
            ], warnings: warnings + ["One capture has no detailed facts (older report). Open it from history to reanalyze it, then select it as baseline again for full metrics."], hasDetailedFacts: false)
        }
        func dnsTime(_ f: CaptureFacts) -> String { f.averageDNSMilliseconds.map { String(format: "%.0f ms (%d matched pair%@)", $0, f.matchedDNSPairs, f.matchedDNSPairs == 1 ? "" : "s") } ?? "No matched pairs" }
        let metrics = [
            ComparisonMetric(name: "DNS error reply share", baselineText: share(bf.dnsErrors, bf.dnsResponses), currentText: share(cf.dnsErrors, cf.dnsResponses), note: "DNS error replies / visible DNS replies."),
            ComparisonMetric(name: "TCP reset packet share", baselineText: share(bf.tcpResets, bf.tcpPackets), currentText: share(cf.tcpResets, cf.tcpPackets), note: "TCP packets with RST / all decoded TCP packets."),
            ComparisonMetric(name: "Matched DNS response time", baselineText: dnsTime(bf), currentText: dnsTime(cf), note: "Mean matched query/reply interval; DNS exchange time, not page-load time."),
            ComparisonMetric(name: "Captured traffic rate", baselineText: rateText(baseline), currentText: rateText(current), note: "Captured bytes / observed packet span. Not a speed test."),
            ComparisonMetric(name: "Observed packet span", baselineText: spanText(baseline.duration), currentText: spanText(current.duration), note: "Last packet timestamp minus first packet timestamp."),
        ]
        return ComparisonResult(metrics: metrics, warnings: warnings, hasDetailedFacts: true)
    }
    static func spanText(_ d: Double) -> String { String(format: "%.1f s", d) }
    static func rateText(_ r: CaptureReport) -> String {
        guard r.duration >= 1 else { return "Not reported (span under 1 s)" }
        return String(format: "%.1f KiB/s", Double(r.capturedBytes) / r.duration / 1024.0)
    }
}

// MARK: - Reports and redaction

public struct SupportOptions: Equatable {
    public var includeIPs = false
    public var includeDomains = false
    public var includeApps = true
    public var includeNotes = false
    public init() {}
}

public enum ReportText {
    static func fmtTime(_ epoch: Double?) -> String {
        guard let e = epoch else { return "unknown" }
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f.string(from: Date(timeIntervalSince1970: e))
    }
    public static func plainReport(report: CaptureReport, context: SessionContext) -> String {
        var lines: [String] = ["PacketScope analysis report", "===========================", ""]
        lines.append("Packets: \(report.packetCount)   Captured bytes: \(report.capturedBytes)   Observed span: \(String(format: "%.1f", report.duration)) s")
        lines.append("Goal: \(context.goal.title)   Interface: \(context.interface.isEmpty ? "unknown" : context.interface)")
        lines.append("Started: \(fmtTime(context.startedAt))   Ended: \(fmtTime(context.endedAt))")
        lines.append("")
        lines.append("Protocol mix:")
        for p in report.protocols { lines.append("  \(p.name): \(p.count) packets, \(p.bytes) bytes") }
        lines.append("")
        lines.append("Top endpoints:")
        for e in report.endpoints.prefix(20) { lines.append("  \(e.address): \(e.packets) packets, \(e.bytes) bytes") }
        lines.append("")
        lines.append("Observations:")
        if report.findings.isEmpty { lines.append("  No matching checks fired. This does not prove the network is healthy.") }
        for f in report.findings {
            lines.append("  - \(f.title): \(f.evidence) Next: \(f.recommendation) Packets: \(f.packetNumbers.map { "#\($0)" }.joined(separator: ", "))")
        }
        for n in report.limitationNotes { lines.append("Note: \(n)") }
        return lines.joined(separator: "\n")
    }

    public static func supportReport(report: CaptureReport, context: SessionContext, options: SupportOptions, comparison: ComparisonResult?, threatIntel: ThreatIntelSummary? = nil) -> String {
        var lines: [String] = []
        lines.append("PacketScope support report")
        lines.append("==========================")
        lines.append("This report was generated on this Mac from measured capture evidence. It contains no packet payloads and no PCAP data.")
        lines.append("")
        lines.append("Capture: \(report.packetCount) packets, \(report.capturedBytes) captured bytes, observed span \(String(format: "%.1f", report.duration)) s")
        lines.append("Goal: \(context.goal.title)")
        lines.append("Interface: \(context.interface.isEmpty ? "unknown" : context.interface)")
        lines.append("Session started: \(fmtTime(context.startedAt))   Ended: \(fmtTime(context.endedAt))")
        if !context.markers.isEmpty {
            lines.append("Marked moments:")
            for m in context.markers { lines.append("  - \(fmtTime(m.timestamp)): \(m.note)") }
        }
        lines.append("")
        lines.append("Observations and next steps:")
        if report.findings.isEmpty { lines.append("  No matching checks fired. This does not prove the network is healthy.") }
        for f in report.findings {
            lines.append("  - \(f.title)")
            lines.append("    Observed: \(f.evidence)")
            lines.append("    Check next: \(f.recommendation)")
            lines.append("    Supporting packets: \(f.packetNumbers.map { "#\($0)" }.joined(separator: ", "))")
        }
        if let facts = report.facts {
            lines.append("")
            lines.append("Measured facts:")
            lines.append("  Visible DNS replies: \(facts.dnsResponses); DNS error replies: \(facts.dnsErrors)")
            lines.append("  Decoded TCP packets: \(facts.tcpPackets); with RST: \(facts.tcpResets)")
            lines.append("  Matched DNS timing: " + (facts.averageDNSMilliseconds.map { String(format: "%.0f ms over %d pair(s)", $0, facts.matchedDNSPairs) } ?? "No matched pairs"))
            lines.append("  Attributed packets: \(facts.attributedPackets); Unknown ownership: \(facts.unattributedPackets)")
            if options.includeApps {
                lines.append("")
                lines.append("Apps / processes:")
                for a in facts.applications.prefix(30) { lines.append("  \(a.name)\(a.processID.map { " (PID \($0))" } ?? ""): \(a.packets) packets, \(a.bytes) bytes") }
            }
            if options.includeDomains {
                lines.append("")
                lines.append("Observed DNS names:")
                for d in facts.domains.prefix(100) { lines.append("  \(d.name): \(d.queryCount) queries, \(d.errorCount) errors\(d.addresses.isEmpty ? "" : ", addresses " + d.addresses.joined(separator: ", "))") }
            }
            if options.includeIPs {
                lines.append("")
                lines.append("Endpoints:")
                for e in report.endpoints.prefix(30) { lines.append("  \(e.address): \(e.packets) packets, \(e.bytes) bytes") }
            }
        }
        if let cmp = comparison {
            lines.append("")
            lines.append("Before/after comparison:")
            for m in cmp.metrics { lines.append("  \(m.name): baseline \(m.baselineText); current \(m.currentText) (\(m.note))") }
            for w in cmp.warnings { lines.append("  Caveat: \(w)") }
            lines.append("  A before/after difference cannot establish causation or confirm a fix.")
        }
        if options.includeNotes {
            if !context.symptom.isEmpty { lines.append(""); lines.append("Your notes / symptoms: \(context.symptom)") }
            if !context.changeNote.isEmpty { lines.append("Change tried: \(context.changeNote)") }
        }
        if let intel = threatIntel {
            lines.append("")
            lines.append("Threat feed matching (checked locally on this Mac):")
            switch intel.status {
            case "no_feeds": lines.append("  Threat matching didn't run: no feed copies had been downloaded.")
            case "disabled": lines.append("  Threat matching is turned off.")
            case "loading": lines.append("  Threat matching didn't run: feeds were still loading.")
            default:
                if intel.matches.isEmpty {
                    lines.append("  No matches in \(intel.feeds.count) threat feeds. Feeds only list known threats, so this doesn't rule out new ones.")
                } else {
                    for group in ThreatIntelSummary.groupByDestination(intel.matches) {
                        lines.append("  - \(group.displayName): severity \(group.severity)")
                        for m in group.matches {
                            let seen = m.indicator.lastSeen.map { ", last seen \($0)" } ?? ""
                            lines.append("    \(m.feedName.isEmpty ? m.indicator.feedId : m.feedName): \(m.matchedOn) \(Normalize.defanged(m.observed, type: m.matchedOn)) (threat: \(m.indicator.threat ?? "listed")\(seen))")
                        }
                    }
                }
                let feedNames = Set(intel.matches.map { $0.indicator.feedId } + intel.feeds.map { $0.id })
                for id in feedNames.sorted() {
                    if let meta = FeedRegistry.meta(id) {
                        lines.append("  Feed: \(meta.name) — license \(meta.license).\(meta.attribution.map { " " + $0 } ?? "")")
                    }
                }
                if intel.ignoredByAllowlist > 0 { lines.append("  Ignored by your allowlist: \(intel.ignoredByAllowlist)") }
            }
        }
        lines.append("")
        lines.append("Limitations:")
        lines.append("  - Encrypted traffic (including most web, call, and streaming traffic) cannot be read; only metadata and visible plaintext headers are used.")
        lines.append("  - An observed DNS name does not establish a website visit or a destination’s owner. No reverse-DNS or external lookups were performed.")
        lines.append("  - Captured volume is not a speed test and is not connection capacity.")
        for n in report.limitationNotes { lines.append("  - \(n)") }
        lines.append("  - Timestamps and packet references are shown by design; these privacy controls are selective redaction, not cryptographic anonymization. Review the preview before sharing, especially free-text notes.")
        var text = lines.joined(separator: "\n")
        text = redact(text, report: report, options: options)
        return text
    }

    // Redaction is applied to the whole generated text, including opted-in notes.
    public static func redact(_ text: String, report: CaptureReport, options: SupportOptions) -> String {
        var out = text
        if !options.includeApps, let facts = report.facts {
            for a in facts.applications where a.name != "Unknown" && a.name.count >= 3 {
                out = out.replacingOccurrences(of: a.name, with: "[app hidden]")
            }
        }
        if !options.includeDomains {
            if let facts = report.facts {
                for d in facts.domains.sorted(by: { $0.name.count > $1.name.count }) {
                    out = out.replacingOccurrences(of: d.name, with: "[domain hidden]")
                }
            }
            out = regexReplace(out, pattern: #"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|co|uk|de|fr|jp|au|ca|us|info|biz|dev|app|local|lan|home|internal|example)(?![A-Za-z0-9_-])"#, with: "[domain hidden]")
            out = regexReplace(out, pattern: #"https?://\S+"#, with: "[domain hidden]")
        }
        if !options.includeIPs {
            if let facts = report.facts { _ = facts }
            for e in report.endpoints.sorted(by: { $0.address.count > $1.address.count }) where e.address.contains(".") || e.address.contains(":") {
                out = out.replacingOccurrences(of: e.address, with: "[address hidden]")
            }
            out = regexReplace(out, pattern: #"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])"#, with: "[address hidden]")
            out = regexReplace(out, pattern: #"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"#, with: "[address hidden]")
        }
        return out
    }
    static func regexReplace(_ text: String, pattern: String, with replacement: String) -> String {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return text }
        return re.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text), withTemplate: replacement)
    }
}

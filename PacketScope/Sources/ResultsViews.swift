import SwiftUI
import Charts
import AppKit

// MARK: - Tone + pill

enum ResultTone { case success, warning, danger, neutral, info
    var color: Color {
        switch self { case .success: return PS.teal; case .warning: return PS.amber; case .danger: return PS.red; case .neutral: return PS.secondary; case .info: return PS.blue }
    }
}

struct StatusPill: View {
    var text: String
    var icon: String
    var tone: ResultTone
    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: icon).font(.system(size: 10, weight: .bold))
            Text(text).font(.system(size: 11, weight: .semibold))
        }
        .foregroundColor(tone.color)
        .padding(.horizontal, 9).padding(.vertical, 4)
        .background(tone.color.opacity(0.16))
        .clipShape(Capsule())
        .overlay(Capsule().stroke(tone.color.opacity(0.35), lineWidth: 1))
    }
}

func statusPillInfo(_ status: String) -> (text: String, icon: String, tone: ResultTone) {
    switch status {
    case "passed": return ("Passed", "checkmark", .success)
    case "failed": return ("Failed", "xmark", .danger)
    case "warning": return ("Warning", "exclamationmark.triangle.fill", .warning)
    case "not_reached": return ("Not reached", "circle", .neutral)
    default: return ("Not visible", "eye.slash", .neutral)
    }
}

func copyToPasteboard(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
}

// MARK: - Results page (spec layout)

struct ResultsPageView: View {
    @EnvironmentObject var model: AppModel
    @State private var selectedDestination: String?
    @State private var aiSummary: ResultSummary?
    @State private var summaryTaskID: String = ""

    private var results: CaptureResults? {
        guard let report = model.report, let ctx = model.context else { return nil }
        return CaptureResultsBuilder.build(report: report, context: ctx, kernelDrops: model.droppedPackets, threatIntel: model.threatIntel)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            if model.state == .analyzing && model.report == nil {
                skeleton
            } else if let r = results {
                header(r)
                if r.securityAlert != "none", let intel = r.threatIntel {
                    SecurityCardView(results: r, intel: intel)
                }
                VerdictCardView(results: r, summary: aiSummary ?? r.templateSummary)
                    .id("verdict")
                if r.verdict != "not_enough_traffic" {
                    if r.verdict == "cause_found" {
                        CoveragePillsView(results: r)
                    } else {
                        CoverageSectionView(results: r).id("coverage")
                    }
                    ConnectionPathView(results: r, selectedDestination: $selectedDestination).id("path")
                    if !r.findings.isEmpty {
                        FindingsSectionView(results: r).id("evidence")
                    }
                    ViewThatFits(in: .horizontal) {
                        HStack(alignment: .top, spacing: 16) {
                            DNSSectionView(results: r).frame(maxWidth: .infinity)
                            ChecksSectionView(results: r).frame(maxWidth: .infinity)
                        }
                        VStack(spacing: 16) {
                            DNSSectionView(results: r)
                            ChecksSectionView(results: r)
                        }
                    }
                    .id("dns")
                    DestinationsSectionView(results: r).id("destinations")
                    TimelineSectionView(results: r).id("timeline")
                    Text("Built-in checks only see this device's traffic during the capture and can't read inside encrypted connections. Nothing flagged doesn't prove the network is healthy or secure.")
                        .font(.system(size: 11)).foregroundColor(PS.secondary)
                }
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    Image(systemName: "doc.text.magnifyingglass").font(.system(size: 28)).foregroundColor(PS.secondary)
                    Text("No results yet").font(.system(size: 17, weight: .semibold))
                    Text("Run a capture on the Capture tab. When you stop it, the results will open here automatically.").font(.system(size: 12)).foregroundColor(PS.secondary)
                    Button("Go to capture") { model.scanPage = .setup }
                        .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black)
                }.psCard().frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .task(id: results.map { "\($0.packets)-\($0.verdict)-\($0.durationSec)" } ?? "none") {
            aiSummary = nil
            guard let r = results else { return }
            let taskID = "\(r.packets)-\(r.verdict)-\(r.durationSec)"
            summaryTaskID = taskID
            let summary = await ResultsSummarizer.summarize(results: r, useAI: model.useAI)
            if summaryTaskID == taskID && !Task.isCancelled { aiSummary = summary }
        }
    }

    private var skeleton: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Capture results").font(.system(size: 28, weight: .semibold))
            ForEach(0..<3, id: \.self) { _ in
                RoundedRectangle(cornerRadius: 12).fill(PS.panel).frame(height: 120)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(PS.border))
            }
            Text("Analyzing the capture…").font(.system(size: 12)).foregroundColor(PS.secondary)
        }
    }

    private func header(_ r: CaptureResults) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 7) {
                Text("Capture results").font(.system(size: 28, weight: .semibold))
                HStack(spacing: 10) {
                    StatusPill(text: "Goal: \(r.goalLabel)", icon: "target", tone: .info)
                    Text(metaLine(r)).font(.system(size: 12)).foregroundColor(PS.secondary)
                }
            }
            Spacer()
            Button("Back to capture") { model.scanPage = .setup }
                .frame(minHeight: 44)
        }
    }
    private func metaLine(_ r: CaptureResults) -> String {
        let date = r.startedAt.map { DateFormatter.localizedString(from: Date(timeIntervalSince1970: $0), dateStyle: .medium, timeStyle: .short) } ?? "Unknown time"
        let iface = r.interfaceName.isEmpty ? "unknown interface" : "\(r.interfaceName) (\(r.interfaceKind))"
        return "\(date)  ·  \(iface)  ·  \(ResultFormat.duration(r.durationSec))"
    }
}


// MARK: - Security card (code-built text; never written by the AI summary)

struct SecurityCardView: View {
    @EnvironmentObject var model: AppModel
    var results: CaptureResults
    var intel: ThreatIntelSummary
    private var isHigh: Bool { results.securityAlert == "high" }
    private var topGroup: MatchedDestination? { ThreatIntelSummary.groupByDestination(intel.matches).first }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                StatusPill(text: isHigh ? "Possible malware contact" : "Contact with a flagged address", icon: "exclamationmark.shield.fill", tone: isHigh ? .danger : .warning)
                Text("Security signal, separate from your troubleshooting answer").font(.system(size: 11)).foregroundColor(PS.secondary)
            }
            Text(intel.securityHeadline).font(.system(size: 20, weight: .semibold))
            if let group = topGroup, let first = group.matches.first {
                Text(factsLine(group: group, first: first)).font(.system(size: 13))
            }
            VStack(alignment: .leading, spacing: 5) {
                Text("What to do").font(.system(size: 12, weight: .semibold)).foregroundColor(isHigh ? PS.red : PS.amber)
                Text("1. Run a malware scan on this device.").font(.system(size: 12.5))
                Text("2. If this is a work device, tell your IT or security team.").font(.system(size: 12.5))
                Text("3. Share this report with them so they can see the evidence.").font(.system(size: 12.5))
            }
            HStack(spacing: 10) {
                Button("Show evidence") { model.resultsAnchor = "#evidence" }
                    .buttonStyle(.bordered).frame(minHeight: 44)
                Button("Share with support") { model.showSupportSheet = true }
                    .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black).frame(minHeight: 44)
            }
            Text("A feed listing is evidence to investigate, not proof that this device is infected.").font(.system(size: 11)).foregroundColor(PS.secondary)
        }
        .padding(20).background(PS.panel).clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke((isHigh ? PS.red : PS.amber).opacity(0.6), lineWidth: 1.5))
    }
    private func factsLine(group: MatchedDestination, first: ThreatMatch) -> String {
        let dest = results.destinations.first { $0.address == group.ip }
        let times = dest.map { "\($0.packets) packets in this capture" } ?? "\(first.evidenceCount) matching packet(s)"
        let seen = intel.matches.compactMap { $0.indicator.lastSeen }.max().map { " Feed last saw it: \($0)." } ?? ""
        return "\(group.displayName)\(group.ip.map { " (\($0)\(group.port.map { ":\($0)" } ?? ""))" } ?? "") — \(times).\(seen)"
    }
}

// MARK: - Verdict

struct VerdictCardView: View {
    @EnvironmentObject var model: AppModel
    var results: CaptureResults
    var summary: ResultSummary

    private var status: (text: String, icon: String, tone: ResultTone) {
        switch results.verdict {
        case "cause_found": return ("Likely cause found", "exclamationmark.triangle.fill", .danger)
        case "possible_issue": return ("Possible issue", "exclamationmark.triangle.fill", .warning)
        case "inconclusive": return ("Inconclusive", "questionmark.circle.fill", .warning)
        case "no_problem_seen": return ("No problem seen", "checkmark.circle.fill", .success)
        default: return ("Not enough traffic", "info.circle.fill", .neutral)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                StatusPill(text: status.text, icon: status.icon, tone: status.tone)
                if let top = results.findings.first, results.verdict == "cause_found" || results.verdict == "possible_issue" {
                    StatusPill(text: "\(top.confidence.capitalized) confidence", icon: "gauge.with.dots.needle.67percent", tone: .neutral)
                }
                Text("Summary written from \(ResultFormat.count(results.packets)) packets · every number links to its evidence")
                    .font(.system(size: 11)).foregroundColor(PS.secondary)
            }
            Text(summary.headline).font(.system(size: 21, weight: .semibold))
            Text(summary.body).font(.system(size: 13.5)).fixedSize(horizontal: false, vertical: true)
            if !summary.citations.isEmpty {
                HStack(spacing: 8) {
                    ForEach(Array(summary.citations.enumerated()), id: \.offset) { _, c in
                        Button(c.text) { model.resultsAnchor = c.anchor }
                            .font(.system(size: 11)).foregroundColor(PS.teal)
                    }
                }
            }
            if results.packets > 0 && results.kernelDrops * 100 > results.packets {
                Text("The capture dropped \(ResultFormat.count(results.kernelDrops)) packets (over 1% of the capture), so some evidence may be missing.")
                    .font(.system(size: 12)).foregroundColor(PS.amber)
            }
            nextStepBox
            if summary.fromTemplate {
                Text("Summary generated from checks").font(.system(size: 10)).foregroundColor(PS.secondary)
            }
        }
        .padding(20)
        .background(PS.panel)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(status.tone.color.opacity(0.55), lineWidth: 1.5))
    }

    private var nextStepBox: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(results.verdict == "cause_found" ? "What to try" : "Next step")
                .font(.system(size: 12, weight: .semibold)).foregroundColor(PS.teal)
            if results.verdict == "cause_found", let top = results.findings.first, top.nextSteps.count > 1 {
                ForEach(Array(top.nextSteps.enumerated()), id: \.offset) { i, step in
                    Text("\(i + 1).  \(step)").font(.system(size: 12.5))
                }
            } else {
                Text(summary.nextStep).font(.system(size: 12.5))
            }
            HStack(spacing: 10) {
                primaryButton
                if results.verdict == "cause_found" {
                    Button("Capture again") { model.scanPage = .setup }.frame(minHeight: 44)
                }
                if let top = results.findings.first {
                    Button("Export these packets") { model.exportEvidencePackets(frames: top.evidence.frames) }.frame(minHeight: 44)
                } else {
                    Button("Export capture") { model.exportRawCapture() }.frame(minHeight: 44)
                }
            }
            .font(.system(size: 12.5))
        }
        .padding(14)
        .background(PS.elevated)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(PS.border))
    }

    @ViewBuilder private var primaryButton: some View {
        switch results.verdict {
        case "cause_found", "possible_issue":
            Button("Share with support") { model.showSupportSheet = true }
                .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black).frame(minHeight: 44)
        case "inconclusive":
            Button("Capture again for 60 s") { model.durationChoice = .m1; model.startCapture() }
                .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black).frame(minHeight: 44)
        case "no_problem_seen":
            Button("Back to capture") { model.scanPage = .setup }
                .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black).frame(minHeight: 44)
        default:
            Button("Capture again") { model.scanPage = .setup }
                .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black).frame(minHeight: 44)
        }
    }
}

// MARK: - Coverage

struct CoveragePillsView: View {
    var results: CaptureResults
    var body: some View {
        HStack(spacing: 8) {
            Text("Coverage").font(.system(size: 12, weight: .semibold)).foregroundColor(PS.secondary)
            StatusPill(text: "\(ResultFormat.duration(results.durationSec)) · \(results.tooShort ? "short" : "long enough")", icon: "clock", tone: results.tooShort ? .warning : .success)
            if results.markedMomentsSec.isEmpty {
                StatusPill(text: "No moment marked", icon: "mappin.slash", tone: .warning)
            } else {
                StatusPill(text: "Moment marked at \(ResultFormat.packetTime(results.markedMomentsSec[0]))", icon: "mappin", tone: .info)
            }
            StatusPill(text: "\(ResultFormat.count(results.checkedPackets)) of \(ResultFormat.count(results.packets)) packets checked\(results.skipped.first.map { " · \(ResultFormat.count($0.packets)) QUIC skipped" } ?? "")", icon: "eye", tone: results.checkedPercent < 70 ? .warning : .neutral)
            StatusPill(text: ResultFormat.bytes(results.bytes), icon: "doc", tone: .neutral)
            StatusPill(text: results.interfaceName.isEmpty ? "unknown" : "\(results.interfaceName) · \(results.interfaceKind)", icon: "network", tone: .neutral)
            StatusPill(text: "\(ResultFormat.count(results.kernelDrops)) dropped", icon: results.kernelDrops > 0 ? "exclamationmark.triangle.fill" : "checkmark", tone: results.kernelDrops > 0 ? .warning : .success)
        }
    }
}

struct CoverageSectionView: View {
    var results: CaptureResults
    private var checkedWarning: Bool { results.checkedPercent < 70 }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("What this capture could see").font(.system(size: 17, weight: .semibold))
                Spacer()
                Text("Limits that affect how much to trust the summary").font(.system(size: 11)).foregroundColor(PS.secondary)
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), spacing: 12)], spacing: 12) {
                tile("Duration", ResultFormat.duration(results.durationSec), results.tooShort ? "Short. May miss the problem" : "Long enough to reproduce most problems", warning: results.tooShort)
                tile("Checked by built-in checks", "\(ResultFormat.count(results.checkedPackets)) of \(ResultFormat.count(results.packets))", checkedDetail, warning: checkedWarning)
                tile("Data", ResultFormat.bytes(results.bytes), "\(ResultFormat.count(results.packets)) packets", warning: false)
                tile("Interface", results.interfaceName.isEmpty ? "—" : results.interfaceName, "\(results.interfaceKind), this device only", warning: false)
                tile("Dropped by capture", ResultFormat.count(results.kernelDrops), results.kernelDrops > 0 ? "Some packets were lost" : "Nothing lost", warning: results.kernelDrops > 0)
                threatTile
            }
            mixBar
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }
    @ViewBuilder private var threatTile: some View {
        if let intel = results.threatIntel {
            let stale = intel.feeds.contains { $0.stale }
            let warning = stale || intel.status != "checked"
            tile("Threat feeds", intel.status == "checked" ? "\(intel.feeds.count) feeds" : "Didn't run",
                 intel.status == "no_feeds" ? "Threat matching didn't run" : (stale ? "Feeds are stale; using the last good copies" : "Updated \(intel.feeds.compactMap { $0.updatedAt }.max().map { relAge($0) } ?? "never")"),
                 warning: warning)
        }
    }
    private func relAge(_ epoch: Double) -> String {
        let secs = max(0, Date().timeIntervalSince1970 - epoch)
        if secs < 3600 { return "\(Int(secs / 60)) min ago" }
        if secs < 86400 { return "\(Int(secs / 3600)) h ago" }
        return "\(Int(secs / 86400)) d ago"
    }
    private var checkedDetail: String {
        guard let first = results.skipped.first else { return "Everything could be checked" }
        if first.reason == "encrypted_quic" {
            return "\(ResultFormat.count(first.packets)) QUIC packets (names read, contents encrypted)"
        }
        let label = first.reason == "encrypted_other" ? "encrypted" : first.reason
        return "\(ResultFormat.count(first.packets)) \(label) packets skipped"
    }
    private func tile(_ title: String, _ value: String, _ sub: String, warning: Bool) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 11)).foregroundColor(PS.secondary)
            Text(value).font(.system(size: 20, weight: .semibold, design: .monospaced))
            Text(sub).font(.system(size: 11)).foregroundColor(warning ? PS.amber : PS.secondary)
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(PS.elevated).clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(warning ? PS.amber.opacity(0.6) : PS.border, lineWidth: 1))
    }
    private var mixBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            GeometryReader { geo in
                HStack(spacing: 2) {
                    ForEach(results.mix) { m in
                        Rectangle().fill(mixColor(m.name))
                            .frame(width: max(2, geo.size.width * CGFloat(m.count) / CGFloat(max(1, results.packets))))
                    }
                }
            }.frame(height: 12).clipShape(RoundedRectangle(cornerRadius: 6))
            HStack(spacing: 16) {
                ForEach(results.mix) { m in
                    HStack(spacing: 5) {
                        Circle().fill(mixColor(m.name)).frame(width: 8, height: 8)
                        Text("\(m.name)  \(ResultFormat.count(m.count))  \(m.name == "QUIC" ? "names read, contents encrypted" : ((results.mixChecked[m.name] ?? true) ? "checked" : "encrypted, skipped"))")
                            .font(.system(size: 11)).foregroundColor(PS.secondary)
                    }
                }
            }
        }
    }
    private func mixColor(_ name: String) -> Color {
        switch name { case "TCP": return PS.blue; case "DNS": return PS.teal; case "QUIC": return Color.gray; case "UDP_OTHER": return Color.purple; case "ICMP": return PS.amber; default: return PS.secondary }
    }
}

// MARK: - Connection path

struct ConnectionPathView: View {
    var results: CaptureResults
    @Binding var selectedDestination: String?
    private var path: ConnectionPathResult? {
        if let sel = selectedDestination, let p = results.paths.first(where: { $0.destination == sel }) { return p }
        return results.paths.first
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(path.map { "Connection path to \($0.destination)" } ?? "Connection path").font(.system(size: 17, weight: .semibold))
                    Text("Every connection passes these steps in order. The first failed step is usually the cause.").font(.system(size: 11)).foregroundColor(PS.secondary)
                }
                Spacer()
                if results.paths.count > 1 {
                    Picker("Destination", selection: Binding(get: { selectedDestination ?? path?.destination ?? "" }, set: { selectedDestination = $0 })) {
                        ForEach(results.paths) { p in Text(p.destination).tag(p.destination) }
                    }.frame(maxWidth: 260)
                }
            }
            if let path = path {
                let firstFailed = path.stages.firstIndex(where: { $0.status == "failed" })
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 175), spacing: 12)], spacing: 12) {
                    ForEach(Array(path.stages.enumerated()), id: \.offset) { i, stage in
                        stageCard(stage, index: i, isFirstFailed: i == firstFailed)
                    }
                }
            }
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }
    private func stageCard(_ stage: PathStage, index: Int, isFirstFailed: Bool) -> some View {
        let info = statusPillInfo(stage.status)
        return VStack(alignment: .leading, spacing: 7) {
            HStack {
                Text("STEP \(index + 1)").font(.system(size: 10, weight: .semibold)).foregroundColor(PS.secondary)
                Spacer()
                StatusPill(text: isFirstFailed ? "Failed here" : info.text, icon: info.icon, tone: info.tone)
            }
            Text(stage.title).font(.system(size: 14, weight: .semibold))
            Text(stage.result).font(.system(size: 12.5))
            Text(stage.detail).font(.system(size: 11)).foregroundColor(PS.secondary)
        }
        .padding(13).frame(maxWidth: .infinity, alignment: .leading)
        .background(PS.elevated).clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(isFirstFailed ? PS.red.opacity(0.75) : PS.border, lineWidth: isFirstFailed ? 1.5 : 1))
    }
}

// MARK: - Findings / evidence

struct FindingsSectionView: View {
    @EnvironmentObject var model: AppModel
    var results: CaptureResults
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            ForEach(results.findings) { f in
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 8) {
                        Text("Evidence: \(titleFor(f))").font(.system(size: 16, weight: .semibold))
                        StatusPill(text: f.severity == "likely_cause" ? "Likely cause" : (f.severity == "warning" ? "Warning" : "Info"), icon: f.severity == "likely_cause" ? "exclamationmark.triangle.fill" : "info.circle", tone: f.severity == "likely_cause" ? .danger : (f.severity == "warning" ? .warning : .info))
                    }
                    ViewThatFits(in: .horizontal) {
                        HStack(alignment: .top, spacing: 20) {
                            column("Observed", f.observed)
                            column("What that usually means", f.interpretation)
                        }
                        VStack(alignment: .leading, spacing: 12) {
                            column("Observed", f.observed)
                            column("What that usually means", f.interpretation)
                        }
                    }
                    if f.category == "security" {
                        indicatorList(f)
                    }
                    packetTable(f)
                    filterRow(filter: f.evidence.filter, frames: f.evidence.frames)
                }.psCard().frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
    private func indicatorList(_ f: ResultFinding) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("Matched indicators").font(.system(size: 12, weight: .semibold)).foregroundColor(PS.secondary)
            ForEach(f.matchedIndicators) { m in
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        if let url = URL(string: m.feedHomepage), !m.feedHomepage.isEmpty {
                            Link(m.feedName.isEmpty ? m.indicator.feedId : m.feedName, destination: url).font(.system(size: 12, weight: .semibold)).foregroundColor(PS.teal)
                        } else {
                            Text(m.feedName.isEmpty ? m.indicator.feedId : m.feedName).font(.system(size: 12, weight: .semibold))
                        }
                        Text(m.matchedOn).font(.system(size: 10, weight: .semibold)).foregroundColor(PS.secondary)
                        Text(Normalize.defanged(m.observed, type: m.matchedOn)).font(.system(size: 11, design: .monospaced)).foregroundColor(PS.secondary)
                    }
                    HStack(spacing: 10) {
                        if let threat = m.indicator.threat { Text("Threat: \(threat)").font(.system(size: 11)).foregroundColor(PS.secondary) }
                        if let fam = m.indicator.malwareFamily { Text("Family: \(fam)").font(.system(size: 11)).foregroundColor(PS.secondary) }
                        if let fs = m.indicator.firstSeen { Text("First seen: \(fs)").font(.system(size: 11)).foregroundColor(PS.secondary) }
                        if let ls = m.indicator.lastSeen { Text("Last seen: \(ls)").font(.system(size: 11)).foregroundColor(PS.secondary) }
                    }
                }
                .padding(9).background(PS.elevated).clipShape(RoundedRectangle(cornerRadius: 8)).overlay(RoundedRectangle(cornerRadius: 8).stroke(PS.border))
            }
            if let first = f.matchedIndicators.first, !first.severityReasons.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Why this severity").font(.system(size: 12, weight: .semibold)).foregroundColor(PS.secondary)
                    ForEach(first.severityReasons, id: \.self) { reason in
                        Text("•  " + plainReason(reason)).font(.system(size: 11.5)).foregroundColor(PS.secondary)
                    }
                }
            }
        }
    }
    private func plainReason(_ reason: String) -> String {
        reason.replacingOccurrences(of: "base: ", with: "Feed base severity: ")
            .replacingOccurrences(of: "downgraded: ", with: "Lowered: ")
            .replacingOccurrences(of: "upgraded: ", with: "Raised: ")
    }
    private func titleFor(_ f: ResultFinding) -> String {
        switch f.id { case "unanswered-connection": return "unanswered connection attempts"; case "refused-connection": return "refused connection"; case "dns-name-not-found": return "name lookup failed"; default: return f.title.lowercased() }
    }
    private func column(_ heading: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(heading).font(.system(size: 12, weight: .semibold)).foregroundColor(PS.secondary)
            Text(text).font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private func packetTable(_ f: ResultFinding) -> some View {
        let rows = (model.report?.packets ?? []).filter { f.evidence.frames.contains($0.id) }.prefix(10)
        return VStack(alignment: .leading, spacing: 0) {
            if rows.isEmpty {
                Text("The supporting packets are outside the retained display rows; the finding was measured over the entire file.").font(.system(size: 11)).foregroundColor(PS.secondary).padding(.vertical, 6)
            } else {
                tableHeader
                ForEach(Array(rows), id: \.id) { pkt in
                    HStack(spacing: 10) {
                        Button("#\(pkt.id)") { model.openPacketLog(number: pkt.id) }.font(.system(size: 11, design: .monospaced)).foregroundColor(PS.teal).frame(width: 52, alignment: .leading)
                        Text(relTime(pkt)).font(.system(size: 11, design: .monospaced)).foregroundColor(PS.secondary).frame(width: 64, alignment: .leading)
                        Text("\(endpoint(pkt.source, pkt.sourcePort)) → \(endpoint(pkt.destination, pkt.destinationPort))").font(.system(size: 11, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading)
                        Text(pkt.summary).font(.system(size: 11)).foregroundColor(PS.secondary).frame(maxWidth: 300, alignment: .leading)
                    }.padding(.vertical, 6)
                    Divider().background(PS.border)
                }
            }
        }
    }
    private var tableHeader: some View {
        HStack(spacing: 10) {
            Text("No.").frame(width: 52, alignment: .leading)
            Text("Time").frame(width: 64, alignment: .leading)
            Text("From → to").frame(maxWidth: .infinity, alignment: .leading)
            Text("Info").frame(maxWidth: 300, alignment: .leading)
        }.font(.system(size: 10, weight: .semibold)).foregroundColor(PS.secondary).padding(.vertical, 4)
    }
    private func relTime(_ pkt: PacketRecord) -> String {
        guard let first = model.report?.facts?.firstTimestamp else { return "—" }
        return ResultFormat.packetTime(pkt.timestamp - first)
    }
    private func endpoint(_ a: String, _ p: Int?) -> String { p.map { "\(a):\($0)" } ?? a }
    private func filterRow(filter: String, frames: [Int]) -> some View {
        HStack(spacing: 10) {
            Text("Filter").font(.system(size: 11, weight: .semibold)).foregroundColor(PS.secondary)
            Text(filter.isEmpty ? "—" : filter).font(.system(size: 11, design: .monospaced)).foregroundColor(PS.secondary).lineLimit(1)
            Button { copyToPasteboard(filter) } label: { Image(systemName: "doc.on.doc") }
                .buttonStyle(.plain).help("Copy filter").accessibilityLabel("Copy filter")
            Button("Open in packet view") { model.openEvidenceFilter(filter) }.font(.system(size: 11)).foregroundColor(PS.teal)
            Button("Export these packets") { model.exportEvidencePackets(frames: frames) }.font(.system(size: 11))
        }
    }
}

// MARK: - DNS + Checks

struct DNSSectionView: View {
    @EnvironmentObject var model: AppModel
    var results: CaptureResults
    private var rating: (String, ResultTone) {
        guard let mx = results.dnsMaxMs else { return ("—", .neutral) }
        if mx > 300 { return ("Slow", .warning) }
        if mx < 100 { return ("Normal", .success) }
        return ("OK", .info)
    }
    private var scale: Double { max(100, results.dnsMaxMs ?? 100) }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Name lookups (DNS)").font(.system(size: 16, weight: .semibold))
                Spacer()
                StatusPill(text: rating.0, icon: "gauge.with.dots.needle.33percent", tone: rating.1)
            }
            HStack(spacing: 22) {
                stat("Answered", results.dnsQueries > 0 ? "\(results.dnsAnswered) of \(results.dnsQueries)" : "0")
                stat("Average", results.dnsAvgMs.map(ResultFormat.ms) ?? "—")
                stat("Slowest", results.dnsMaxMs.map(ResultFormat.ms) ?? "—")
                stat("Resolver", results.dnsResolvers.first ?? "—")
            }
            if results.dnsLookups.isEmpty {
                Text("No standard DNS lookups were visible. Encrypted DNS, cached lookups, and absent queries leave gaps.").font(.system(size: 11)).foregroundColor(PS.secondary)
            } else {
                ForEach(results.dnsLookups.prefix(50)) { l in
                    HStack(spacing: 10) {
                        Text("\(l.name)  \(l.type)").font(.system(size: 11, design: .monospaced)).frame(width: 210, alignment: .leading).lineLimit(1)
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                RoundedRectangle(cornerRadius: 4).fill(PS.elevated).frame(height: 8)
                                if let ms = l.milliseconds {
                                    RoundedRectangle(cornerRadius: 4).fill(PS.teal).frame(width: max(3, geo.size.width * CGFloat(min(ms, scale)) / CGFloat(scale)), height: 8)
                                }
                            }
                        }.frame(height: 8)
                        Text(l.milliseconds.map(ResultFormat.ms) ?? (l.rcode.isEmpty ? "no answer" : l.rcode))
                            .font(.system(size: 11, design: .monospaced)).foregroundColor(l.milliseconds == nil ? PS.amber : PS.secondary)
                            .frame(width: 82, alignment: .trailing)
                    }
                }
                Text("Bars are scaled to \(ResultFormat.ms(scale)). Lookups under 100 ms don't cause a noticeable delay. This measures name lookup only, not page load or internet speed.")
                    .font(.system(size: 11)).foregroundColor(PS.secondary)
            }
            HStack(spacing: 10) {
                Text("Evidence").font(.system(size: 11, weight: .semibold)).foregroundColor(PS.secondary)
                Text("dns.flags.response == 1").font(.system(size: 11, design: .monospaced)).foregroundColor(PS.secondary)
                Button { copyToPasteboard("dns.flags.response == 1") } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.plain).help("Copy filter").accessibilityLabel("Copy DNS evidence filter")
                Button("Show \(ResultFormat.count(results.dnsEvidenceCount)) packets") { model.openEvidenceFilter("dns") }
                    .font(.system(size: 11)).foregroundColor(PS.teal)
            }
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }
    private func stat(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.system(size: 10)).foregroundColor(PS.secondary)
            Text(value).font(.system(size: 16, weight: .semibold, design: .monospaced))
        }
    }
}

struct ChecksSectionView: View {
    var results: CaptureResults
    private var flaggedCount: Int { results.checks.filter { $0.flagged }.count }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Checks run").font(.system(size: 16, weight: .semibold))
                Spacer()
                Text("\(results.checks.count) run · \(flaggedCount) flagged").font(.system(size: 11)).foregroundColor(PS.secondary)
            }
            ForEach(results.checks) { c in
                HStack(spacing: 10) {
                    Image(systemName: c.flagged ? "exclamationmark.triangle.fill" : "checkmark.circle")
                        .foregroundColor(c.flagged ? PS.amber : PS.teal).font(.system(size: 13))
                    Text(c.label).font(.system(size: 12.5))
                    Spacer()
                    Text(ResultFormat.count(c.count)).font(.system(size: 12.5, design: .monospaced))
                    Text(c.note).font(.system(size: 11)).foregroundColor(c.flagged ? PS.amber : PS.secondary).frame(width: 110, alignment: .trailing)
                }
                Divider().background(PS.border)
            }
            Text(notCheckedText).font(.system(size: 11)).foregroundColor(PS.secondary)
            if let intel = results.threatIntel {
                Divider().background(PS.border)
                ThreatIntelChecksView(intel: intel)
            }
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }
    private var notCheckedText: String {
        var parts: [String] = []
        for s in results.skipped {
            let label = s.reason == "encrypted_quic" ? "QUIC (names read, contents encrypted)" : (s.reason == "encrypted_other" ? "encrypted" : s.reason)
            parts.append("the \(ResultFormat.count(s.packets)) \(label) packets")
        }
        let base = parts.isEmpty ? "Nothing was skipped by the checks." : "Not checked: " + parts.joined(separator: ", ") + "."
        return base + " Anything outside these \(ResultFormat.duration(results.durationSec)) or this interface is also not covered."
    }
}

// MARK: - Destinations

struct DestinationsSectionView: View {
    @EnvironmentObject var model: AppModel
    var results: CaptureResults
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Who this device talked to").font(.system(size: 17, weight: .semibold))
                Spacer()
                Text("Names come from DNS lookups and TLS server names").font(.system(size: 11)).foregroundColor(PS.secondary)
            }
            ScrollView(.horizontal, showsIndicators: false) {
                VStack(alignment: .leading, spacing: 0) {
                    headerRow
                    ForEach(results.destinations) { d in row(d) }
                    if let resolver = results.dnsResolvers.first {
                        HStack(spacing: 10) {
                            Text("Router (DNS)").frame(width: 180, alignment: .leading)
                            Text("\(resolver):53").font(.system(size: 11, design: .monospaced)).frame(width: 160, alignment: .leading)
                            Text("DNS").frame(width: 130, alignment: .leading)
                            StatusPill(text: "\(results.dnsAnswered) of \(results.dnsQueries) answered", icon: "checkmark", tone: .success)
                            Spacer()
                            Text(ResultFormat.count(results.dnsEvidenceCount)).frame(width: 70, alignment: .trailing)
                            Text("dns").font(.system(size: 11, design: .monospaced)).foregroundColor(PS.secondary).frame(width: 220, alignment: .leading)
                        }.font(.system(size: 12)).padding(.vertical, 7)
                        Divider().background(PS.border)
                    }
                    if results.destinations.isEmpty && results.dnsResolvers.isEmpty {
                        Text("No destinations were observed.").font(.system(size: 12)).foregroundColor(PS.secondary).padding(.vertical, 8)
                    }
                }.frame(minWidth: 780, alignment: .leading)
            }
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }
    private var headerRow: some View {
        HStack(spacing: 10) {
            Text("Destination").frame(width: 180, alignment: .leading)
            Text("Address").frame(width: 160, alignment: .leading)
            Text("Protocol").frame(width: 130, alignment: .leading)
            Text("Result").frame(width: 150, alignment: .leading)
            Spacer()
            Text("Packets").frame(width: 70, alignment: .trailing)
            Text("Evidence filter").frame(width: 220, alignment: .leading)
        }.font(.system(size: 10, weight: .semibold)).foregroundColor(PS.secondary).padding(.vertical, 5)
    }
    private func row(_ d: DestinationRecord) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 1) {
                Text(d.name ?? d.address).font(.system(size: 12, weight: .medium)).lineLimit(1)
                if let src = d.nameSource { Text("name from \(src == "dns" ? "DNS" : "TLS server name")").font(.system(size: 9)).foregroundColor(PS.secondary) }
            }.frame(width: 180, alignment: .leading)
            Text(d.port > 0 ? "\(d.address):\(d.port)" : d.address).font(.system(size: 11, design: .monospaced)).frame(width: 160, alignment: .leading)
            Text(d.protocolLabel).font(.system(size: 12)).frame(width: 130, alignment: .leading)
            VStack(alignment: .leading, spacing: 3) {
                outcomePill(d.outcome)
                if let sev = d.intelTopSeverity, let m = results.threatIntel?.matches.first(where: { $0.destinationIP == d.address }) {
                    StatusPill(text: "Listed by \(m.feedName.isEmpty ? m.indicator.feedId : m.feedName)", icon: "shield.lefthalf.filled", tone: sev == "high" ? .danger : .warning)
                }
            }.frame(width: 150, alignment: .leading)
            Spacer()
            Text(ResultFormat.count(d.packets)).font(.system(size: 12, design: .monospaced)).frame(width: 70, alignment: .trailing)
            Button { model.openEvidenceFilter(d.evidenceFilter) } label: {
                Text(d.evidenceFilter).font(.system(size: 10, design: .monospaced)).foregroundColor(PS.teal).lineLimit(1)
            }.buttonStyle(.plain).frame(width: 220, alignment: .leading)
        }.padding(.vertical, 7)
    }
    private func outcomePill(_ outcome: String) -> some View {
        switch outcome {
        case "connected": return StatusPill(text: "Connected", icon: "checkmark", tone: .success)
        case "refused": return StatusPill(text: "Refused", icon: "xmark", tone: .danger)
        case "no_reply": return StatusPill(text: "No reply", icon: "xmark", tone: .danger)
        case "reset_later": return StatusPill(text: "Reset later", icon: "exclamationmark.triangle.fill", tone: .warning)
        case "not_checked": return StatusPill(text: "Not checked", icon: "eye.slash", tone: .neutral)
        default: return StatusPill(text: "Background", icon: "circle", tone: .neutral)
        }
    }
}

// MARK: - Timeline

struct TimelineSectionView: View {
    var results: CaptureResults
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Timeline").font(.system(size: 17, weight: .semibold))
                Spacer()
                Text("Packets per \(binLabel)").font(.system(size: 11)).foregroundColor(PS.secondary)
            }
            if results.timelineBuckets.isEmpty {
                Text("No timeline data for this capture.").font(.system(size: 12)).foregroundColor(PS.secondary)
            } else {
                Chart {
                    ForEach(results.timelineBuckets) { b in
                        BarMark(x: .value("Seconds", b.second), y: .value("Packets", b.packets))
                            .foregroundStyle(PS.blue)
                    }
                    ForEach(Array(results.timelineEvents.filter { $0.kind == "finding" }.enumerated()), id: \.offset) { _, e in
                        if let end = e.endSec {
                            RectangleMark(xStart: .value("Start", Int(e.atSec)), xEnd: .value("End", Int(max(end, e.atSec + 1))), yStart: .value("Y", 0), yEnd: .value("Y", maxPackets))
                                .foregroundStyle(PS.red.opacity(0.15))
                        }
                    }
                    ForEach(results.markedMomentsSec, id: \.self) { m in
                        RuleMark(x: .value("Marked", Int(m))).foregroundStyle(PS.amber).lineStyle(StrokeStyle(lineWidth: 2))
                    }
                }
                .frame(height: 170)
                HStack {
                    Text("0 s").font(.system(size: 10, design: .monospaced)).foregroundColor(PS.secondary)
                    Spacer()
                    Text(ResultFormat.duration(results.durationSec)).font(.system(size: 10, design: .monospaced)).foregroundColor(PS.secondary)
                }
                eventPills
            }
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }
    private var maxPackets: Int { max(1, results.timelineBuckets.map { $0.packets }.max() ?? 1) }
    private var binLabel: String { results.timelineBinSec >= 1 ? "\(Int(results.timelineBinSec)) s" : String(format: "%.1f s", results.timelineBinSec) }
    private var eventPills: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                ForEach(Array(results.timelineEvents.enumerated()), id: \.offset) { _, e in
                    StatusPill(text: "\(ResultFormat.packetTime(e.atSec)) · \(e.label)", icon: e.kind == "marked" ? "mappin" : (e.kind == "finding" ? "exclamationmark.triangle.fill" : "circle.fill"), tone: e.kind == "marked" ? .info : (e.kind == "finding" ? .danger : .neutral))
                }
                if results.markedMomentsSec.isEmpty {
                    StatusPill(text: "No moment marked", icon: "mappin.slash", tone: .warning)
                }
            }
            if results.markedMomentsSec.isEmpty {
                Text("Press Mark the moment during your next capture and the summary will focus on what happened around it.").font(.system(size: 11)).foregroundColor(PS.secondary)
            }
        }
    }
}

// MARK: - Threat-intel check rows (inside Checks run)

struct ThreatIntelChecksView: View {
    var intel: ThreatIntelSummary
    private func matchCount(on types: [String]) -> Int { intel.matches.filter { types.contains($0.matchedOn) }.count }
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Threat feed checks").font(.system(size: 13, weight: .semibold))
            if intel.status == "loading" {
                row("Threat matching didn't run (feeds still loading)", detail: "The results were ready first; capture again to include threat matching")
            } else if intel.status == "no_feeds" {
                row("Threat matching didn't run", detail: "No feed copies have been downloaded yet")
            } else if intel.status == "disabled" {
                row("Threat matching is off", detail: "Enable feeds in Threat feeds settings")
            } else {
                row("Destinations checked against threat feeds: \(intel.checkedIPsTotal > intel.checkedIPs ? "\(intel.checkedIPs) of \(intel.checkedIPsTotal)" : "\(intel.checkedIPs)")", detail: "\(matchCount(on: ["ipv4", "ipv6", "cidr", "ip_port"])) matches")
                row("Domains checked against threat feeds: \(intel.checkedDomains)", detail: "\(matchCount(on: ["domain"])) matches")
                row("URLs checked against threat feeds: \(intel.checkedURLs)", detail: "\(matchCount(on: ["url"])) matches")
                row("Certificates checked against threat feeds: \(intel.checkedCerts)", detail: "\(matchCount(on: ["cert_sha1", "cert_sha256"])) matches")
                row("TLS fingerprints checked against threat feeds: \(intel.checkedFingerprints)", detail: "\(matchCount(on: ["ja3", "ja4"])) matches")
                row("Files: not checked", detail: "This app doesn't reconstruct transferred files, so file hashes can't be checked")
                if intel.ignoredByAllowlist > 0 {
                    row("Ignored by your allowlist: \(intel.ignoredByAllowlist)", detail: "Allowlisted matches are counted, not hidden")
                }
                if intel.matches.isEmpty {
                    Text("No matches in \(intel.feeds.count) threat feeds. Feeds only list known threats, so this doesn't rule out new ones.")
                        .font(.system(size: 11)).foregroundColor(PS.teal)
                }
            }
        }
    }
    private func row(_ label: String, detail: String) -> some View {
        HStack {
            Text(label).font(.system(size: 12))
            Spacer()
            Text(detail).font(.system(size: 11)).foregroundColor(PS.secondary)
        }
    }
}

import SwiftUI
import Charts
import AppKit

// MARK: - Guided setup

struct GuidedSetupView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                ForEach(CaptureGoal.allCases) { g in
                    Button { model.goal = g } label: {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack { Image(systemName: g.symbol).foregroundColor(PS.teal); Text(g.title).font(.system(size: 13, weight: .semibold)).foregroundColor(PS.primary); Spacer(); if model.goal == g { Image(systemName: "checkmark.circle.fill").foregroundColor(PS.teal) } }
                            Text(g.guidance).font(.system(size: 11)).foregroundColor(PS.secondary).multilineTextAlignment(.leading)
                        }.padding(14)
                        .background(model.goal == g ? PS.elevated : PS.panel)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(model.goal == g ? PS.teal.opacity(0.6) : PS.border, lineWidth: 1))
                    }.buttonStyle(.plain).disabled(model.isCapturing || model.state.isBusy)
                }
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("Symptom (optional)").font(.system(size: 11, weight: .semibold)).foregroundColor(PS.secondary)
                TextField("e.g. Teams freezes when I unmute", text: $model.symptom).textFieldStyle(.roundedBorder).disabled(model.isCapturing || model.state.isBusy)
                Text("The goal and symptom are saved with the session for the support report. All goals use the same capture and analysis engine; they change guidance and saved context, not the diagnostic algorithm.")
                    .font(.system(size: 11)).foregroundColor(PS.secondary)
            }.psCard().frame(maxWidth: .infinity, alignment: .leading)
            if model.state == .authorizing {
                Text("Waiting for the macOS administrator prompt… PacketScope never asks for or stores your password.").font(.system(size: 11)).foregroundColor(PS.amber)
            }
        }
    }
}

// MARK: - Timeline

struct TimelineView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Timeline").font(.system(size: 28, weight: .semibold))
            if let report = model.report, let facts = report.facts, !facts.timeline.isEmpty {
                Text("Captured bytes per time bucket, relative to the first observed packet, across the full file (not just retained rows). Amber rules are your saved markers. Byte totals include PKTAP metadata when present and are not unique wire bytes.")
                    .font(.system(size: 11)).foregroundColor(PS.secondary)
                Chart {
                    ForEach(facts.timeline) { b in
                        BarMark(x: .value("Seconds from first packet", b.second), y: .value("Bytes", b.bytes))
                            .foregroundStyle(PS.teal)
                    }
                    ForEach(model.context?.markers ?? []) { m in
                        if let first = facts.firstTimestamp {
                            RuleMark(x: .value("Marker", Int(m.timestamp - first))).foregroundStyle(PS.amber).lineStyle(StrokeStyle(lineWidth: 2))
                        }
                    }
                }.frame(height: 260).psCard()
                VStack(alignment: .leading, spacing: 8) {
                    Text("Marked moments").font(.system(size: 15, weight: .semibold))
                    if (model.context?.markers ?? []).isEmpty { Text("No markers in this session. Markers can only be added while capturing.").font(.system(size: 12)).foregroundColor(PS.secondary) }
                    ForEach(model.context?.markers ?? []) { m in
                        HStack {
                            Image(systemName: "mappin.circle.fill").foregroundColor(PS.amber)
                            Text(ReportText.fmtTime(m.timestamp)).psMonospaced()
                            if let first = facts.firstTimestamp { Text(String(format: "(%+.1f s from first packet)", m.timestamp - first)).psMonospaced().foregroundColor(PS.secondary) }
                            Text(m.note).font(.system(size: 12)).foregroundColor(PS.secondary)
                        }
                    }
                    Text("Markers can fall outside the observed packet span when the capture contains quiet time.").font(.system(size: 11)).foregroundColor(PS.secondary)
                }.psCard().frame(maxWidth: .infinity, alignment: .leading)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Bucket evidence (packets · bytes · DNS errors · TCP resets)").font(.system(size: 12, weight: .semibold)).foregroundColor(PS.secondary)
                    ForEach(facts.timeline.prefix(30)) { b in
                        Text("+\(b.second)s — \(b.packets) pkts · \(b.bytes) B · \(b.dnsErrors) DNS err · \(b.tcpResets) RST").psMonospaced().foregroundColor(PS.secondary)
                    }
                }.psCard().frame(maxWidth: .infinity, alignment: .leading)
            } else { emptyState("No timeline yet. Buckets are built from the full capture file after analysis.") }
        }
    }
}

// MARK: - Apps

struct AppsView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Apps").font(.system(size: 28, weight: .semibold))
            Text("Process identity comes only from PKTAP metadata actually present in capture records — never inferred from an address, port, domain, or the app that happens to be open. Missing identity is grouped as Unknown, which is not automatically suspicious. Ordinary PCAP files without metadata are entirely Unknown.")
                .font(.system(size: 11)).foregroundColor(PS.secondary)
            if let facts = model.report?.facts, !facts.applications.isEmpty {
                Text("Attributed: \(facts.attributedPackets) packets · Unknown: \(facts.unattributedPackets) packets").psMonospaced().foregroundColor(PS.secondary)
                ForEach(facts.applications) { a in
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 4) {
                            if a.destinations.isEmpty {
                                Text("No observed peer destinations recorded for this group (peer is only shown when packet direction is known).").font(.system(size: 11)).foregroundColor(PS.secondary)
                            } else {
                                ForEach(a.destinations.prefix(64), id: \.self) { d in Text(d).font(.system(size: 11, design: .monospaced)).foregroundColor(PS.secondary) }
                                if a.destinations.count >= 64 { Text("Destination list capped at 64.").font(.system(size: 11)).foregroundColor(PS.amber) }
                            }
                            HStack(spacing: 6) {
                                Text("Packets:").font(.system(size: 11)).foregroundColor(PS.secondary)
                                ForEach(a.packetNumbers.prefix(12), id: \.self) { n in Button("#\(n)") { model.openPacketLog(number: n) }.font(.system(size: 11, design: .monospaced)).foregroundColor(PS.teal) }
                            }
                        }.padding(.top, 6)
                    } label: {
                        HStack(spacing: 10) {
                            appIcon(a.name)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(a.name + (a.processID.map { " (PID \($0))" } ?? "")).font(.system(size: 13, weight: .semibold))
                                Text(sentReceived(a)).font(.system(size: 11)).foregroundColor(PS.secondary)
                            }
                            Spacer()
                            Text("\(a.packets) pkts · \(a.bytes) B").psMonospaced().foregroundColor(PS.secondary)
                        }
                    }.padding(14).background(PS.panel).clipShape(RoundedRectangle(cornerRadius: 12)).overlay(RoundedRectangle(cornerRadius: 12).stroke(PS.border))
                }
                Text("Process names can be shortened, helpers can act on behalf of apps, and PIDs can differ across sessions. Up to 2,000 distinct process identities are kept, plus an Unknown overflow group.").font(.system(size: 11)).foregroundColor(PS.secondary)
            } else { emptyState("No process data. Capture with PKTAP attribution on this Mac, or reopen a PKTAP capture, to see per-app traffic.") }
        }
    }
    private func sentReceived(_ a: AppTraffic) -> String {
        if a.sentBytes == 0 && a.receivedBytes == 0 { return "\(a.bytes) bytes · direction unknown for these records (zero directional bytes does not prove no activity)" }
        return "\(a.bytes) bytes · \(a.sentBytes) sent · \(a.receivedBytes) received"
    }
    @ViewBuilder private func appIcon(_ name: String) -> some View {
        if let img = iconImage(name) { Image(nsImage: img).resizable().frame(width: 26, height: 26) }
        else { Image(systemName: "app.dashed").font(.system(size: 22)).foregroundColor(PS.secondary).frame(width: 26, height: 26) }
    }
    private func iconImage(_ name: String) -> NSImage? {
        // Local resolution only, using the process name as an app name hint.
        for app in NSWorkspace.shared.runningApplications where app.localizedName == name {
            if let icon = app.icon { return icon }
        }
        return nil
    }
}

// MARK: - Compare

struct CompareView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Compare").font(.system(size: 28, weight: .semibold))
            Text("Make one change, then run the same check again. A before/after difference cannot establish causation or confirm a fix, and captured volume is not a speed test.")
                .font(.system(size: 12)).foregroundColor(PS.secondary)
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Baseline:").font(.system(size: 13, weight: .semibold))
                    if let b = model.baseline {
                        Text("\(b.date.formatted()) · \(b.report.packetCount) packets · \(b.context.goal.title)").font(.system(size: 12)).foregroundColor(PS.secondary)
                    } else { Text("none selected").font(.system(size: 12)).foregroundColor(PS.secondary) }
                }
                HStack {
                    Button("Use current as baseline") { model.useCurrentAsBaseline() }.disabled(model.report == nil || model.isCapturing)
                    Menu("Choose from history") {
                        ForEach(model.sessions) { s in Button("\(s.date.formatted()) · \(s.report.packetCount) pkts · \(s.context.goal.title)") { model.chooseBaseline(s) } }
                    }.disabled(model.sessions.isEmpty)
                    Button("Clear") { model.clearBaseline() }.disabled(model.baseline == nil)
                }.font(.system(size: 12))
                Text("What changed? (saved with the next capture)").font(.system(size: 11, weight: .semibold)).foregroundColor(PS.secondary)
                TextField("e.g. switched from Wi-Fi A to Wi-Fi B", text: $model.changeNoteDraft).textFieldStyle(.roundedBorder).disabled(model.isCapturing)
                Button { model.repeatCapture() } label: { Label("Run the same check again", systemImage: "arrow.clockwise") }
                    .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black)
                    .disabled(model.baseline == nil || model.state.isBusy || model.isCapturing)
                Text("This preserves the baseline, restores its goal, symptom, and interface when still available, and starts a real new capture using the current duration selection. A baseline is an in-memory choice in this version.")
                    .font(.system(size: 11)).foregroundColor(PS.secondary)
            }.psCard().frame(maxWidth: .infinity, alignment: .leading)
            if let cmp = model.comparison {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Baseline vs current").font(.system(size: 16, weight: .semibold))
                    ForEach(cmp.metrics) { m in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(m.name).font(.system(size: 13, weight: .medium))
                                Text(m.note).font(.system(size: 10)).foregroundColor(PS.secondary)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 2) {
                                Text("Baseline: \(m.baselineText)").psMonospaced()
                                Text("Current: \(m.currentText)").psMonospaced().foregroundColor(PS.teal)
                            }
                        }
                        Divider().background(PS.border)
                    }
                    ForEach(cmp.warnings, id: \.self) { w in
                        HStack(alignment: .top, spacing: 6) { Image(systemName: "exclamationmark.triangle").foregroundColor(PS.amber); Text(w).font(.system(size: 11)) }
                    }
                }.psCard().frame(maxWidth: .infinity, alignment: .leading)
            } else {
                emptyState("No comparison yet. Load or capture a session, set it as baseline, make one change, and run the same check again.")
            }
            SessionHistoryView(compact: false)
        }
    }
}

// MARK: - History

struct SessionHistoryView: View {
    @EnvironmentObject var model: AppModel
    var compact: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if !compact { Text("Session history").font(.system(size: 16, weight: .semibold)) }
            if model.sessions.isEmpty {
                Text("No saved sessions yet.").font(.system(size: 11)).foregroundColor(PS.secondary)
            } else {
                ForEach(model.sessions.prefix(compact ? 8 : 50)) { s in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(s.date.formatted(date: .abbreviated, time: .shortened)).font(.system(size: 11, weight: .medium))
                            if let b = model.baseline, b.directory == s.directory { Text("BASELINE").font(.system(size: 8, weight: .bold)).foregroundColor(.black).padding(.horizontal, 5).padding(.vertical, 2).background(PS.amber).clipShape(Capsule()) }
                        }
                        Text("\(s.context.goal.title) · \(s.report.packetCount) pkts · \(s.report.capturedBytes) B").font(.system(size: 10)).foregroundColor(PS.secondary)
                        Text("Interface \(s.context.interface.isEmpty ? "unknown" : s.context.interface) · \(s.context.markers.count) marker(s)\(s.dropped > 0 ? " · \(s.dropped) dropped" : "")").font(.system(size: 10)).foregroundColor(PS.secondary)
                        HStack(spacing: 8) {
                            Button("Open") { model.openSession(s) }.font(.system(size: 10))
                            Button("Set as baseline") { model.chooseBaseline(s) }.font(.system(size: 10))
                        }
                    }
                    .padding(9).background(PS.panel).clipShape(RoundedRectangle(cornerRadius: 9)).overlay(RoundedRectangle(cornerRadius: 9).stroke(PS.border))
                }
                if compact && model.sessions.count > 8 { Text("…and \(model.sessions.count - 8) more in Compare.").font(.system(size: 10)).foregroundColor(PS.secondary) }
                Text("Latest 50 readable saved sessions are listed.").font(.system(size: 9)).foregroundColor(PS.secondary)
            }
        }
    }
}

// MARK: - Ask capture

struct AskView: View {
    @EnvironmentObject var model: AppModel
    @State private var draft = ""
    static let suggestions = ["Why was this flagged?", "What should I check first?", "What happened near my marked moments?", "Which apps were communicating?", "What changed between captures?"]
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Ask capture").font(.system(size: 28, weight: .semibold))
            Toggle(isOn: $model.useAI) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Use on-device AI when available").font(.system(size: 13))
                    Text(model.useAI ? "On-device model: \(model.aiAvailability). Factual app, marker, and comparison answers always come from measured data." : "Off: the local rules guide answers everything. Nothing leaves this Mac either way.")
                        .font(.system(size: 11)).foregroundColor(PS.secondary)
                }
            }.toggleStyle(.switch)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    if model.chatMessages.isEmpty {
                        Text("Ask about this capture. Answers are based only on measured evidence in the loaded session; unsupported questions are explained rather than guessed. Each question is sent with the current capture only — earlier chat is not used as model memory.")
                            .font(.system(size: 12)).foregroundColor(PS.secondary)
                    }
                    ForEach(model.chatMessages) { m in
                        VStack(alignment: .leading, spacing: 5) {
                            Text(m.role == "user" ? "You" : m.source).font(.system(size: 10, weight: .semibold)).foregroundColor(m.role == "user" ? PS.blue : PS.teal)
                            Text(m.text).font(.system(size: 12.5)).textSelection(.enabled)
                            if !m.packetNumbers.isEmpty {
                                HStack(spacing: 6) {
                                    ForEach(m.packetNumbers, id: \.self) { n in Button("#\(n)") { model.openPacketLog(number: n) }.font(.system(size: 11, design: .monospaced)).foregroundColor(PS.teal) }
                                }
                            }
                        }
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(m.role == "user" ? PS.elevated : PS.panel)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(PS.border))
                    }
                    if model.chatBusy {
                        HStack(spacing: 8) { ProgressView().scaleEffect(0.7); Text("Working from the capture evidence…").font(.system(size: 12)).foregroundColor(PS.secondary); Button("Cancel") { model.cancelChat() }.font(.system(size: 11)) }
                    }
                }
            }.frame(maxHeight: 430)
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    ForEach(Self.suggestions, id: \.self) { s in
                        Button(s) { model.ask(s) }.font(.system(size: 10)).buttonStyle(.bordered).disabled(model.chatBusy)
                    }
                }
                HStack {
                    TextField("Ask about this capture…", text: $draft).textFieldStyle(.roundedBorder)
                        .onSubmit { submit() }
                    Button("Ask") { submit() }.buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black).disabled(model.chatBusy || draft.trimmingCharacters(in: .whitespaces).isEmpty)
                    Button("Clear") { model.clearConversation() }.disabled(model.chatMessages.isEmpty && !model.chatBusy)
                }
            }
        }
        .onDisappear { /* session switches clear chat in AppModel; leaving the tab keeps it */ }
    }
    private func submit() { let q = draft; draft = ""; model.ask(q) }
}

// MARK: - Support sheet

struct SupportSheetView: View {
    @EnvironmentObject var model: AppModel
    @State private var options = SupportOptions()
    @Environment(\.dismiss) private var dismiss
    private var preview: String {
        guard let rep = model.report, let ctx = model.context else { return "No capture loaded." }
        return ReportText.supportReport(report: rep, context: ctx, options: options, comparison: model.comparison, threatIntel: model.threatIntel)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Share with support").font(.system(size: 20, weight: .semibold))
            Text("Plain-text preview generated from structured facts. No raw payloads and no PCAP are included. This is selective redaction, not guaranteed anonymization — review the preview, especially any free-text notes you opt in.")
                .font(.system(size: 11)).foregroundColor(PS.secondary)
            HStack(spacing: 18) {
                Toggle("IP addresses", isOn: $options.includeIPs)
                Toggle("Domain names", isOn: $options.includeDomains)
                Toggle("App / process names", isOn: $options.includeApps)
                Toggle("Your notes & symptoms", isOn: $options.includeNotes)
            }.font(.system(size: 12)).toggleStyle(.switch)
            Text("Identifiers are redacted across the whole report according to these controls, even inside notes you choose to include. Turning notes on does not turn addresses or domains on.")
                .font(.system(size: 11)).foregroundColor(PS.amber)
            ScrollView { Text(preview).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                .padding(12).background(PS.panel).clipShape(RoundedRectangle(cornerRadius: 10)).overlay(RoundedRectangle(cornerRadius: 10).stroke(PS.border))
            HStack {
                Button("Save support report…") { model.exportSupportReport(options: options) }
                    .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black)
                Button("Export raw capture…") { model.exportRawCapture() }
                    .help("Copies the original PCAP unchanged, with all addresses, metadata, DNS names, and possible unencrypted payloads.")
                Spacer()
                Button("Done") { dismiss() }
            }.font(.system(size: 12))
            Text("PacketScope does not email or upload anything.").font(.system(size: 11)).foregroundColor(PS.secondary)
        }
        .padding(24).frame(minWidth: 760, minHeight: 620)
        .background(PS.background).foregroundColor(PS.primary)
    }
}

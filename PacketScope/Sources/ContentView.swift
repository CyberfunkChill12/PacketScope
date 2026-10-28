import SwiftUI
import AppKit
import UniformTypeIdentifiers

public enum PS {
    public static let background = Color(.sRGB, red: 0.035, green: 0.052, blue: 0.085)
    public static let sidebar = Color(.sRGB, red: 0.055, green: 0.078, blue: 0.115)
    public static let panel = Color(.sRGB, red: 0.075, green: 0.101, blue: 0.145)
    public static let elevated = Color(.sRGB, red: 0.101, green: 0.133, blue: 0.181)
    public static let primary = Color(.sRGB, red: 0.930, green: 0.960, blue: 0.990)
    public static let secondary = Color(.sRGB, red: 0.610, green: 0.690, blue: 0.780)
    public static let teal = Color(.sRGB, red: 0.280, green: 0.880, blue: 0.770)
    public static let amber = Color(.sRGB, red: 1.000, green: 0.740, blue: 0.380)
    public static let red = Color(.sRGB, red: 1.000, green: 0.450, blue: 0.490)
    public static let blue = Color(.sRGB, red: 0.420, green: 0.690, blue: 1.000)
    public static let border = Color.white.opacity(0.085)
}

extension View {
    func psCard() -> some View {
        self.padding(20).background(PS.panel).clipShape(RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(PS.border, lineWidth: 1))
    }
    func psMonospaced() -> some View { self.font(.system(.caption, design: .monospaced)) }
}

public struct ContentView: View {
    @EnvironmentObject var model: AppModel
    public init() {}
    public var body: some View {
        HStack(spacing: 0) {
            sidebar.frame(width: 242)
            VStack(spacing: 0) {
                header
                Divider().background(PS.border)
                ScrollViewReader { proxy in
                    ScrollView {
                        Group {
                            switch model.section {
                            case .overview: OverviewView()
                            case .timeline: TimelineView()
                            case .apps: AppsView()
                            case .compare: CompareView()
                            case .ask: AskView()
                            case .packets: PacketLogView()
                            case .endpoints: EndpointsView()
                            case .feeds: ThreatFeedSettingsView()
                            }
                        }
                        .padding(.horizontal, 28).padding(.vertical, 22)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .onChange(of: model.resultsAnchor) { anchor in
                        guard let anchor = anchor else { return }
                        withAnimation { proxy.scrollTo(anchor, anchor: .top) }
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { model.resultsAnchor = nil }
                    }
                }
            }
        }
        .background(PS.background)
        .foregroundColor(PS.primary)
        .sheet(isPresented: $model.showSupportSheet) { SupportSheetView() }
    }

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(model.section.rawValue).font(.system(size: 20, weight: .semibold))
                Text(model.state.label).font(.system(size: 11)).foregroundColor(stateColor)
            }
            Spacer()
            if model.report != nil {
                Button("Share with support") { model.showSupportSheet = true }
                    .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black)
            }
            Button { model.revealSessionFiles() } label: { Label("Session files", systemImage: "folder") }
                .help("Reveal session files in Finder")
        }
        .padding(.horizontal, 28).padding(.vertical, 14)
        .background(PS.background)
    }
    private var stateColor: Color {
        switch model.state {
        case .capturing: return PS.teal
        case .failed: return PS.red
        case .authorizing, .stopping, .analyzing: return PS.amber
        default: return PS.secondary
        }
    }

    private var sidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    Image(systemName: "waveform.path.ecg").font(.system(size: 22)).foregroundColor(PS.teal)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("PacketScope").font(.system(size: 17, weight: .semibold))
                        Text("NETWORK OBSERVATORY").font(.system(size: 8, weight: .semibold)).foregroundColor(PS.secondary).tracking(1.2)
                    }
                }
                .padding(.top, 26)
                VStack(spacing: 4) {
                    ForEach(AppSection.allCases) { s in
                        Button { model.section = s } label: {
                            HStack { Image(systemName: s.symbol).frame(width: 20); Text(s.rawValue).font(.system(size: 13)); Spacer() }
                                .padding(.horizontal, 10).padding(.vertical, 8)
                                .background(model.section == s ? PS.elevated : Color.clear)
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                        }.buttonStyle(.plain).foregroundColor(model.section == s ? PS.primary : PS.secondary)
                    }
                }
                Divider().background(PS.border)
                Text("Session history").font(.system(size: 11, weight: .semibold)).foregroundColor(PS.secondary)
                SessionHistoryView(compact: true)
                Spacer(minLength: 20)
            }
            .padding(.horizontal, 16)
        }
        .background(PS.sidebar)
    }
}

// MARK: - Scan (setup + in-page Results tab)

struct OverviewView: View {
    @EnvironmentObject var model: AppModel
    @State private var dropTargeted = false
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            // In-page tabs within the Scan section.
            Picker("", selection: $model.scanPage) {
                ForEach(ScanPage.allCases) { page in Text(page.rawValue).tag(page) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 340)

            if model.scanPage == .results {
                ResultsPageView()
            } else {
                scanSetupPage
            }
        }
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(dropTargeted ? PS.teal : Color.clear, lineWidth: 2)
                .padding(2)
        )
        .onDrop(of: [UTType.fileURL], isTargeted: $dropTargeted) { providers in
            guard let provider = providers.first(where: { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) }) else { return false }
            provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
                let url: URL?
                if let data = item as? Data { url = URL(dataRepresentation: data, relativeTo: nil) }
                else if let u = item as? URL { url = u }
                else { url = nil }
                guard let fileURL = url else { return }
                DispatchQueue.main.async { model.importUserLogFile(fileURL) }
            }
            return true
        }
    }

    private var scanSetupPage: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Start capture leads the page, with its options centered.
            Text("Start capture")
                .font(.system(size: 28, weight: .semibold))
                .frame(maxWidth: .infinity, alignment: .center)
                .multilineTextAlignment(.center)
            CaptureControlsView()
            Text("What are you troubleshooting?")
                .font(.system(size: 22, weight: .semibold))
                .frame(maxWidth: .infinity, alignment: .center)
                .multilineTextAlignment(.center)
            GuidedSetupView()
            if let msg = model.errorMessage {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundColor(PS.amber)
                    Text(msg).font(.system(size: 12))
                    Spacer()
                    Button("Dismiss") { model.errorMessage = nil }.font(.system(size: 11))
                }.psCard()
            }
            switch model.state {
            case .authorizing:
                notice(icon: "lock.shield", color: PS.amber, title: "Waiting for administrator authorization", text: "macOS is asking for approval outside PacketScope. PacketScope never sees or stores your password. Cancel there to return here unchanged.")
            case .capturing, .stopping:
                liveCard
            case .analyzing:
                notice(icon: "waveform.path", color: PS.amber, title: "Analyzing the capture…", text: "Counting every packet in the file and building your results. Large captures can take a moment.")
            case .failed(let m):
                notice(icon: "xmark.octagon", color: PS.red, title: "Something went wrong", text: m + " Any saved capture data was kept and can be reopened from session history.")
            default:
                if model.report != nil {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Your latest capture is ready.").font(.system(size: 15, weight: .semibold))
                        Button("View Results") { model.scanPage = .results }
                            .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black)
                    }.psCard().frame(maxWidth: .infinity, alignment: .leading)
                } else { emptyCard }
            }
        }
    }

    private var emptyCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Image(systemName: "waveform.path.ecg").font(.system(size: 28)).foregroundColor(PS.teal)
            Text("No capture yet").font(.system(size: 17, weight: .semibold))
            Text("Choose an interface under Start capture, press the Start capture button, and reproduce the problem while it runs. Pick a goal below to save what you were troubleshooting with the session. Or open an existing classic PCAP file — no administrator authorization is needed for that.").font(.system(size: 12)).foregroundColor(PS.secondary)
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }
    private var liveCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack { Image(systemName: "record.circle.fill").foregroundColor(PS.red); Text("Capturing on \(model.selectedInterface)").font(.system(size: 16, weight: .semibold)) }
            HStack(spacing: 22) {
                metric("Packets", "\(model.liveStatus?.packets ?? 0)")
                metric("Captured bytes", "\(model.liveStatus?.bytes ?? 0)")
                metric("Elapsed", String(format: "%.0f s", model.liveStatus?.elapsed ?? 0))
                metric("Interface", model.selectedInterface)
                metric("Process attribution", model.attributionAvailable ? "PKTAP on" : "Unknown (unavailable or off)")
            }
            Text("Now reproduce the problem. Use “It happened just now” above the moment it occurs — markers are saved immediately. A marker records when you noticed a problem; it is not proof of a network fault.")
                .font(.system(size: 12)).foregroundColor(PS.secondary)
            Text("Markers saved: \(model.context?.markers.count ?? 0) of 50").psMonospaced().foregroundColor(PS.amber)
            Text("When you stop, your results will open here in the Results tab.").font(.system(size: 12)).foregroundColor(PS.teal)
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }
    private func metric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label.uppercased()).font(.system(size: 9, weight: .semibold)).foregroundColor(PS.secondary)
            Text(value).psMonospaced().font(.system(size: 14, weight: .medium))
        }
    }
    private func notice(icon: String, color: Color, title: String, text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).foregroundColor(color).font(.system(size: 20))
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 15, weight: .semibold))
                Text(text).font(.system(size: 12)).foregroundColor(PS.secondary)
            }
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }
}

// Capture buttons and options at the top of the Capture page, centered.
struct CaptureControlsView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(alignment: .center, spacing: 18) {
            // Options, centered.
            HStack(alignment: .top, spacing: 28) {
                VStack(alignment: .center, spacing: 8) {
                    HStack {
                        Text("Network interface").font(.system(size: 12, weight: .semibold)).foregroundColor(PS.secondary)
                        Button { model.refreshInterfaces() } label: { Image(systemName: "arrow.clockwise") }.buttonStyle(.plain).help("Refresh interfaces")
                    }
                    Picker("", selection: $model.selectedInterface) {
                        ForEach(model.interfaces) { i in Text(i.description.isEmpty ? i.name : "\(i.name) — \(i.description)").tag(i.name) }
                    }.labelsHidden().frame(minWidth: 260).disabled(model.isCapturing || model.state.isBusy)
                }
                VStack(alignment: .center, spacing: 8) {
                    Text("Capture duration").font(.system(size: 12, weight: .semibold)).foregroundColor(PS.secondary)
                    Picker("", selection: $model.durationChoice) { ForEach(DurationChoice.allCases) { d in Text(d.rawValue).tag(d) } }
                        .labelsHidden().frame(minWidth: 220).disabled(model.isCapturing || model.state.isBusy)
                }
            }
            Text("Capture shows traffic visible to the selected interface — usually this Mac’s traffic, not the whole network. Manual capture still stops at 15 minutes or 100 MiB, whichever comes first.")
                .font(.system(size: 11)).foregroundColor(PS.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 620)
            // Large, prominent action buttons, centered.
            if model.isCapturing {
                HStack(spacing: 16) {
                    Button { model.stopCapture() } label: {
                        Label("Stop & analyze", systemImage: "stop.circle.fill")
                            .font(.system(size: 17, weight: .bold))
                            .frame(minWidth: 250, minHeight: 56)
                    }
                    .buttonStyle(.borderedProminent).tint(PS.red).controlSize(.large)
                    Button { model.addMarker() } label: {
                        Label("It happened just now", systemImage: "mappin.and.ellipse")
                            .font(.system(size: 17, weight: .bold))
                            .frame(minWidth: 250, minHeight: 56)
                    }
                    .buttonStyle(.borderedProminent).tint(PS.amber).foregroundColor(.black).controlSize(.large)
                }
            } else {
                HStack(spacing: 16) {
                    Button { model.startCapture() } label: {
                        Label("Start capture", systemImage: "record.circle.fill")
                            .font(.system(size: 18, weight: .bold))
                            .frame(minWidth: 270, minHeight: 58)
                    }
                    .buttonStyle(.borderedProminent).tint(PS.teal).foregroundColor(.black).controlSize(.large)
                    .disabled(model.state.isBusy || model.selectedInterface.isEmpty)
                    Button { model.presentOpenPanel() } label: {
                        Label("Import log file", systemImage: "square.and.arrow.down")
                            .font(.system(size: 16, weight: .semibold))
                            .frame(minWidth: 210, minHeight: 58)
                    }
                    .buttonStyle(.bordered).controlSize(.large)
                    .disabled(model.state.isBusy)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .center)
        .psCard()
    }
}

// MARK: - Packet log

struct PacketLogView: View {
    @EnvironmentObject var model: AppModel
    var filtered: [PacketRecord] {
        guard let packets = model.report?.packets else { return [] }
        let q = model.packetSearch.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return packets }
        if q.hasPrefix("#"), let n = Int(q.dropFirst()) { return packets.filter { $0.id == n } }
        // Evidence display filters copied from the Results page (subset).
        if q.contains("ip.addr==") {
            let ip = q.components(separatedBy: "ip.addr==").last?.split(whereSeparator: { $0 == " " || $0 == "&" }).first.map(String.init) ?? ""
            var rows = packets.filter { $0.source == ip || $0.destination == ip }
            if q.contains("tcp.port=="), let portText = q.components(separatedBy: "tcp.port==").last?.split(whereSeparator: { !$0.isNumber }).first, let port = Int(portText) {
                rows = rows.filter { $0.sourcePort == port || $0.destinationPort == port }
            }
            if q.contains("udp.port=="), let portText = q.components(separatedBy: "udp.port==").last?.split(whereSeparator: { !$0.isNumber }).first, let port = Int(portText) {
                rows = rows.filter { $0.sourcePort == port || $0.destinationPort == port }
            }
            return rows
        }
        if q.hasPrefix("dns") { return packets.filter { $0.protocolName == "DNS" || $0.protocolName == "mDNS" } }
        if q.hasPrefix("tcp.flags") { return packets.filter { $0.summary.lowercased().contains("rst") || $0.summary.lowercased().contains("[syn") || $0.protocolName == "TCP" } }
        return packets.filter { p in
            p.source.lowercased().contains(q) || p.destination.lowercased().contains(q) || p.protocolName.lowercased().contains(q)
                || (p.processName?.lowercased().contains(q) ?? false) || (p.hostname?.lowercased().contains(q) ?? false) || "#\(p.id)".contains(q)
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Packet log").font(.system(size: 28, weight: .semibold))
            if let report = model.report {
                Text("Showing \(filtered.count) of \(report.packets.count) retained rows (first \(PacketAnalyzer.displayLimit) of \(report.packetCount) packets). Statistics cover the entire file. Raw payload contents are never shown.")
                    .font(.system(size: 11)).foregroundColor(PS.secondary)
                TextField("Search address, protocol, process, hostname, or #number", text: $model.packetSearch)
                    .textFieldStyle(.roundedBorder)
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(filtered) { p in
                            HStack(alignment: .top, spacing: 10) {
                                Text("#\(p.id)").psMonospaced().foregroundColor(PS.teal).frame(width: 52, alignment: .leading)
                                Text(relTime(p)).psMonospaced().foregroundColor(PS.secondary).frame(width: 74, alignment: .leading)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("\(endpoint(p.source, p.sourcePort)) → \(endpoint(p.destination, p.destinationPort))").font(.system(size: 12, design: .monospaced))
                                    Text(p.summary).font(.system(size: 11)).foregroundColor(PS.secondary)
                                    if let h = p.hostname { Text(h).font(.system(size: 10)).foregroundColor(PS.blue) }
                                }
                                Spacer()
                                VStack(alignment: .trailing, spacing: 2) {
                                    Text(p.protocolName).font(.system(size: 11, weight: .semibold))
                                    Text("\(p.length) B").psMonospaced().foregroundColor(PS.secondary)
                                    if let pn = p.processName { Text("\(pn)\(p.processID.map { " (\($0))" } ?? "")").font(.system(size: 10)).foregroundColor(PS.secondary) }
                                }
                            }.padding(10).background(PS.panel).clipShape(RoundedRectangle(cornerRadius: 8)).overlay(RoundedRectangle(cornerRadius: 8).stroke(PS.border))
                        }
                        if filtered.isEmpty { Text("No retained rows match this search.").foregroundColor(PS.secondary).font(.system(size: 12)) }
                    }
                }.frame(maxHeight: 560)
            } else { emptyState("No capture loaded. Start a capture or open a PCAP file to inspect packets.") }
        }
    }
    private func relTime(_ p: PacketRecord) -> String {
        guard let first = model.report?.facts?.firstTimestamp else { return "—" }
        return String(format: "+%.3f s", p.timestamp - first)
    }
    private func endpoint(_ a: String, _ port: Int?) -> String { port.map { "\(a):\($0)" } ?? a }
}

func emptyState(_ text: String) -> some View {
    VStack(alignment: .leading, spacing: 8) {
        Image(systemName: "tray").font(.system(size: 24)).foregroundColor(PS.secondary)
        Text(text).font(.system(size: 12)).foregroundColor(PS.secondary)
    }.psCard().frame(maxWidth: .infinity, alignment: .leading)
}

// MARK: - Endpoints

struct EndpointsView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Endpoints").font(.system(size: 28, weight: .semibold))
            if let report = model.report {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Protocol mix").font(.system(size: 16, weight: .semibold))
                    ForEach(report.protocols) { p in
                        HStack { Text(p.name).font(.system(size: 12, weight: .medium)); Spacer(); Text("\(p.count) packets · \(p.bytes) bytes").psMonospaced().foregroundColor(PS.secondary) }
                    }
                }.psCard().frame(maxWidth: .infinity, alignment: .leading)
                VStack(alignment: .leading, spacing: 10) {
                    Text("Endpoints by captured bytes").font(.system(size: 16, weight: .semibold))
                    Text("Addresses are shown exactly as captured. No reverse-DNS or external lookup is performed.").font(.system(size: 11)).foregroundColor(PS.secondary)
                    ForEach(report.endpoints.prefix(50)) { e in
                        HStack { Text(e.address).font(.system(size: 12, design: .monospaced)); Spacer(); Text("\(e.packets) packets · \(e.bytes) bytes").psMonospaced().foregroundColor(PS.secondary) }
                    }
                }.psCard().frame(maxWidth: .infinity, alignment: .leading)
                if let facts = report.facts, !facts.domains.isEmpty {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Observed DNS names").font(.system(size: 16, weight: .semibold))
                        Text("Only names and A/AAAA addresses decoded from visible DNS. Encrypted DNS, cached lookups, and absent queries leave gaps; an observed name does not establish a website visit or the destination’s owner. Showing \(min(100, facts.domains.count)) of \(facts.domains.count).")
                            .font(.system(size: 11)).foregroundColor(PS.secondary)
                        ForEach(facts.domains.prefix(100)) { d in
                            HStack(alignment: .top) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(d.name).font(.system(size: 12, design: .monospaced))
                                    if !d.addresses.isEmpty { Text(d.addresses.joined(separator: ", ")).font(.system(size: 10)).foregroundColor(PS.secondary) }
                                }
                                Spacer()
                                Text("\(d.queryCount) queries · \(d.errorCount) errors").psMonospaced().foregroundColor(PS.secondary)
                            }
                        }
                    }.psCard().frame(maxWidth: .infinity, alignment: .leading)
                }
            } else { emptyState("No capture loaded. Endpoints and protocol mix appear here after analysis.") }
        }
    }
}

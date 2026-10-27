import Foundation
import AppKit

public struct InterfaceInfo: Codable, Identifiable, Equatable {
    public var id: String { name }
    public var name: String
    public var description: String
}

public struct HelperStatus: Codable, Equatable {
    public var state: String
    public var packets: Int
    public var bytes: Int
    public var elapsed: Double
    public var dropped: Int
    public var message: String
}

public struct SavedSession: Identifiable, Equatable {
    public var id: String { directory.path }
    public var directory: URL
    public var date: Date
    public var report: CaptureReport
    public var context: SessionContext
    public var dropped: Int
    public static func == (a: SavedSession, b: SavedSession) -> Bool { a.directory == b.directory && a.date == b.date && a.report.packetCount == b.report.packetCount }
}

public enum CaptureState: Equatable {
    case idle, authorizing, capturing, stopping, analyzing, complete, failed(String)
    public var label: String {
        switch self {
        case .idle: return "Ready"
        case .authorizing: return "Waiting for authorization…"
        case .capturing: return "Capturing"
        case .stopping: return "Stopping…"
        case .analyzing: return "Analyzing…"
        case .complete: return "Capture complete"
        case .failed(let m): return "Problem: \(m)"
        }
    }
    public var isBusy: Bool {
        switch self { case .authorizing, .stopping, .analyzing: return true; default: return false }
    }
}

public enum AppSection: String, CaseIterable, Identifiable {
    case overview = "Capture", timeline = "Timeline", apps = "Apps", compare = "Compare", ask = "Ask capture", packets = "Packet log", endpoints = "Endpoints", feeds = "Threat feeds"
    public var id: String { rawValue }
    public var symbol: String {
        switch self {
        case .overview: return "waveform.path.ecg"
        case .timeline: return "chart.bar.xaxis"
        case .apps: return "app.connected.to.app.below.fill"
        case .compare: return "arrow.left.arrow.right"
        case .ask: return "questionmark.bubble"
        case .packets: return "list.number"
        case .endpoints: return "point.3.connected.trianglepath.dotted"
        case .feeds: return "shield.lefthalf.filled"
        }
    }
}

public enum DurationChoice: String, CaseIterable, Identifiable {
    case s30 = "30 seconds", m1 = "1 minute", m2 = "2 minutes", m5 = "5 minutes", untilStopped = "Until I stop"
    public var id: String { rawValue }
    public var seconds: Int {
        switch self { case .s30: return 30; case .m1: return 60; case .m2: return 120; case .m5: return 300; case .untilStopped: return 900 }
    }
}

public enum ScanPage: String, CaseIterable, Identifiable {
    case setup = "Capture", results = "Results"
    public var id: String { rawValue }
}


/// Thread-safe holder for the preloaded indicator-store snapshot. Analysis
/// waits for it for at most 2 seconds and then proceeds without it.
public final class IntelSnapshotBox: @unchecked Sendable {
    public struct Snapshot {
        public var store: IndicatorStore
        public var feedRefs: [FeedRef]
        public var anyStored: Bool
        public var anyEnabled: Bool
    }
    private let lock = NSLock()
    private var value: Snapshot?
    private var loading = false
    public func get() -> Snapshot? { lock.lock(); defer { lock.unlock() }; return value }
    public func beginLoading() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if value != nil || loading { return false }
        loading = true; return true
    }
    public func set(_ snapshot: Snapshot) { lock.lock(); value = snapshot; loading = false; lock.unlock() }
    public func clear() { lock.lock(); value = nil; loading = false; lock.unlock() }
}

@MainActor
public final class AppModel: ObservableObject {
    public static let shared = AppModel()

    @Published public var state: CaptureState = .idle
    @Published public var section: AppSection = .overview
    @Published public var scanPage: ScanPage = .setup
    @Published public var interfaces: [InterfaceInfo] = []
    @Published public var selectedInterface: String = ""
    @Published public var durationChoice: DurationChoice = .m1
    @Published public var goal: CaptureGoal = .website
    @Published public var symptom: String = ""
    @Published public var changeNoteDraft: String = ""
    @Published public var report: CaptureReport?
    @Published public var context: SessionContext?
    @Published public var sessions: [SavedSession] = []
    @Published public var baseline: SavedSession?
    @Published public var baselineIsCurrent: Bool = false
    @Published public var currentSessionDir: URL?
    @Published public var liveStatus: HelperStatus?
    @Published public var attributionAvailable: Bool = false
    @Published public var errorMessage: String?
    @Published public var packetSearch: String = ""
    @Published public var chatMessages: [AssistantMessage] = []
    @Published public var chatBusy: Bool = false
    @Published public var useAI: Bool = true
    @Published public var aiAvailability: String = OnDeviceAI.availabilityDescription()
    @Published public var droppedPackets: Int = 0
    @Published public var showSupportSheet: Bool = false
    @Published public var threatIntel: ThreatIntelSummary?
    @Published public var allowlist: [AllowlistEntry] = []
    @Published public var customFeeds: [FeedMeta] = []
    @Published public var feedMessage: String?
    public let feedUpdater = FeedUpdater(directory: FeedUpdater.defaultDirectory, transport: URLSessionFeedTransport(), keyStore: KeychainKeyStore())
    public let intelBox = IntelSnapshotBox()
    /// Loads (once) the indicator store from the persisted per-feed indexes.
    public func preloadIntelStore(force: Bool = false) {
        if force { intelBox.clear() }
        guard intelBox.beginLoading() else { return }
        let updater = feedUpdater
        let customs = customFeeds
        let metas = allFeedMetas
        Task.detached(priority: .userInitiated) { [intelBox] in
            let loaded = updater.loadStore(now: Date(), extraMetas: customs)
            let refs: [FeedRef] = metas.compactMap { (meta) -> FeedRef? in
                let s = updater.state(for: meta)
                // "N threat feeds" counts only feeds that are on AND have data.
                guard s.enabled, updater.storedData(for: meta) != nil else { return nil }
                return FeedRef(id: meta.id, name: meta.name, updatedAt: s.lastSuccessAt, stale: s.isStale(meta: meta, now: Date().timeIntervalSince1970), indicatorCount: loaded.perFeed[meta.id]?.count ?? s.indicatorCount)
            }
            let snapshot = IntelSnapshotBox.Snapshot(store: loaded.store.snapshot(), feedRefs: refs,
                                                     anyStored: metas.contains { updater.storedData(for: $0) != nil },
                                                     anyEnabled: metas.contains { updater.state(for: $0).enabled })
            intelBox.set(snapshot)
        }
    }
    public func invalidateIntelSnapshot() { preloadIntelStore(force: true) }
    private func waitIntelSnapshot(timeoutSec: Double) async -> IntelSnapshotBox.Snapshot? {
        preloadIntelStore()
        let box = intelBox
        return await Task.detached {
            let deadline = Date().addingTimeInterval(timeoutSec)
            while Date() < deadline {
                if let v = box.get() { return v }
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
            return box.get()
        }.value
    }
    @Published public var resultsAnchor: String?

    private var helperProcess: Process?
    private var pollTask: Task<Void, Never>?
    private var chatTask: Task<Void, Never>?
    private var sessionToken = UUID()
    private var chatToken = UUID()
    public private(set) var currentSessionDropped: Int = 0

    public var isCapturing: Bool { state == .capturing }
    public var comparison: ComparisonResult? {
        guard let baselineReport = baseline?.report, let current = report, let bctx = baseline?.context, let cctx = context else { return nil }
        if let cur = currentSessionDir, let base = baseline, cur == base.directory { return nil } // never compare a session with itself
        return ComparisonEngine.compare(baseline: baselineReport, current: current, baselineContext: bctx, currentContext: cctx)
    }
    public var baselineForComparison: CaptureReport? { baseline?.report }

    // MARK: Paths

    public static var sessionsRoot: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("PacketScope/Sessions", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true, attributes: [FileAttributeKey.posixPermissions: 0o700])
        return base
    }
    public var helperURL: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/packetscope-capture")
    }

    public func onAppear() {
        refreshInterfaces()
        loadHistory()
        loadFeedPreferences()
        aiAvailability = OnDeviceAI.availabilityDescription()
        // Refresh stale feeds in the background; analysis never waits for this.
        feedUpdater.refreshInBackground(feeds: allFeedMetas.filter { feedUpdater.state(for: $0).enabled }, now: Date())
        preloadIntelStore()
    }
    public var allFeedMetas: [FeedMeta] { FeedRegistry.all + customFeeds }
    public func loadFeedPreferences() {
        let dir = feedUpdater.directory
        if let data = try? Data(contentsOf: dir.appendingPathComponent("allowlist.json")),
           let decoded = try? JSONDecoder().decode([AllowlistEntry].self, from: data) { allowlist = decoded }
        if let data = try? Data(contentsOf: dir.appendingPathComponent("custom-feeds.json")),
           let decoded = try? JSONDecoder().decode([FeedMeta].self, from: data) { customFeeds = decoded }
    }
    public func saveAllowlist() {
        if let data = try? JSONEncoder().encode(allowlist) {
            try? data.write(to: feedUpdater.directory.appendingPathComponent("allowlist.json"), options: [.atomic])
        }
    }
    public func saveCustomFeeds() {
        if let data = try? JSONEncoder().encode(customFeeds) {
            try? data.write(to: feedUpdater.directory.appendingPathComponent("custom-feeds.json"), options: [.atomic])
        }
    }
    public func addCustomFeed(_ meta: FeedMeta) {
        customFeeds.append(meta); saveCustomFeeds()
        if !meta.url.hasPrefix("file:") { Task { _ = await feedUpdater.update(feed: meta, now: Date(), manual: true) } }
    }

    // MARK: Interfaces

    public func refreshInterfaces() {
        let helper = helperURL
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            errorMessage = "The bundled capture helper was not found. Rebuild the app with scripts/build.sh."
            return
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let p = Process()
            p.executableURL = helper
            p.arguments = ["--interfaces"]
            let out = Pipe(); p.standardOutput = out; p.standardError = Pipe()
            do { try p.run() } catch {
                Task { @MainActor in self?.errorMessage = "Could not list interfaces: \(error.localizedDescription)" }
                return
            }
            let data = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            let decoded = (try? JSONDecoder().decode([InterfaceInfo].self, from: data)) ?? []
            Task { @MainActor in
                guard let self = self else { return }
                self.interfaces = decoded
                if self.selectedInterface.isEmpty || !decoded.contains(where: { $0.name == self.selectedInterface }) {
                    self.selectedInterface = decoded.first(where: { $0.name == "en0" })?.name ?? decoded.first(where: { $0.name == "lo0" })?.name ?? decoded.first?.name ?? ""
                }
            }
        }
    }

    // MARK: Capture lifecycle

    nonisolated static func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    nonisolated static func appleScriptQuote(_ s: String) -> String { s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") }

    public func newCapture() {
        clearConversation()
        sessionToken = UUID()
        report = nil; context = nil; currentSessionDir = nil; liveStatus = nil; droppedPackets = 0; threatIntel = nil
        state = .idle; section = .overview; scanPage = .setup; errorMessage = nil
    }

    public func startCapture() {
        guard !state.isBusy, state != .capturing else { return }
        scanPage = .setup
        guard interfaces.contains(where: { $0.name == selectedInterface }) else {
            errorMessage = "Choose an interface from the list (refresh if it is empty). PacketScope only captures on an enumerated interface."
            return
        }
        clearConversation()
        let token = UUID(); sessionToken = token
        errorMessage = nil
        // New session directory, mode 0700, never a symlink.
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let dir = Self.sessionsRoot.appendingPathComponent("\(stamp)_\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [FileAttributeKey.posixPermissions: 0o700])
            try FileManager.default.setAttributes([FileAttributeKey.posixPermissions: 0o700], ofItemAtPath: dir.path)
        } catch {
            state = .failed("Could not create a session directory: \(error.localizedDescription)")
            return
        }
        var ctx = SessionContext(goal: goal, symptom: symptom, interface: selectedInterface, startedAt: Date().timeIntervalSince1970, changeNote: baseline != nil ? changeNoteDraft : "")
        context = ctx
        currentSessionDir = dir
        saveContext(ctx, to: dir)
        droppedPackets = 0; attributionAvailable = false; liveStatus = nil

        let uid = getuid(), gid = getgid()
        let args: [String] = [
            helperURL.path,
            "--interface", selectedInterface,
            "--directory", dir.path,
            "--uid", String(uid), "--gid", String(gid),
            "--duration", String(durationChoice.seconds),
            "--max-bytes", String(100 * 1024 * 1024),
            "--watch-pid", String(ProcessInfo.processInfo.processIdentifier),
            "--attribution", "1",
        ]
        let shell = args.map(Self.shellQuote).joined(separator: " ")
        let script = "do shell script \"\(Self.appleScriptQuote(shell))\" with administrator privileges"

        state = .authorizing
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", script]
        let errPipe = Pipe(); p.standardError = errPipe; p.standardOutput = Pipe()
        helperProcess = p
        p.terminationHandler = { [weak self] proc in
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errText = String(data: errData, encoding: .utf8) ?? ""
            Task { @MainActor in
                guard let self = self, self.sessionToken == token else { return }
                self.helperProcess = nil
                self.pollTask?.cancel()
                if self.state == .authorizing {
                    // Authorization was cancelled or the helper never started.
                    self.state = .idle
                    self.errorMessage = errText.localizedCaseInsensitiveContains("cancel")
                        ? "Administrator authorization was cancelled. Nothing was captured; you can try again when ready."
                        : "The capture helper did not start. \(errText.trimmingCharacters(in: .whitespacesAndNewlines))"
                    return
                }
                // Helper finished: analyze whatever it flushed, if a PCAP exists.
                let pcap = dir.appendingPathComponent("traffic.pcap")
                if FileManager.default.fileExists(atPath: pcap.path) {
                    if let st = self.readStatus(in: dir) { self.droppedPackets = st.dropped; self.liveStatus = st }
                    self.analyzeSession(dir: dir, token: token)
                } else {
                    let msg = self.readStatus(in: dir)?.message ?? "The capture produced no data."
                    self.state = .failed(msg.isEmpty ? "The capture produced no data." : msg)
                }
            }
        }
        do {
            try p.run()
        } catch {
            state = .failed("Could not request administrator authorization: \(error.localizedDescription)")
            helperProcess = nil
            return
        }
        // Poll status.json ~every 0.5 s.
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 500_000_000)
                guard let self = self, self.sessionToken == token else { return }
                if let st = self.readStatus(in: dir) {
                    self.liveStatus = st
                    if st.state == "capturing" && self.state == .authorizing { self.state = .capturing }
                    if !st.message.isEmpty && st.message.contains("attribution") { self.attributionAvailable = false }
                    if st.message.contains("with PKTAP") { self.attributionAvailable = true }
                }
            }
        }
        _ = ctx
    }

    public func stopCapture() {
        guard state == .capturing || state == .authorizing, let dir = currentSessionDir else { return }
        state = .stopping
        // The helper validates ownership/type of this file before honouring it.
        let stopURL = dir.appendingPathComponent("stop.request")
        if !FileManager.default.fileExists(atPath: stopURL.path) {
            FileManager.default.createFile(atPath: stopURL.path, contents: Data("stop\n".utf8), attributes: [FileAttributeKey.posixPermissions: 0o600])
        }
    }

    public func addMarker() {
        guard state == .capturing, var ctx = context, let dir = currentSessionDir else { return }
        guard ctx.markers.count < 50 else { errorMessage = "This session already has 50 markers (the per-session cap)."; return }
        ctx.markers.append(ProblemMarker(timestamp: Date().timeIntervalSince1970))
        context = ctx
        saveContext(ctx, to: dir) // saved immediately, atomically
    }

    public func requestCleanupOnQuit() {
        pollTask?.cancel(); chatTask?.cancel()
        if state == .capturing || state == .authorizing { stopCapture() }
        helperProcess?.terminate()
    }

    // MARK: Analysis

    private func readStatus(in dir: URL) -> HelperStatus? {
        let url = dir.appendingPathComponent("status.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(HelperStatus.self, from: data)
    }

    private func saveContext(_ ctx: SessionContext, to dir: URL) {
        let url = dir.appendingPathComponent("context.json")
        if let data = try? JSONEncoder().encode(ctx) { try? data.write(to: url, options: [.atomic]) }
    }

    private func analyzeSession(dir: URL, token: UUID) {
        state = .analyzing
        Task { [weak self] in
            guard let self = self, self.sessionToken == token else { return }
            // One consistent snapshot for the whole analysis. If the store is
            // still loading after 2 seconds, proceed without it and say so.
            let cached = await self.waitIntelSnapshot(timeoutSec: 2)
            self.performAnalysis(dir: dir, token: token, cached: cached)
        }
    }

    private func performAnalysis(dir: URL, token: UUID, cached: IntelSnapshotBox.Snapshot?) {
        // Threat matching uses one consistent snapshot taken at analysis
        // start; a feed swap landing mid-analysis never changes it.
        let storeSnapshot = cached?.store ?? IndicatorStore()
        let feedRefs: [FeedRef] = cached?.feedRefs ?? []
        let anyEnabled = cached?.anyEnabled ?? true
        let anyStored = cached?.anyStored ?? false
        let storeTimedOut = cached == nil
        let metasDict = Dictionary(uniqueKeysWithValues: allFeedMetas.map { ($0.id, $0) })
        let allowSnapshot = allowlist
        feedUpdater.refreshInBackground(feeds: allFeedMetas.filter { feedUpdater.state(for: $0).enabled }, now: Date())
        let pcap = dir.appendingPathComponent("traffic.pcap")
        Task.detached(priority: .userInitiated) { [weak self] in
            let result: Result<CaptureReport, Error>
            do { result = .success(try PacketAnalyzer.analyze(url: pcap)) } catch { result = .failure(error) }
            await MainActor.run {
                guard let self = self, self.sessionToken == token else { return }
                switch result {
                case .success(let rep):
                    self.report = rep
                    var ctx = self.context ?? self.loadContext(from: dir) ?? SessionContext.unknownImported
                    ctx.endedAt = ctx.endedAt ?? Date().timeIntervalSince1970
                    if ctx.interface.isEmpty { ctx.interface = self.selectedInterface }
                    // Retain a saved marker/context that may have been reloaded from disk.
                    if let disk = self.loadContext(from: dir), disk.markers.count > ctx.markers.count { ctx.markers = disk.markers }
                    self.context = ctx
                    self.saveContext(ctx, to: dir)
                    self.saveReport(rep, ctx: ctx, to: dir)
                    let outcome = IntelMatcher.match(report: rep, store: storeSnapshot, metas: metasDict, allowlist: allowSnapshot, now: Date())
                    let status = storeTimedOut ? "loading" : (!anyEnabled ? "disabled" : (!anyStored ? "no_feeds" : "checked"))
                    self.threatIntel = ThreatIntelSummary.make(outcome: outcome, feeds: feedRefs, status: status)
                    self.scanPage = .results
                    self.currentSessionDropped = self.droppedPackets
                    self.state = .complete
                    self.loadHistory()
                case .failure(let err):
                    self.state = .failed(err.localizedDescription)
                    self.errorMessage = "Analysis failed: \(err.localizedDescription) The saved capture file was kept."
                }
            }
        }
    }

    private func saveReport(_ rep: CaptureReport, ctx: SessionContext, to dir: URL) {
        let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys]
        if let data = try? enc.encode(rep) {
            try? data.write(to: dir.appendingPathComponent("report.json"), options: [.atomic])
        }
        try? ReportText.plainReport(report: rep, context: ctx).write(to: dir.appendingPathComponent("report.txt"), atomically: true, encoding: .utf8)
    }

    private func loadContext(from dir: URL) -> SessionContext? {
        guard let data = try? Data(contentsOf: dir.appendingPathComponent("context.json")) else { return nil }
        return try? JSONDecoder().decode(SessionContext.self, from: data)
    }

    // MARK: Import & history

    /// Friendly pre-flight check for a user-supplied capture log file.
    /// Acceptance is by file content (classic PCAP magic), not extension, so
    /// captures saved as .pcap, .cap, .log, or anything else all work.
    nonisolated public static func logFileValidationError(at url: URL) -> String? {
        guard FileManager.default.isReadableFile(atPath: url.path) else {
            return "That file could not be read. Check that it still exists and that PacketScope can access it."
        }
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return "That file could not be opened."
        }
        defer { try? handle.close() }
        guard let head = try? handle.read(upToCount: 4), head.count == 4 else {
            return "That file is too short to be a packet capture log. PacketScope can analyze classic PCAP capture files (for example from Wireshark or tcpdump)."
        }
        let b = [UInt8](head)
        if b == [0x0A, 0x0D, 0x0D, 0x0A] {
            return "That is a PCAPNG file, which this version cannot analyze yet. In Wireshark, use Save As and choose the classic PCAP format, then import it again."
        }
        let classic: [[UInt8]] = [
            [0xD4, 0xC3, 0xB2, 0xA1], // little-endian, microsecond
            [0xA1, 0xB2, 0xC3, 0xD4], // big-endian, microsecond
            [0x4D, 0x3C, 0xB2, 0xA1], // little-endian, nanosecond
            [0xA1, 0xB2, 0x3C, 0x4D], // big-endian, nanosecond
        ]
        if classic.contains(b) { return nil }
        return "That file does not look like a packet capture log. PacketScope can analyze classic PCAP capture files (for example exported from Wireshark or tcpdump); plain text logs cannot be turned into packet results."
    }

    /// Import entry point for files the user picks or drops onto the app.
    public func importUserLogFile(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        if let problem = Self.logFileValidationError(at: url) {
            state = .failed(problem)
            errorMessage = problem
            section = .overview
            scanPage = .setup
            return
        }
        section = .overview
        openPCAP(url: url)
    }

    public func openPCAP(url: URL) {
        clearConversation()
        let token = UUID(); sessionToken = token
        errorMessage = nil
        do {
            let vals = try url.resourceValues(forKeys: [.fileSizeKey])
            if let size = vals.fileSize, size > PacketAnalyzer.maxFileBytes {
                state = .failed(AnalyzerError.fileTooLarge(size).localizedDescription); return
            }
        } catch { /* analysis will surface read errors */ }
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let dir = Self.sessionsRoot.appendingPathComponent("import_\(stamp)_\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [FileAttributeKey.posixPermissions: 0o700])
            let dest = dir.appendingPathComponent("traffic.pcap")
            try FileManager.default.copyItem(at: url, to: dest) // original preserved untouched
            let after = try FileManager.default.attributesOfItem(atPath: dest.path)
            if let size = after[.size] as? NSNumber, size.intValue > PacketAnalyzer.maxFileBytes {
                throw AnalyzerError.fileTooLarge(size.intValue)
            }
            try FileManager.default.setAttributes([FileAttributeKey.posixPermissions: 0o600], ofItemAtPath: dest.path)
        } catch {
            state = .failed(error.localizedDescription)
            return
        }
        let ctx = SessionContext(goal: .background, symptom: "", interface: "Imported: \(url.lastPathComponent)", startedAt: Date().timeIntervalSince1970, isImported: true)
        context = ctx; currentSessionDir = dir; droppedPackets = 0
        saveContext(ctx, to: dir)
        analyzeSession(dir: dir, token: token)
    }

    public func loadHistory() {
        let root = Self.sessionsRoot
        guard let dirs = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.creationDateKey], options: [.skipsHiddenFiles]) else { sessions = []; return }
        var found: [SavedSession] = []
        for dir in dirs {
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir), isDir.boolValue else { continue }
            guard FileManager.default.fileExists(atPath: dir.appendingPathComponent("traffic.pcap").path) else { continue }
            guard let data = try? Data(contentsOf: dir.appendingPathComponent("report.json")),
                  let rep = try? JSONDecoder().decode(CaptureReport.self, from: data) else { continue }
            let ctx = loadContext(from: dir) ?? SessionContext.unknownImported
            let dropped = readStatus(in: dir)?.dropped ?? 0
            let date = ctx.startedAt.map { Date(timeIntervalSince1970: $0) } ?? (try? dir.resourceValues(forKeys: [.creationDateKey]))?.creationDate ?? Date.distantPast
            found.append(SavedSession(directory: dir, date: date, report: rep, context: ctx, dropped: dropped))
        }
        sessions = Array(found.sorted { $0.date > $1.date }.prefix(50))
    }

    public func openSession(_ s: SavedSession) {
        clearConversation()
        let token = UUID(); sessionToken = token
        currentSessionDir = s.directory
        context = s.context
        droppedPackets = s.dropped
        errorMessage = nil
        analyzeSession(dir: s.directory, token: token) // reanalyze the saved PCAP
    }

    public func useCurrentAsBaseline() {
        guard let dir = currentSessionDir, let rep = report, let ctx = context else { return }
        baseline = SavedSession(directory: dir, date: ctx.startedAt.map { Date(timeIntervalSince1970: $0) } ?? Date(), report: rep, context: ctx, dropped: droppedPackets)
        baselineIsCurrent = true
    }
    public func chooseBaseline(_ s: SavedSession) {
        if let cur = currentSessionDir, cur == s.directory { errorMessage = "A session cannot be compared with itself. Open a different capture first."; return }
        baseline = s; baselineIsCurrent = false
    }
    public func clearBaseline() { baseline = nil; baselineIsCurrent = false }

    public func repeatCapture() {
        guard let b = baseline else { return }
        goal = b.context.goal
        if !b.context.symptom.isEmpty { symptom = b.context.symptom }
        if interfaces.contains(where: { $0.name == b.context.interface }) { selectedInterface = b.context.interface }
        changeNoteDraft = changeNoteDraft // note describing the change, kept for the next capture
        baselineIsCurrent = false
        startCapture()
    }

    // MARK: Navigation helpers

    public func openPacketLog(number: Int) {
        packetSearch = "#\(number)"
        section = .packets
        if let rep = report, !rep.packets.contains(where: { $0.id == number }) {
            errorMessage = "Packet #\(number) is outside the retained display set (first \(PacketAnalyzer.displayLimit) of \(rep.packetCount) packets). Totals and findings still cover the entire file."
        }
    }
    public func closePacketSearchNote() { errorMessage = nil }

    // MARK: Exports

    public func exportSupportReport(options: SupportOptions) {
        guard let rep = report, let ctx = context else { return }
        let text = ReportText.supportReport(report: rep, context: ctx, options: options, comparison: comparison, threatIntel: threatIntel)
        saveText(text, defaultName: "PacketScope-support-report.txt")
        showSupportSheet = false
    }
    public func exportLegacyReport() {
        guard let rep = report, let ctx = context else { return }
        saveText(ReportText.plainReport(report: rep, context: ctx), defaultName: "PacketScope-report.txt")
    }
    public func exportRawCapture() {
        guard let dir = currentSessionDir else { return }
        let src = dir.appendingPathComponent("traffic.pcap")
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "traffic.pcap"
        panel.title = "Export raw capture"
        panel.message = "The raw PCAP is copied unchanged: original addresses, packet metadata, DNS names, and any unencrypted payloads remain. Support-report redaction options do not apply to it."
        if panel.runModal() == .OK, let dest = panel.url {
            do { if FileManager.default.fileExists(atPath: dest.path) { try FileManager.default.removeItem(at: dest) }; try FileManager.default.copyItem(at: src, to: dest) }
            catch { errorMessage = "Raw export failed: \(error.localizedDescription)" }
        }
    }
    public func openEvidenceFilter(_ filter: String) {
        packetSearch = filter
        section = .packets
    }
    public func exportEvidencePackets(frames: [Int], suggestedName: String = "evidence-packets.pcap") {
        guard let dir = currentSessionDir else { return }
        let src = dir.appendingPathComponent("traffic.pcap")
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.title = "Export these packets"
        panel.message = "Writes a new PCAP containing only the listed frame numbers, copied unchanged from the original capture. It can still contain addresses, metadata, DNS names, and any unencrypted payloads in those packets."
        if panel.runModal() == .OK, let dest = panel.url {
            let frameSet = Set(frames)
            Task.detached {
                do { try PacketAnalyzer.exportPackets(from: src, frames: frameSet, to: dest) }
                catch { await MainActor.run { AppModel.shared.errorMessage = "Packet export failed: \(error.localizedDescription)" } }
            }
        }
    }
    private func saveText(_ text: String, defaultName: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = defaultName
        panel.allowedContentTypes = [.plainText]
        if panel.runModal() == .OK, let dest = panel.url {
            do { try text.write(to: dest, atomically: true, encoding: .utf8) }
            catch { errorMessage = "Save failed: \(error.localizedDescription)" }
        }
    }
    public func revealSessionFiles() {
        if let dir = currentSessionDir {
            NSWorkspace.shared.activateFileViewerSelecting([dir.appendingPathComponent("traffic.pcap")])
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([Self.sessionsRoot])
        }
    }

    // MARK: Ask capture

    public func cancelChat() {
        chatTask?.cancel(); chatTask = nil; chatBusy = false; chatToken = UUID()
    }
    public func clearConversation() { cancelChat(); chatMessages = [] }

    public func ask(_ rawQuestion: String) {
        let question = rawQuestion.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !question.isEmpty, !chatBusy else { return }
        chatMessages.append(AssistantMessage(role: "user", text: question))
        let token = UUID(); chatToken = token
        chatBusy = true
        let rep = report, ctx = context, cmp = comparison, hasBaseline = baseline != nil, aiOn = useAI
        chatTask = Task { [weak self] in
            var answerText: String? = nil
            var refs: [Int] = []
            var source = AssistantSource.rules
            let factual = RulesGuide.isFactualLookup(question)
            if aiOn && !factual, let rep = rep, OnDeviceAI.isAvailable {
                let evidence = EvidenceBuilder.build(report: rep, context: ctx, comparison: cmp)
                if let ans = try? await OnDeviceAI.generateWithDeadline(question: question, evidence: evidence),
                   AIOutputValidator.validate(text: ans.text, packetNumbers: ans.packetNumbers, allowed: evidence.allowedPacketIDs) {
                    var t = TextSanitizer.clean(ans.text, maxLength: 1500)
                    if evidence.isPartial { t += "\n\nNote: the evidence supplied to the model was partial. Verify important conclusions against the findings above." }
                    t += "\n\nPlease verify important conclusions against the findings."
                    answerText = t; refs = ans.packetNumbers; source = AssistantSource.ai
                }
            }
            if Task.isCancelled { return }
            if answerText == nil {
                let r = RulesGuide.answer(question: question, report: rep, context: ctx, comparison: cmp, baselineAvailable: hasBaseline)
                answerText = r.text; refs = r.packetNumbers; source = AssistantSource.rules
            }
            await MainActor.run {
                guard let self = self, self.chatToken == token else { return }
                self.chatMessages.append(AssistantMessage(role: "assistant", text: answerText ?? "", source: source, packetNumbers: refs))
                self.chatBusy = false
            }
        }
    }
}

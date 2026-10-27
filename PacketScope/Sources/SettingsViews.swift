import SwiftUI
import AppKit

struct ThreatFeedSettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var refreshTick = 0
    @State private var keyDrafts: [String: String] = [:]
    @State private var allowValue = ""
    @State private var allowReason = ""
    @State private var customName = ""
    @State private var customURL = ""
    @State private var customType = "domain"
    @State private var customSeverity = "medium"
    @State private var customFormat = "custom_lines"

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Threat feeds").font(.system(size: 28, weight: .semibold))
            Text("PacketScope can check destinations, names, certificates, and TLS fingerprints from your captures against threat feeds stored on this Mac. Matching is entirely local: no address, domain, URL, or hash from a capture is ever sent to an online service. The only downloads are the feed files below, from their registry URLs. Cleartext HTTP addresses from captures are checked locally against these feeds in the same way.")
                .font(.system(size: 12)).foregroundColor(PS.secondary)
            if let msg = model.feedMessage {
                Text(msg).font(.system(size: 12)).foregroundColor(PS.amber)
            }
            VStack(alignment: .leading, spacing: 12) {
                Text("Feeds").font(.system(size: 17, weight: .semibold))
                ForEach(model.allFeedMetas.filter { $0.id != "threatfox" && $0.id != "urlhaus" }) { meta in feedRow(meta) }
                Text("ThreatFox and URLhaus are hidden until their export parsers can be verified against a real file with a user's own Auth-Key.")
                    .font(.system(size: 11)).foregroundColor(PS.secondary)
            }.psCard().frame(maxWidth: .infinity, alignment: .leading)
            allowlistCard
            customFeedCard
            Text("Public suffix data: Public Suffix List version \(PublicSuffix.versionDate), licensed under MPL 2.0. Feed content is untrusted data; indicator values are shown defanged and are never opened as links. Auth-Keys are stored in the macOS Keychain and never written to settings files or logs.")
                .font(.system(size: 11)).foregroundColor(PS.secondary)
        }
        .id(refreshTick)
    }

    private func feedRow(_ meta: FeedMeta) -> some View {
        let state = model.feedUpdater.state(for: meta)
        let next = model.feedUpdater.nextAllowedUpdate(for: meta, now: Date())
        let updateAllowed = Date() >= next || state.lastAttemptAt == nil
        return VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 10) {
                Toggle("", isOn: Binding(get: { state.enabled }, set: { model.feedUpdater.setEnabled($0, for: meta); refreshTick += 1 }))
                    .labelsHidden()
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(meta.name).font(.system(size: 14, weight: .semibold))
                        if let home = URL(string: meta.homepage) { Link("Source", destination: home).font(.system(size: 11)) }
                    }
                    Text(statusText(meta: meta, state: state)).font(.system(size: 11)).foregroundColor(stateTextColor(state: state, meta: meta))
                    if let err = state.lastError { Text(err).font(.system(size: 11)).foregroundColor(PS.amber) }
                }
                Spacer()
                Button("Update now") {
                    Task { _ = await model.feedUpdater.update(feed: meta, now: Date(), manual: true); model.invalidateIntelSnapshot(); refreshTick += 1 }
                }
                .disabled(!state.enabled || !updateAllowed)
                .help(updateAllowed ? "Download the latest copy now" : "Available after the feed's minimum interval")
            }
            if !updateAllowed && state.enabled {
                Text("Next update allowed \(next.formatted(date: .omitted, time: .shortened)) (minimum interval \(meta.minRefreshSec / 60) min).")
                    .font(.system(size: 10)).foregroundColor(PS.secondary)
            }
            HStack(spacing: 12) {
                Text("License: \(meta.license)").font(.system(size: 10)).foregroundColor(PS.secondary)
                Text("Refresh: \(meta.refreshSec >= 86400 ? "daily" : "hourly")").font(.system(size: 10)).foregroundColor(PS.secondary)
                Text("Base severity: \(meta.baseSeverity)").font(.system(size: 10)).foregroundColor(PS.secondary)
            }
            if let attribution = meta.attribution { Text(attribution).font(.system(size: 10)).foregroundColor(PS.secondary) }
            if let cr = state.feedCopyright { Text("Feed data: \(cr)\(state.feedTerms.map { " · Terms: \($0)" } ?? "")").font(.system(size: 10)).foregroundColor(PS.secondary) }
            if meta.requiresKey {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        SecureField("abuse.ch Auth-Key", text: Binding(get: { keyDrafts[meta.id] ?? "" }, set: { keyDrafts[meta.id] = $0 }))
                            .frame(maxWidth: 340)
                        Button("Save key") {
                            model.feedUpdater.keyStore.setKey(keyDrafts[meta.id], for: meta.id)
                            keyDrafts[meta.id] = ""
                            model.feedMessage = "Key saved in the Keychain for \(meta.name)."
                        }
                        if let signup = URL(string: "https://auth.abuse.ch/") { Link("Get an Auth-Key", destination: signup).font(.system(size: 11)) }
                    }
                    Text("Free for non-profit use; commercial use may need a paid subscription. The key is stored only in the macOS Keychain.").font(.system(size: 10)).foregroundColor(PS.amber)
                    if model.feedUpdater.keyStore.key(for: meta.id) != nil { Text("A key is saved for this feed.").font(.system(size: 10)).foregroundColor(PS.teal) }
                }
            }
        }
        .padding(13).background(PS.elevated).clipShape(RoundedRectangle(cornerRadius: 10)).overlay(RoundedRectangle(cornerRadius: 10).stroke(PS.border))
    }
    private func statusText(meta: FeedMeta, state: FeedState) -> String {
        if !state.enabled { return "Off" }
        guard let s = state.lastSuccessAt else { return "Never downloaded — threat matching will say it didn't run" }
        let age = Date().timeIntervalSince1970 - s
        let rel = age < 3600 ? "\(Int(age / 60)) min ago" : (age < 86400 ? "\(Int(age / 3600)) h ago" : "\(Int(age / 86400)) d ago")
        let stale = state.isStale(meta: meta, now: Date().timeIntervalSince1970) ? " · STALE, using the last good copy" : ""
        let newest = state.newestIndicatorAt.map { " · newest entry \($0)" } ?? ""
        return "Updated \(rel) · \(state.indicatorCount) indicators\(newest)\(stale)"
    }
    private func stateTextColor(state: FeedState, meta: FeedMeta) -> Color {
        if state.enabled && state.isStale(meta: meta, now: Date().timeIntervalSince1970) { return PS.amber }
        return PS.secondary
    }

    private var allowlistCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Allowlist").font(.system(size: 17, weight: .semibold))
            Text("Matches for these values are suppressed but counted under “Ignored by your allowlist” on the Results page.").font(.system(size: 11)).foregroundColor(PS.secondary)
            if model.allowlist.isEmpty { Text("Nothing is allowlisted.").font(.system(size: 12)).foregroundColor(PS.secondary) }
            ForEach(model.allowlist) { entry in
                HStack {
                    Text(entry.value).font(.system(size: 12, design: .monospaced))
                    Text(entry.reason).font(.system(size: 11)).foregroundColor(PS.secondary)
                    Text(Date(timeIntervalSince1970: entry.addedAt).formatted(date: .abbreviated, time: .omitted)).font(.system(size: 11)).foregroundColor(PS.secondary)
                    Spacer()
                    Button("Remove") { model.allowlist.removeAll { $0.value == entry.value }; model.saveAllowlist() }.font(.system(size: 11))
                }
            }
            HStack {
                TextField("Value (IP, domain, URL, or hash)", text: $allowValue).frame(maxWidth: 320)
                TextField("Reason", text: $allowReason).frame(maxWidth: 240)
                Button("Add") {
                    let v = Normalize.ip(allowValue) ?? Normalize.domain(allowValue) ?? allowValue.lowercased()
                    model.allowlist.append(AllowlistEntry(value: v, reason: allowReason, addedAt: Date().timeIntervalSince1970))
                    model.saveAllowlist(); allowValue = ""; allowReason = ""
                }.disabled(allowValue.trimmingCharacters(in: .whitespaces).isEmpty)
            }.font(.system(size: 12))
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }

    private var customFeedCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Add a custom feed").font(.system(size: 17, weight: .semibold))
            Text("Your own list, from a URL or a local file. You are responsible for its license.").font(.system(size: 11)).foregroundColor(PS.secondary)
            HStack {
                TextField("Name", text: $customName).frame(maxWidth: 220)
                TextField("https://… feed URL", text: $customURL).frame(maxWidth: 360)
            }.font(.system(size: 12))
            HStack(spacing: 14) {
                Picker("Format", selection: $customFormat) {
                    Text("One indicator per line").tag("custom_lines")
                    Text("Typed CSV (type,value,threat,severity)").tag("custom_csv")
                }.frame(maxWidth: 320)
                Picker("Type", selection: $customType) {
                    Text("Domain").tag("domain"); Text("IPv4").tag("ipv4"); Text("IPv6").tag("ipv6"); Text("CIDR").tag("cidr"); Text("URL").tag("url")
                }.frame(maxWidth: 200)
                Picker("Severity", selection: $customSeverity) {
                    Text("High").tag("high"); Text("Medium").tag("medium"); Text("Low").tag("low"); Text("Info").tag("info")
                }.frame(maxWidth: 180)
            }
            HStack {
                Button("Add URL feed") { addCustom(url: customURL) }
                    .disabled(customName.isEmpty || customURL.isEmpty)
                Button("Choose local file…") { chooseCustomFile() }
                    .disabled(customName.isEmpty)
            }.font(.system(size: 12))
        }.psCard().frame(maxWidth: .infinity, alignment: .leading)
    }
    private func addCustom(url: String) {
        let meta = FeedMeta(id: "custom-" + UUID().uuidString.prefix(8).lowercased(), name: customName, url: url, homepage: "", license: "Custom feed (your responsibility)", requiresKey: false, enabledByDefault: true, refreshSec: 86400, minRefreshSec: 300, maxAgeSec: 259200, baseSeverity: customSeverity, parser: customFormat)
        model.addCustomFeed(meta)
        customName = ""; customURL = ""
        refreshTick += 1
    }
    private func chooseCustomFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.title = "Choose a custom feed file"
        guard panel.runModal() == .OK, let url = panel.url, let data = try? Data(contentsOf: url) else { return }
        let meta = FeedMeta(id: "custom-" + UUID().uuidString.prefix(8).lowercased(), name: customName, url: "file://custom", homepage: "", license: "Custom feed (your responsibility)", requiresKey: false, enabledByDefault: true, refreshSec: 86400, minRefreshSec: 300, maxAgeSec: 259200, baseSeverity: customSeverity, parser: customFormat)
        model.customFeeds.append(meta); model.saveCustomFeeds()
        do {
            try model.feedUpdater.importLocalCopy(feed: meta, data: data, customType: customFormat == "custom_lines" ? customType : nil)
            model.feedMessage = "Custom feed “\(customName)” imported."
        } catch {
            model.feedMessage = "Custom feed was not imported: \(error.localizedDescription)"
        }
        customName = ""
        refreshTick += 1
    }
}

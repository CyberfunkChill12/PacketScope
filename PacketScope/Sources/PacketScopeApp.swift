import SwiftUI
import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Hidden title bar; the sidebar provides the app identity.
        DispatchQueue.main.async {
            for window in NSApp.windows { Self.style(window) }
        }
    }
    func applicationDidBecomeActive(_ notification: Notification) {
        for window in NSApp.windows { Self.style(window) }
    }
    static func style(_ window: NSWindow) {
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.styleMask.insert(.fullSizeContentView)
        window.minSize = NSSize(width: 1180, height: 780)
        window.backgroundColor = NSColor(srgbRed: 0.035, green: 0.052, blue: 0.085, alpha: 1)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) {
        // Best-effort cleanup; the helper also stops when its --watch-pid disappears.
        Task { @MainActor in AppModel.shared.requestCleanupOnQuit() }
    }
}

@main
struct PacketScopeApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var model = AppModel.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 1180, minHeight: 780)
                .onAppear { model.onAppear() }
        }
        .defaultSize(width: 1180, height: 780)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Capture") { model.newCapture() }.keyboardShortcut("n", modifiers: .command)
                Button("Import Log File…") { model.presentOpenPanel() }.keyboardShortcut("o", modifiers: .command)
            }
            CommandMenu("Capture") {
                Button("Start Capture") { model.startCapture() }.keyboardShortcut("r", modifiers: .command)
                    .disabled(model.state.isBusy || model.isCapturing)
                Button("Stop Capture") { model.stopCapture() }.keyboardShortcut(".", modifiers: .command)
                    .disabled(!model.isCapturing)
                Divider()
                Button("Show Session Files") { model.revealSessionFiles() }
                Button("Export Report") { model.exportLegacyReport() }.keyboardShortcut("e", modifiers: .command)
                    .disabled(model.report == nil)
            }
        }
    }
}

extension AppModel {
    func presentOpenPanel() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.title = "Import your own capture log file"
        panel.message = "Choose a classic PCAP capture log (for example .pcap or .cap from Wireshark or tcpdump). The file is checked by its contents, copied into a new local session, and analyzed exactly like a PacketScope capture. Your original is preserved and no administrator authorization is needed."
        if panel.runModal() == .OK, let url = panel.url { importUserLogFile(url) }
    }
}

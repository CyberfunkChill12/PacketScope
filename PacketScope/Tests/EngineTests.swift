import Foundation

private func helperPath() -> String {
    ProcessInfo.processInfo.environment["PACKETSCOPE_HELPER"] ?? "build/tests/packetscope-capture"
}
private func runHelper(_ args: [String]) -> (Int32, String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: helperPath())
    p.arguments = args
    let out = Pipe(); p.standardOutput = out; p.standardError = out
    try! p.run()
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}
private func baseArgs(dir: String) -> [String] {
    ["--interface", "lo0", "--directory", dir, "--uid", "\(getuid())", "--gid", "\(getgid())",
     "--duration", "60", "--max-bytes", "104857600", "--watch-pid", "\(ProcessInfo.processInfo.processIdentifier)", "--attribution", "1"]
}

func registerEngineTests() {
    let T = TestHarness.self
    T.test("helper --interfaces returns valid JSON including lo0") {
        let (rc, out) = runHelper(["--interfaces"])
        T.expectEqual(rc, 0)
        let objs = try JSONSerialization.jsonObject(with: Data(out.utf8)) as? [[String: String]]
        T.expect(objs?.contains(where: { $0["name"] == "lo0" }) ?? false)
    }
    T.test("helper rejects unknown option") {
        let (rc, _) = runHelper(["--bogus"])
        T.expect(rc != 0)
    }
    T.test("helper rejects repeated option") {
        var a = baseArgs(dir: "/tmp"); a += ["--interface", "en0"]
        let (rc, _) = runHelper(a); T.expect(rc != 0)
    }
    T.test("helper rejects missing value") {
        let (rc, _) = runHelper(["--interface"])
        T.expect(rc != 0)
    }
    T.test("helper rejects interface with comma or bad characters") {
        var a = baseArgs(dir: "/tmp"); a[1] = "en0,en1"
        let (rc, _) = runHelper(a); T.expect(rc != 0)
        a[1] = "en 0"; let (rc2, _) = runHelper(a); T.expect(rc2 != 0)
    }
    T.test("helper rejects root as target user") {
        var a = baseArgs(dir: "/tmp")
        a[5] = "0"
        let (rc, _) = runHelper(a); T.expect(rc != 0)
    }
    T.test("helper rejects a GID that is not the user's primary group") {
        var a = baseArgs(dir: "/tmp")
        a[7] = "12" // everyone: a real group, but not the primary group
        let (rc, out) = runHelper(a); T.expect(rc != 0); _ = out
    }
    T.test("helper rejects out-of-range duration and max-bytes") {
        var a = baseArgs(dir: "/tmp"); a[9] = "901"
        T.expect(runHelper(a).0 != 0)
        a = baseArgs(dir: "/tmp"); a[11] = "104857601"
        T.expect(runHelper(a).0 != 0)
        a = baseArgs(dir: "/tmp"); a[9] = "abc"
        T.expect(runHelper(a).0 != 0)
    }
    T.test("helper rejects session dir with wrong permissions (not 0700)") {
        let dir = NSTemporaryDirectory() + "ps-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: false, attributes: [FileAttributeKey.posixPermissions: 0o755])
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let (rc, _) = runHelper(baseArgs(dir: dir))
        T.expect(rc != 0)
    }
    T.test("helper rejects symlinked session directory") {
        let real = NSTemporaryDirectory() + "ps-real-\(UUID().uuidString)"
        let link = NSTemporaryDirectory() + "ps-link-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: real, withIntermediateDirectories: false, attributes: [FileAttributeKey.posixPermissions: 0o700])
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)
        defer { try? FileManager.default.removeItem(atPath: real); try? FileManager.default.removeItem(atPath: link) }
        T.expect(runHelper(baseArgs(dir: link)).0 != 0)
    }
    T.test("shell quoting survives spaces and apostrophes") {
        T.expectEqual(AppModel.shellQuote("a b'c"), "'a b'\\''c'")
        T.expect(!AppModel.shellQuote("plain").contains("\\"))
        let script = AppModel.appleScriptQuote("say \"hi\" \\ ok")
        T.expect(script.contains("\\\""))
    }
    T.test("duration choices map to bounded seconds (manual max 15 minutes)") {
        T.expectEqual(DurationChoice.m1.seconds, 60)
        T.expectEqual(DurationChoice.untilStopped.seconds, 900)
        T.expect(DurationChoice.allCases.allSatisfy { $0.seconds <= 900 && $0.seconds >= 30 })
    }
}

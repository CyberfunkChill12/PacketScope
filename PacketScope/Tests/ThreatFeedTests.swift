import Foundation

private let testFeedCSV = """
type,value,threat,severity
ipv4,203.0.113.50,botnet_c2,high
ip_port,198.51.100.7:8443,botnet_c2,high
cidr,198.51.100.128/25,hijacked_netblock,medium
domain,c2.test-ioc.example,botnet_c2,high
url,http://downloads.test-ioc.example/payload.bin,malware_download,high
ipv4,10.0.0.5,botnet_c2,high
"""

private let testFeedCSVForSlow = testFeedCSV

private func testMeta(minRefresh: Int = 0, parser: String = "test_csv") -> FeedMeta {
    FeedMeta(id: "test_feed", name: "Synthetic test feed", url: "https://feeds.invalid/test.csv", homepage: "https://example.invalid/", license: "Test data (reserved documentation addresses)", requiresKey: false, enabledByDefault: true, refreshSec: 3600, minRefreshSec: minRefresh, maxAgeSec: 86400, baseSeverity: "high", parser: parser)
}

private final class MockTransport: FeedTransport {
    var responses: [FeedTransportResponse] = []
    var error: Error?
    var calls: [(url: URL, etag: String?)] = []
    func fetch(url: URL, etag: String?, lastModified: String?, userAgent: String, timeoutSec: Int, maxBytes: Int) async throws -> FeedTransportResponse {
        calls.append((url, etag))
        if let error = error { throw error }
        return responses.isEmpty ? FeedTransportResponse(status: 500) : responses.removeFirst()
    }
}

private func tempDir() -> URL {
    let d = URL(fileURLWithPath: NSTemporaryDirectory() + "ps-feeds-\(UUID().uuidString)")
    try! FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
    return d
}
private func runAsync(_ body: @escaping () async -> Void) {
    let sem = DispatchSemaphore(value: 0)
    Task { await body(); sem.signal() }
    sem.wait()
}

func registerThreatFeedTests() {
    let T = TestHarness.self

    T.test("normalization: punycode, trailing dots, IPv4-mapped IPv6, canonical IPv6") {
        T.expectEqual(Normalize.domain("Bücher.EXAMPLE."), "xn--bcher-kva.example")
        T.expectEqual(Normalize.ip("::ffff:203.0.113.50"), "203.0.113.50")
        T.expectEqual(Normalize.ip("2001:0DB8:0000:0000:0000:FF00:0042:8329"), "2001:db8::ff00:42:8329")
        T.expectEqual(Normalize.domain("C2.Test-IOC.Example."), "c2.test-ioc.example")
    }
    T.test("domain matching is parent-only, never the reverse; public suffix entries ignored") {
        T.expect(Normalize.domainMatches(feedDomain: "c2.test-ioc.example", observed: "cdn.c2.test-ioc.example"))
        T.expect(Normalize.domainMatches(feedDomain: "c2.test-ioc.example", observed: "c2.test-ioc.example"))
        T.expect(!Normalize.domainMatches(feedDomain: "cdn.c2.test-ioc.example", observed: "c2.test-ioc.example"))
        T.expect(FeedParser.makeIndicator(feedId: "t", type: "domain", rawValue: "github.io", threat: nil, severity: nil) == nil)
    }
    T.test("CIDR edges: /25 includes .200 and the broadcast edge, excludes .127") {
        let parsed = CIDRRange.parse("198.51.100.128/25")
        T.expect(parsed != nil)
        T.expect(parsed!.range.contains(ip: "198.51.100.200"))
        T.expect(parsed!.range.contains(ip: "198.51.100.255"))
        T.expect(parsed!.range.contains(ip: "198.51.100.128"))
        T.expect(!parsed!.range.contains(ip: "198.51.100.127"))
    }
    T.test("test feed parses; private-address row parses but is marked never-flag") {
        let result = try FeedParser.parse(meta: testMeta(), data: Data(testFeedCSV.utf8))
        T.expectEqual(result.indicators.count, 6)
        T.expect(result.indicators.contains { $0.value == "10.0.0.5" })
        T.expect(Normalize.isNeverFlaggedIP("10.0.0.5"))
        T.expect(!Normalize.isNeverFlaggedIP("203.0.113.50"))
    }
    T.test("parser rejects a changed header and an HTML error page") {
        expectThrows({ _ = try FeedParser.parse(meta: testMeta(), data: Data("value,type,threat,severity\nipv4,203.0.113.50,x,high\n".utf8)) }) { _ in true }
        expectThrows({ _ = try FeedParser.parse(meta: testMeta(), data: Data("<html><body>Not Found</body></html>".utf8)) }) { ($0 as? FeedParseError) != nil }
    }
    T.test("domain normalization: NFC + case folding (decomposed and uppercase forms agree)") {
        T.expectEqual(Normalize.domain("bu\u{0308}cher.example"), "xn--bcher-kva.example")
        T.expectEqual(Normalize.domain("BÜCHER.example"), "xn--bcher-kva.example")
        T.expectEqual(Normalize.domain("Bücher.EXAMPLE."), "xn--bcher-kva.example")
    }
    T.test("public suffix guard uses the full bundled list") {
        T.expect(PublicSuffix.ruleCount > 5000, "expected the full list, got \(PublicSuffix.ruleCount) rules")
        T.expect(PublicSuffix.versionDate != "unknown", "list version date should be recorded")
        T.expect(Normalize.isPublicSuffix("github.io"))
        T.expect(Normalize.isPublicSuffix("co.uk"))
        T.expect(!Normalize.isPublicSuffix("example.co.uk"))
        T.expect(!Normalize.isPublicSuffix("www.example.co.uk"))
        T.expect(Normalize.isPublicSuffix("other.kawasaki.jp"))   // *.kawasaki.jp wildcard
        T.expect(!Normalize.isPublicSuffix("city.kawasaki.jp"))   // !city.kawasaki.jp exception
        T.expect(!Normalize.isPublicSuffix("example.com"))
    }
    T.test("key never leaks through a real URLSession error into state or state.json") {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let secret = "AUTHKEY-LEAK-TEST-98765"
        let keys = InMemoryKeyStore(); keys.setKey(secret, for: "keyed")
        let meta = FeedMeta(id: "keyed", name: "Keyed", url: "https://127.0.0.1:1/{AUTH_KEY}/feed.csv", homepage: "https://example.invalid/", license: "test", requiresKey: true, enabledByDefault: true, refreshSec: 3600, minRefreshSec: 0, maxAgeSec: 86400, baseSeverity: "high", parser: "test_csv")
        let updater = FeedUpdater(directory: dir, transport: URLSessionFeedTransport(), keyStore: keys)
        runAsync {
            let (state, outcome) = await updater.update(feed: meta, now: Date(), manual: true)
            T.expect(outcome != .updated)
            T.expect(!(state.lastError ?? "").contains(secret), "key in stored error: \(state.lastError ?? "")")
            let stateText = (try? String(contentsOf: dir.appendingPathComponent("state.json"), encoding: .utf8)) ?? ""
            T.expect(!stateText.contains(secret), "key written to state.json")
            T.expect(!FeedSecrets.sanitizedError(URLError(.cannotConnectToHost), key: secret).contains(secret))
            let ns = NSError(domain: NSURLErrorDomain, code: -1004, userInfo: [NSURLErrorFailingURLErrorKey: URL(string: "https://127.0.0.1/\(secret)/x")!, NSLocalizedDescriptionKey: "failed https://127.0.0.1/\(secret)/x"])
            T.expect(!FeedSecrets.sanitizedError(ns, key: secret).contains(secret), "sanitized error must drop userInfo URLs entirely")
        }
    }
    T.test("scheduled refresh delay is refresh plus 0-10 percent") {
        T.expect(abs(FeedUpdater.scheduledDelaySec(refreshSec: 3600, randomFraction: 0) - 3600) < 0.001)
        T.expect(abs(FeedUpdater.scheduledDelaySec(refreshSec: 3600, randomFraction: 0.5) - 3780) < 0.001)
        T.expect(abs(FeedUpdater.scheduledDelaySec(refreshSec: 3600, randomFraction: 1) - 3960) < 0.001)
        T.expect(abs(FeedUpdater.scheduledDelaySec(refreshSec: 86400, randomFraction: 2) - 95040) < 0.001, "fraction is clamped to 1")
    }
    T.test("background refresh never blocks the caller") {
        final class SlowTransport: FeedTransport {
            func fetch(url: URL, etag: String?, lastModified: String?, userAgent: String, timeoutSec: Int, maxBytes: Int) async throws -> FeedTransportResponse {
                try await Task.sleep(nanoseconds: 3_000_000_000)
                return FeedTransportResponse(status: 200, data: Data(testFeedCSVForSlow.utf8))
            }
        }
        let updater = FeedUpdater(directory: tempDir(), transport: SlowTransport(), keyStore: InMemoryKeyStore())
        let start = Date()
        updater.refreshInBackground(feeds: [testMeta()], now: Date())
        let elapsed = Date().timeIntervalSince(start)
        T.expect(elapsed < 1.0, "refreshInBackground blocked for \(elapsed)s")
    }
    T.test("a store snapshot is isolated from later feed swaps") {
        let parsed = try! FeedParser.parse(meta: testMeta(), data: Data(testFeedCSV.utf8))
        let store = IndicatorStore()
        store.load(indicators: parsed.indicators, retentionSec: nil, now: Date())
        let snap = store.snapshot()
        // Simulate a swap: reload the same store object with different data.
        let other = try! FeedParser.parse(meta: testMeta(), data: Data("type,value,threat,severity\ndomain,other.example,botnet_c2,high\n".utf8))
        store.load(indicators: other.indicators, retentionSec: nil, now: Date())
        T.expect(snap.exactMatch(type: "ipv4", value: "203.0.113.50") != nil, "snapshot changed after swap")
        T.expect(store.exactMatch(type: "ipv4", value: "203.0.113.50") == nil)
        T.expectEqual(snap.count, 6)
    }
    T.test("updater: successful download is stored with hash and count") {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let mock = MockTransport(); mock.responses = [FeedTransportResponse(status: 200, data: Data(testFeedCSV.utf8), etag: "\"v1\"")]
        let updater = FeedUpdater(directory: dir, transport: mock, keyStore: InMemoryKeyStore())
        runAsync {
            let (state, outcome) = await updater.update(feed: testMeta(), now: Date(), manual: true)
            T.expect(outcome == .updated)
            T.expectEqual(state.indicatorCount, 6)
            T.expect(!state.fileSha256.isEmpty)
            T.expect(updater.storedData(for: testMeta()) != nil)
        }
    }
    T.test("updater: a rejected download never replaces the last good copy") {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let mock = MockTransport()
        mock.responses = [FeedTransportResponse(status: 200, data: Data(testFeedCSV.utf8)),
                          FeedTransportResponse(status: 200, data: Data("<html>error</html>".utf8)),
                          FeedTransportResponse(status: 200, data: Data("type,value,threat,severity\nipv4,999.1.1.1,x,high\n".utf8))]
        let updater = FeedUpdater(directory: dir, transport: mock, keyStore: InMemoryKeyStore())
        let meta = testMeta()
        runAsync {
            _ = await updater.update(feed: meta, now: Date(), manual: true)
            let good = updater.storedData(for: meta)
            let (_, o2) = await updater.update(feed: meta, now: Date().addingTimeInterval(10), manual: true)
            T.expect(o2 != .updated)
            T.expectEqual(updater.storedData(for: meta), good, "HTML page must not replace the good copy")
            let (_, o3) = await updater.update(feed: meta, now: Date().addingTimeInterval(20), manual: true)
            T.expect(o3 != .updated, "a mostly-invalid file must be rejected (<95% valid)")
            T.expectEqual(updater.storedData(for: meta), good)
        }
    }
    T.test("updater: indicator-count collapse is rejected") {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let big = (["type,value,threat,severity"] + (0..<40).map { "ipv4,203.0.113.\($0 % 250 + 1),botnet_c2,high" }).joined(separator: "\n")
        let mock = MockTransport()
        mock.responses = [FeedTransportResponse(status: 200, data: Data(big.utf8)),
                          FeedTransportResponse(status: 200, data: Data(testFeedCSV.utf8))]
        let updater = FeedUpdater(directory: dir, transport: mock, keyStore: InMemoryKeyStore())
        runAsync {
            let (s1, _) = await updater.update(feed: testMeta(), now: Date(), manual: true)
            T.expectEqual(s1.indicatorCount, 40)
            let (_, o2) = await updater.update(feed: testMeta(), now: Date().addingTimeInterval(10), manual: true)
            T.expect(o2 != .updated, "40 -> 6 is a collapse and must be rejected")
        }
    }
    T.test("updater: minimum refresh interval is a hard floor, even manually") {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let mock = MockTransport(); mock.responses = [FeedTransportResponse(status: 200, data: Data(testFeedCSV.utf8))]
        let updater = FeedUpdater(directory: dir, transport: mock, keyStore: InMemoryKeyStore())
        let meta = testMeta(minRefresh: 3600)
        let now = Date()
        runAsync {
            _ = await updater.update(feed: meta, now: now, manual: true)
            let (_, outcome) = await updater.update(feed: meta, now: now.addingTimeInterval(60), manual: true)
            if case .tooSoon(let next) = outcome {
                T.expect(next > now.addingTimeInterval(3500))
            } else { T.expect(false, "expected tooSoon, got \(outcome)") }
            T.expectEqual(mock.calls.count, 1, "no second fetch may happen inside the minimum interval")
        }
    }
    T.test("updater: 304 counts as success; offline failure keeps the last good copy usable") {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let mock = MockTransport()
        mock.responses = [FeedTransportResponse(status: 200, data: Data(testFeedCSV.utf8), etag: "\"v1\""), FeedTransportResponse(status: 304)]
        let updater = FeedUpdater(directory: dir, transport: mock, keyStore: InMemoryKeyStore())
        let meta = testMeta()
        runAsync {
            _ = await updater.update(feed: meta, now: Date(), manual: true)
            let t2 = Date().addingTimeInterval(4000)
            let (s2, o2) = await updater.update(feed: meta, now: t2, manual: false)
            T.expect(o2 == .notModified)
            T.expect(abs((s2.lastSuccessAt ?? 0) - t2.timeIntervalSince1970) < 1)
            // Now go offline: the stored copy must still load.
            mock.error = NSError(domain: "offline", code: -1009)
            _ = await updater.update(feed: meta, now: t2.addingTimeInterval(4000), manual: false)
            let (store, _) = updater.loadStore(now: t2.addingTimeInterval(4000))
            // The test feed is not in the default registry, so load via direct parse instead:
            let parsed = try? FeedParser.parse(meta: meta, data: updater.storedData(for: meta) ?? Data())
            T.expectEqual(parsed?.indicators.count, 6)
            _ = store
        }
    }
    T.test("updater: stale is reported after maxAge; backoff grows and is floored") {
        let updater = FeedUpdater(directory: tempDir(), transport: MockTransport(), keyStore: InMemoryKeyStore())
        let meta = testMeta()
        T.expectEqual(updater.backoffSec(consecutiveFailures: 1), 300)
        T.expectEqual(updater.backoffSec(consecutiveFailures: 2), 900)
        T.expectEqual(updater.backoffSec(consecutiveFailures: 5), 3600)
        var s = FeedState(feedId: meta.id, enabled: true); s.lastSuccessAt = 0
        T.expect(s.isStale(meta: meta, now: Double(meta.maxAgeSec) + 1))
        T.expect(!s.isStale(meta: meta, now: 100))
    }
    T.test("keyed feeds: URL is built from the key, and the key never leaks into errors") {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let secret = "SECRETKEY123456"
        let keys = InMemoryKeyStore(); keys.setKey(secret, for: "threatfox")
        let mock = MockTransport(); mock.responses = [FeedTransportResponse(status: 401)]
        let updater = FeedUpdater(directory: dir, transport: mock, keyStore: keys)
        let meta = FeedMeta(id: "threatfox", name: "ThreatFox", url: "https://threatfox-api.abuse.ch/v2/files/exports/{AUTH_KEY}/full.csv.zip", homepage: "https://threatfox.abuse.ch/", license: "test", requiresKey: true, enabledByDefault: true, refreshSec: 3600, minRefreshSec: 0, maxAgeSec: 86400, baseSeverity: "high", parser: "test_csv")
        runAsync {
            let (state, outcome) = await updater.update(feed: meta, now: Date(), manual: true)
            T.expect(outcome == .keyInvalid)
            T.expect(!(state.lastError ?? "").contains(secret), "Auth-Key leaked into the error message")
            T.expect(mock.calls.first?.url.absoluteString.contains(secret) ?? false, "download URL should carry the key (transport only)")
            T.expect(FeedSecrets.redacted("url/\(secret)/x", key: secret) == "url/•••/x")
        }
        // Registry sanity: the four no-key feeds are on by default; JA3 and keyed feeds are off.
        T.expectEqual(FeedRegistry.all.filter { $0.enabledByDefault }.map { $0.id }.sorted(), ["feodo_recommended", "spamhaus_drop", "sslbl_certs"])
        T.expect(FeedRegistry.all.first { $0.id == "sslbl_ja3" }?.enabledByDefault == false)
        T.expect(FeedRegistry.all.first { $0.id == "sslbl_ips" } == nil, "SSLBL C2 IPs was dropped from the registry (deprecated, empty)")
        T.expect(FeedRegistry.all.first { $0.id == "threatfox" }?.requiresKey == true)
    }
}

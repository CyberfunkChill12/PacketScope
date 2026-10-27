import Foundation
import CryptoKit
import CommonCrypto

// MARK: - Builders for TLS / QUIC fixtures

func tcpSeg(src: String, dst: String, sport: Int, dport: Int, seq: UInt32, flags: UInt8, payload: [UInt8] = []) -> [UInt8] {
    var h: [UInt8] = []
    h += u16be(sport)
    h += u16be(dport)
    h += u32be(seq)
    h += u32be(0)
    h += [0x50, flags]
    h += u16be(8192)
    h += u16be(0)
    h += u16be(0)
    return ipv4Packet(src: src, dst: dst, proto: 6, payload: h + payload)
}

/// Builds a TLS ClientHello handshake (type + length + body), optionally with
/// ECH and with a large key_share so the hello exceeds one segment.
func clientHello(sni: String?, ech: Bool = false, bigKeyShare: Bool = false) -> [UInt8] {
    var exts: [UInt8] = []
    func ext(_ type: Int, _ data: [UInt8]) -> [UInt8] { u16be(type) + u16be(data.count) + data }
    if let sni = sni {
        let name = Array(sni.utf8)
        let list = u16be(name.count + 3) + [0] + u16be(name.count) + name
        exts += ext(0, list)
    }
    exts += ext(43, [2, 0x03, 0x04])                       // supported_versions: TLS 1.3
    exts += ext(10, u16be(4) + u16be(29) + u16be(23))      // supported_groups
    exts += ext(13, u16be(4) + u16be(0x0403) + u16be(0x0804)) // signature_algorithms
    exts += ext(16, u16be(3) + [2] + Array("h2".utf8))     // ALPN
    exts += ext(51, u16be(2) + u16be(29) + u16be(bigKeyShare ? 1100 : 32) + [UInt8](repeating: 0xAB, count: bigKeyShare ? 1100 : 32)) // key_share
    if ech { exts += ext(0xFE0D, [0, 0, 0, 0]) }
    var body: [UInt8] = [0x03, 0x03] + [UInt8](repeating: 7, count: 32) // version + random
    body += [0]                                                      // session id
    body += u16be(4) + u16be(0x1301) + u16be(0x1302)                 // cipher suites
    body += [1, 0]                                                   // compression
    body += u16be(exts.count) + exts
    return [1] + [UInt8((body.count >> 16) & 0xFF), UInt8((body.count >> 8) & 0xFF), UInt8(body.count & 0xFF)] + body
}
func tlsRecord(_ payload: [UInt8], type: UInt8 = 22) -> [UInt8] {
    [type, 3, 3] + u16be(payload.count) + payload
}
func certHandshake(certs: [[UInt8]]) -> [UInt8] {
    var list: [UInt8] = []
    for c in certs { list += [UInt8((c.count >> 16) & 0xFF), UInt8((c.count >> 8) & 0xFF), UInt8(c.count & 0xFF)] + c }
    let body = [UInt8((list.count >> 16) & 0xFF), UInt8((list.count >> 8) & 0xFF), UInt8(list.count & 0xFF)] + list
    return [11] + [UInt8((body.count >> 16) & 0xFF), UInt8((body.count >> 8) & 0xFF), UInt8(body.count & 0xFF)] + body
}
func sha1Hex(_ data: [UInt8]) -> String { Insecure.SHA1.hash(data: Data(data)).map { String(format: "%02x", $0) }.joined() }
func sha256Hex(_ data: [UInt8]) -> String { SHA256.hash(data: Data(data)).map { String(format: "%02x", $0) }.joined() }

private func synSeg(_ src: String, _ dst: String, _ sp: Int, _ dp: Int, seq: UInt32 = 100) -> (Double, [UInt8]) {
    (0, tcpSeg(src: src, dst: dst, sport: sp, dport: dp, seq: seq, flags: 0x02))
}
private func synAckSeg(_ src: String, _ dst: String, _ sp: Int, _ dp: Int, seq: UInt32 = 900) -> (Double, [UInt8]) {
    (0, tcpSeg(src: src, dst: dst, sport: sp, dport: dp, seq: seq, flags: 0x12))
}

// QUIC Initial client packet builder (v1), mirroring RFC 9001 key derivation.
func quicInitial(crypto: [UInt8], cryptoOffset: Int, pn: Int, dcid: [UInt8]) -> [UInt8] {
    func hkdfExpand(prk: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
        var out: [UInt8] = [], t: [UInt8] = [], counter: UInt8 = 1
        while out.count < length {
            var h = HMAC<SHA256>(key: SymmetricKey(data: Data(prk)))
            h.update(data: Data(t + info + [counter]))
            t = Array(h.finalize().withUnsafeBytes { Array($0) })
            out += t; counter += 1
        }
        return Array(out.prefix(length))
    }
    func label(_ secret: [UInt8], _ name: String, _ len: Int) -> [UInt8] {
        let full = Array("tls13 ".utf8) + Array(name.utf8)
        return hkdfExpand(prk: secret, info: [UInt8(len >> 8), UInt8(len & 0xFF), UInt8(full.count)] + full + [0], length: len)
    }
    let salt: [UInt8] = [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a]
    var extract = HMAC<SHA256>(key: SymmetricKey(data: Data(salt)))
    extract.update(data: Data(dcid))
    let initial = Array(extract.finalize().withUnsafeBytes { Array($0) })
    let client = label(initial, "client in", 32)
    let key = label(client, "quic key", 16)
    let iv = label(client, "quic iv", 12)
    let hp = label(client, "quic hp", 16)
    // CRYPTO frame
    func varint(_ v: Int) -> [UInt8] {
        if v < 64 { return [UInt8(v)] }
        if v < 16384 { return [UInt8(0x40 | ((v >> 8) & 0x3F)), UInt8(v & 0xFF)] }
        return [UInt8(0x80 | ((v >> 24) & 0x3F)), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }
    var plain: [UInt8] = [6] + varint(cryptoOffset) + varint(crypto.count) + crypto
    while plain.count < 32 { plain.append(0) } // padding so header-protection sample exists
    // Header (pn length 4): first byte 0xC3, version, dcid, scid(0), token(0), length
    let payloadLen = 4 + plain.count + 16
    var header: [UInt8] = [0xC3, 0, 0, 0, 1, UInt8(dcid.count)] + dcid + [0, 0] + varint(payloadLen)
    let pnOffset = header.count
    header += [UInt8((pn >> 24) & 0xFF), UInt8((pn >> 16) & 0xFF), UInt8((pn >> 8) & 0xFF), UInt8(pn & 0xFF)]
    var nonce = iv
    for i in 0..<4 { nonce[nonce.count - 1 - i] ^= UInt8((pn >> (8 * i)) & 0xFF) }
    let sealed = try! AES.GCM.seal(Data(plain), using: SymmetricKey(data: Data(key)), nonce: try! AES.GCM.Nonce(data: Data(nonce)), authenticating: Data(header))
    let cipher = Array(sealed.ciphertext) + Array(sealed.tag)
    // Header protection sample: ciphertext bytes starting 4 bytes after pn start.
    let sample = Array(cipher[0..<16])
    var mask = [UInt8](repeating: 0, count: 16)
    var outLen = 0
    let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode), hp, hp.count, nil, sample, 16, &mask, 16, &outLen)
    precondition(status == kCCSuccess)
    var packet = header + cipher
    packet[0] = header[0] ^ (mask[0] & 0x0F)
    for i in 0..<4 { packet[pnOffset + i] = header[pnOffset + i] ^ mask[1 + i] }
    return packet
}


private func tempDirForFeeds() -> URL {
    let d = URL(fileURLWithPath: NSTemporaryDirectory() + "ps-ti-\(UUID().uuidString)")
    try! FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
    return d
}
private let testFeedCSVForParser = """
type,value,threat,severity
ipv4,203.0.113.50,botnet_c2,high
ipv4,203.0.113.51,botnet_c2,high
ipv4,203.0.113.52,botnet_c2,high
ipv4,203.0.113.53,botnet_c2,high
ipv4,203.0.113.54,botnet_c2,high
ipv4,203.0.113.55,botnet_c2,high
"""
private final class MockTransportForFeeds: FeedTransport {
    var responses: [FeedTransportResponse] = []
    func fetch(url: URL, etag: String?, lastModified: String?, userAgent: String, timeoutSec: Int, maxBytes: Int) async throws -> FeedTransportResponse {
        responses.isEmpty ? FeedTransportResponse(status: 500) : responses.removeFirst()
    }
}
private func runAsyncForFeeds(_ body: @escaping () async -> Void) {
    let sem = DispatchSemaphore(value: 0)
    Task { await body(); sem.signal() }
    sem.wait()
}

private func testFeedStore(extraRows: String = "") -> IndicatorStore {
    let csv = """
type,value,threat,severity
ipv4,203.0.113.50,botnet_c2,high
ip_port,198.51.100.7:8443,botnet_c2,high
cidr,198.51.100.128/25,hijacked_netblock,medium
domain,c2.test-ioc.example,botnet_c2,high
url,http://downloads.test-ioc.example/payload.bin,malware_download,high
ipv4,10.0.0.5,botnet_c2,high
""" + extraRows
    let meta = FeedMeta(id: "test_feed", name: "Synthetic test feed", url: "https://feeds.invalid/test.csv", homepage: "https://example.invalid/", license: "Test", requiresKey: false, enabledByDefault: true, refreshSec: 3600, minRefreshSec: 0, maxAgeSec: 86400, baseSeverity: "high", parser: "test_csv")
    let parsed = try! FeedParser.parse(meta: meta, data: Data(csv.utf8))
    let store = IndicatorStore()
    store.load(indicators: parsed.indicators, retentionSec: nil, now: Date())
    return store
}
private func testMetas() -> [String: FeedMeta] {
    let meta = FeedMeta(id: "test_feed", name: "Synthetic test feed", url: "https://feeds.invalid/test.csv", homepage: "https://example.invalid/", license: "Test", requiresKey: false, enabledByDefault: true, refreshSec: 3600, minRefreshSec: 0, maxAgeSec: 86400, baseSeverity: "high", parser: "test_csv")
    return ["test_feed": meta]
}
private func analyze(_ pkts: [(Double, [UInt8])]) -> CaptureReport {
    try! PacketAnalyzer.analyze(data: buildPCAP(linkType: 101, packets: pkts.map { (1000 + $0.0, $0.1) }))
}

func registerThreatIntelTests() {
    let T = TestHarness.self
    let client = "192.168.1.23"

    T.test("two-segment ClientHello keeps SNI that is in the second segment") {
        let hello = tlsRecord(clientHello(sni: "api.example.com", bigKeyShare: true))
        let split = hello.count - 40 // SNI sits early, so split before it ends: force split inside the SNI name instead
        _ = split
        // Put the SNI-bearing part in segment 2: split 30 bytes into the record.
        let seg1 = Array(hello.prefix(30))
        let seg2 = Array(hello.dropFirst(30))
        let pkts: [(Double, [UInt8])] = [
            (0, synSeg(client, "203.0.113.10", 51000, 443).1),
            (0.01, synAckSeg("203.0.113.10", client, 443, 51000).1),
            (0.02, tcpSeg(src: client, dst: "203.0.113.10", sport: 51000, dport: 443, seq: 1000, flags: 0x18, payload: seg1)),
            (0.03, tcpSeg(src: client, dst: "203.0.113.10", sport: 51000, dport: 443, seq: 1000 + UInt32(seg1.count), flags: 0x18, payload: seg2)),
        ]
        let rep = analyze(pkts)
        let fp = rep.facts?.fingerprints.first
        T.expectEqual(fp?.sni, "api.example.com")
        T.expect(fp?.ja4.hasPrefix("t") ?? false)
        T.expect(!(fp?.ja3.isEmpty ?? true))
        let dest = rep.facts?.destinations.first { $0.address == "203.0.113.10" }
        T.expectEqual(dest?.name, "api.example.com")
        T.expectEqual(dest?.nameSource, "sni")
    }

    T.test("QUIC ClientHello split across two Initial packets, sent out of order") {
        let hello = clientHello(sni: "quic.example.com")
        let dcid: [UInt8] = [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08]
        let half = hello.count / 2
        let pkt2 = quicInitial(crypto: Array(hello.dropFirst(half)), cryptoOffset: half, pn: 1, dcid: dcid)
        let pkt1 = quicInitial(crypto: Array(hello.prefix(half)), cryptoOffset: 0, pn: 0, dcid: dcid)
        let pkts: [(Double, [UInt8])] = [
            (0, ipv4Packet(src: client, dst: "203.0.113.20", proto: 17, payload: udpPacket(sport: 52000, dport: 443, payload: pkt2))),
            (0.05, ipv4Packet(src: client, dst: "203.0.113.20", proto: 17, payload: udpPacket(sport: 52000, dport: 443, payload: pkt1))),
        ]
        let rep = analyze(pkts)
        let fp = rep.facts?.fingerprints.first
        T.expectEqual(fp?.sni, "quic.example.com")
        T.expect(fp?.quic == true)
        T.expect(fp?.ja4.hasPrefix("q") ?? false)
    }

    T.test("TLS 1.2 certificate chain spanning several segments is hashed") {
        let cert = [UInt8](repeating: 0x41, count: 300)
        let certRecord = tlsRecord(certHandshake(certs: [cert, [UInt8](repeating: 0x42, count: 120)]))
        let serverHello = tlsRecord([2, 0, 0, 0]) // minimal (parser only needs the type)
        let serverFlight = serverHello + certRecord
        // Split the server flight into three segments.
        let third = serverFlight.count / 3
        let s1 = Array(serverFlight.prefix(third))
        let s2 = Array(serverFlight.dropFirst(third).prefix(third))
        let s3 = Array(serverFlight.dropFirst(2 * third))
        let hello = tlsRecord(clientHello(sni: "api.example.com"))
        let pkts: [(Double, [UInt8])] = [
            (0, synSeg(client, "203.0.113.50", 51000, 443).1),
            (0.01, synAckSeg("203.0.113.50", client, 443, 51000).1),
            (0.02, tcpSeg(src: client, dst: "203.0.113.50", sport: 51000, dport: 443, seq: 1000, flags: 0x18, payload: hello)),
            (0.03, tcpSeg(src: "203.0.113.50", dst: client, sport: 443, dport: 51000, seq: 5000, flags: 0x18, payload: s1)),
            (0.04, tcpSeg(src: "203.0.113.50", dst: client, sport: 443, dport: 51000, seq: 5000 + UInt32(s1.count), flags: 0x18, payload: s2)),
            (0.05, tcpSeg(src: "203.0.113.50", dst: client, sport: 443, dport: 51000, seq: 5000 + UInt32(s1.count + s2.count), flags: 0x18, payload: s3)),
        ]
        let rep = analyze(pkts)
        T.expectEqual(rep.facts?.certificates.count, 1)
        T.expectEqual(rep.facts?.certificates.first?.sha1, sha1Hex(cert))
        T.expectEqual(rep.facts?.certificates.first?.sha256, sha256Hex(cert))
    }

    T.test("ECH ClientHello: outer name recorded, never used as the display name") {
        let hello = tlsRecord(clientHello(sni: "outer.public.example", ech: true))
        let pkts: [(Double, [UInt8])] = [
            (0, synSeg(client, "203.0.113.30", 51000, 443).1),
            (0.01, synAckSeg("203.0.113.30", client, 443, 51000).1),
            (0.02, tcpSeg(src: client, dst: "203.0.113.30", sport: 51000, dport: 443, seq: 1000, flags: 0x18, payload: hello)),
        ]
        let rep = analyze(pkts)
        T.expect(rep.facts?.fingerprints.first?.ech == true)
        let dest = rep.facts?.destinations.first { $0.address == "203.0.113.30" }
        T.expectEqual(dest?.name, nil)
        T.expectEqual(dest?.nameSource, "sni_outer")
        T.expectEqual(dest?.outerName, "outer.public.example")
    }

    T.test("matcher: completed connection to a listed IP + its certificate gives two high matches") {
        let cert = [UInt8](repeating: 0x41, count: 200)
        let extra = "\ncert_sha1,\(sha1Hex(cert)),botnet_c2,high"
        let store = testFeedStore(extraRows: extra)
        let hello = tlsRecord(clientHello(sni: "api.example.com"))
        let serverFlight = tlsRecord([2, 0, 0, 0]) + tlsRecord(certHandshake(certs: [cert]))
        let pkts: [(Double, [UInt8])] = [
            (0, synSeg(client, "203.0.113.50", 51000, 443).1),
            (0.01, synAckSeg("203.0.113.50", client, 443, 51000).1),
            (0.02, tcpSeg(src: client, dst: "203.0.113.50", sport: 51000, dport: 443, seq: 1000, flags: 0x18, payload: hello)),
            (0.03, tcpSeg(src: "203.0.113.50", dst: client, sport: 443, dport: 51000, seq: 5000, flags: 0x18, payload: serverFlight)),
            (0.04, tcpSeg(src: client, dst: "203.0.113.50", sport: 51000, dport: 443, seq: 1000 + UInt32(hello.count), flags: 0x10)),
        ]
        let rep = analyze(pkts)
        let outcome = IntelMatcher.match(report: rep, store: store, metas: testMetas(), allowlist: [], now: Date())
        let destMatches = outcome.matches.filter { $0.destinationIP == "203.0.113.50" }
        T.expect(destMatches.contains { $0.matchedOn == "ipv4" && $0.severity == "high" })
        T.expect(destMatches.contains { $0.matchedOn == "cert_sha1" && $0.severity == "high" })
        T.expect(destMatches.contains { $0.severityReasons.contains { $0.contains("upgraded") || $0.contains("base: high") } })
        T.expectEqual(outcome.checkedCerts, 1)
    }

    T.test("matcher: DNS-only lookup is one level lower with the attempted-not-completed reason") {
        let pkts: [(Double, [UInt8])] = [
            (0, rawUDP(src: client, dst: "192.168.1.1", sport: 40000, dport: 53, payload: dnsMessage(id: 1, response: false, name: "c2.test-ioc.example"))),
            (0.03, rawUDP(src: "192.168.1.1", dst: client, sport: 53, dport: 40000, payload: dnsMessage(id: 1, response: true, name: "c2.test-ioc.example", answers: [("c2.test-ioc.example", "203.0.113.77")]))),
        ]
        let rep = analyze(pkts)
        let outcome = IntelMatcher.match(report: rep, store: testFeedStore(), metas: testMetas(), allowlist: [], now: Date())
        let m = outcome.matches.first { $0.matchedOn == "domain" }
        T.expectEqual(m?.severity, "medium")
        T.expectEqual(m?.direction, "dns_only")
        T.expect(m?.severityReasons.contains("downgraded: contact attempted, not completed") ?? false)
    }

    T.test("matcher: subdomain matches the feed domain; the reverse would not") {
        let pkts: [(Double, [UInt8])] = [
            (0, rawUDP(src: client, dst: "192.168.1.1", sport: 40000, dport: 53, payload: dnsMessage(id: 1, response: false, name: "cdn.c2.test-ioc.example"))),
        ]
        let rep = analyze(pkts)
        let outcome = IntelMatcher.match(report: rep, store: testFeedStore(), metas: testMetas(), allowlist: [], now: Date())
        T.expect(outcome.matches.contains { $0.matchedOn == "domain" && $0.observed == "cdn.c2.test-ioc.example" })
        T.expect(!Normalize.domainMatches(feedDomain: "cdn.c2.test-ioc.example", observed: "c2.test-ioc.example"))
    }

    T.test("matcher: unanswered SYN inside a listed CIDR ends low (medium lowered for no reply)") {
        let pkts: [(Double, [UInt8])] = [
            (0, synSeg(client, "198.51.100.200", 51000, 443).1),
            (1, synSeg(client, "198.51.100.200", 51000, 443).1),
        ]
        let rep = analyze(pkts)
        let outcome = IntelMatcher.match(report: rep, store: testFeedStore(), metas: testMetas(), allowlist: [], now: Date())
        let m = outcome.matches.first { $0.matchedOn == "cidr" }
        T.expectEqual(m?.severity, "low")
        T.expect(m?.severityReasons.contains("downgraded: contact attempted, not completed") ?? false)
    }

    T.test("matcher: the private-address feed row never matches") {
        let pkts: [(Double, [UInt8])] = [
            (0, synSeg(client, "10.0.0.5", 51000, 443).1),
            (0.01, synAckSeg("10.0.0.5", client, 443, 51000).1),
        ]
        let rep = analyze(pkts)
        let outcome = IntelMatcher.match(report: rep, store: testFeedStore(), metas: testMetas(), allowlist: [], now: Date())
        T.expect(!outcome.matches.contains { $0.observed.contains("10.0.0.5") })
    }

    T.test("matcher: cleartext HTTP URL matches exactly, with the host checked as a domain") {
        let get = Array("GET /payload.bin HTTP/1.1\r\nHost: downloads.test-ioc.example\r\n\r\n".utf8)
        let ethPkts: [(Double, [UInt8])] = [
            (0, ethUDP(src: client, dst: "192.168.1.1", sport: 40000, dport: 53, payload: dnsMessage(id: 1, response: false, name: "downloads.test-ioc.example"))),
            (0.03, ethUDP(src: "192.168.1.1", dst: client, sport: 53, dport: 40000, payload: dnsMessage(id: 1, response: true, name: "downloads.test-ioc.example", answers: [("downloads.test-ioc.example", "203.0.113.60")]))),
            (0.1, ethTCP(src: client, dst: "203.0.113.60", sport: 51000, dport: 80, flags: 0x02)),
            (0.11, ethTCP(src: "203.0.113.60", dst: client, sport: 80, dport: 51000, flags: 0x12)),
            (0.12, ethTCP(src: client, dst: "203.0.113.60", sport: 51000, dport: 80, flags: 0x18, payload: get)),
        ]
        let rep = try! PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: ethPkts.map { (1000 + $0.0, $0.1) }))
        T.expect(rep.facts?.httpURLs.contains("http://downloads.test-ioc.example/payload.bin") ?? false)
        let outcome = IntelMatcher.match(report: rep, store: testFeedStore(), metas: testMetas(), allowlist: [], now: Date())
        let m = outcome.matches.first { $0.matchedOn == "url" }
        T.expectEqual(m?.severity, "high")
        T.expectEqual(m?.observed, "http://downloads.test-ioc.example/payload.bin")
    }

    T.test("step 5: one security finding per destination, alert counts destinations") {
        let cert = [UInt8](repeating: 0x41, count: 200)
        let extra = "\ncert_sha1,\(sha1Hex(cert)),botnet_c2,high"
        let store = testFeedStore(extraRows: extra)
        let hello = tlsRecord(clientHello(sni: "api.example.com"))
        let serverFlight = tlsRecord([2, 0, 0, 0]) + tlsRecord(certHandshake(certs: [cert]))
        let pkts: [(Double, [UInt8])] = [
            (0, synSeg(client, "203.0.113.50", 51000, 443).1),
            (0.01, synAckSeg("203.0.113.50", client, 443, 51000).1),
            (0.02, tcpSeg(src: client, dst: "203.0.113.50", sport: 51000, dport: 443, seq: 1000, flags: 0x18, payload: hello)),
            (0.03, tcpSeg(src: "203.0.113.50", dst: client, sport: 443, dport: 51000, seq: 5000, flags: 0x18, payload: serverFlight)),
        ]
        let rep = analyze(pkts)
        let outcome = IntelMatcher.match(report: rep, store: store, metas: testMetas(), allowlist: [], now: Date())
        let intel = ThreatIntelSummary.make(outcome: outcome, feeds: [FeedRef(id: "test_feed", name: "Synthetic test feed", updatedAt: Date().timeIntervalSince1970, stale: false, indicatorCount: store.count)], status: "checked")
        let r = CaptureResultsBuilder.build(report: rep, context: SessionContext(goal: .website, interface: "en0"), kernelDrops: 0, threatIntel: intel)
        let security = r.findings.filter { $0.category == "security" }
        T.expectEqual(security.count, 1, "two match records must become one finding for the destination")
        T.expectEqual(security.first?.matchedIndicators.count, 2)
        T.expect(security.first?.matchedIndicators.contains { $0.matchedOn == "ipv4" } ?? false)
        T.expect(security.first?.matchedIndicators.contains { $0.matchedOn == "cert_sha1" } ?? false)
        T.expectEqual(r.securityAlert, "high")
        T.expect(r.destinations.first { $0.address == "203.0.113.50" }?.intelTopSeverity == "high")
        T.expect(r.templateSummary.headline == r.templateSummary.headline) // goal verdict text is computed independently of the security finding
    }
    T.test("AI validator: threat wording rules") {
        // Results with no intel matches at all.
        var pkts: [(Double, [UInt8])] = []
        for i in 0..<12 { pkts.append((Double(i), synSeg(client, "203.0.113.99", 51000, 443).1)) }
        let rep = analyze(pkts)
        let clean = CaptureResultsBuilder.build(report: rep, context: SessionContext(goal: .website, interface: "en0"), kernelDrops: 0,
                                                threatIntel: ThreatIntelSummary.make(outcome: ThreatIntelOutcome(), feeds: [FeedRef(id: "test_feed", name: "Synthetic test feed", updatedAt: nil, stale: false, indicatorCount: 6)], status: "checked"))
        let infected = ##"{"headline":"This device is infected","body":"The device is infected with malware.","nextStep":"Scan it.","citations":[]}"##
        T.expect(SummaryValidator.validate(jsonText: infected, results: clean) == nil)
        let mentionsFeeds = ##"{"headline":"Nothing was flagged by threat feeds","body":"No matches in 4 threat feeds were found.","nextStep":"Capture again.","citations":[]}"##
        T.expect(SummaryValidator.validate(jsonText: mentionsFeeds, results: clean) == nil)
        // Fallback still renders for the same results.
        T.expect(!clean.templateSummary.headline.isEmpty)
        // With a match present, naming an absent feed or family must fail.
        let withIntel = CaptureResultsBuilder.build(report: rep, context: SessionContext(goal: .website, interface: "en0"), kernelDrops: 0,
            threatIntel: ThreatIntelSummary(status: "checked", feeds: [FeedRef(id: "test_feed", name: "Synthetic test feed", updatedAt: nil, stale: false, indicatorCount: 6)], checkedIPs: 1, checkedDomains: 0, checkedURLs: 0, checkedCerts: 0, checkedFingerprints: 0, filesChecked: false,
                matches: [ThreatMatch(id: "m1", indicator: Indicator(feedId: "test_feed", type: "ipv4", value: "203.0.113.50", threat: "botnet_c2", lastSeen: "2026-10-20"), matchedOn: "ipv4", observed: "203.0.113.50", destinationIP: "203.0.113.50", destinationPort: 443, destinationName: nil, dnsName: nil, sni: nil, url: nil, direction: "outbound", connected: true, severity: "high", severityReasons: ["base: high"], frames: [1], filter: "ip.addr==203.0.113.50", evidenceCount: 1, feedName: "Synthetic test feed", feedHomepage: "")],
                ignoredByAllowlist: 0, securityAlert: "high", securityHeadline: "x"))
        let wrongFeed = ##"{"headline":"Feodo Tracker flagged this address","body":"Feodo Tracker lists 203.0.113.50 as a botnet server.","nextStep":"Scan the device.","citations":[]}"##
        T.expect(SummaryValidator.validate(jsonText: wrongFeed, results: withIntel) == nil)
        let wrongFamily = ##"{"headline":"Emotet activity was seen","body":"The address 203.0.113.50 is linked to Emotet in October 2026.","nextStep":"Scan the device.","citations":[]}"##
        T.expect(SummaryValidator.validate(jsonText: wrongFamily, results: withIntel) == nil)
        let wrongDate = ##"{"headline":"A listed address was contacted","body":"The address 203.0.113.50 was last seen on 2025-01-15 according to the feed.","nextStep":"Scan the device.","citations":[]}"##
        T.expect(SummaryValidator.validate(jsonText: wrongDate, results: withIntel) == nil)
        T.expect(!withIntel.templateSummary.headline.isEmpty, "fallback must render")
    }
    T.test("matching covers the full observable set: match at destination 50,000 of 51,200") {
        var pkts: [(Double, [UInt8])] = []
        pkts.reserveCapacity(51201)
        for i in 0..<51200 {
            let dst = i == 50000 ? "203.0.113.50" : "45.33.\((i / 256) % 200).\(i % 256)"
            pkts.append((Double(i) * 0.001, rawUDP(src: client, dst: dst, sport: 40000, dport: 443, payload: [0xC0, 0, 0, 0, 1])))
        }
        let rep = analyze(pkts)
        T.expect((rep.facts?.observableIPCount ?? 0) >= 51200, "observable IPs: \(rep.facts?.observableIPCount ?? 0)")
        let outcome = IntelMatcher.match(report: rep, store: testFeedStore(), metas: testMetas(), allowlist: [], now: Date())
        T.expect(outcome.matches.contains { $0.observed == "203.0.113.50" && $0.matchedOn == "ipv4" }, "the 50,000th destination must still match")
        T.expect(outcome.checkedIPs >= 51200)
        T.expect(outcome.checkedIPsTotal >= outcome.checkedIPs, "total includes the device address itself")
    }
    T.test("real feed parsers accept the inspected structures and reject changes") {
        let feodoMeta = FeedMeta(id: "feodo_recommended", name: "Feodo Tracker", url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json", homepage: "", license: "CC0", requiresKey: false, enabledByDefault: true, refreshSec: 3600, minRefreshSec: 300, maxAgeSec: 86400, baseSeverity: "high", parser: "feodo_json")
        let feodo = try! FeedParser.parse(meta: feodoMeta, data: Data(##"[{"ip_address":"203.0.113.50","port":443,"malware":"TestFamily","first_seen":"2026-10-01 00:00:00","last_online":"2026-10-26"}]"##.utf8))
        T.expectEqual(feodo.indicators.count, 1)
        T.expectEqual(feodo.indicators.first?.malwareFamily, "TestFamily")
        expectThrows({ _ = try FeedParser.parse(meta: feodoMeta, data: Data(##"{"not":"an array"}"##.utf8)) }) { ($0 as? FeedParseError) != nil }

        let certMeta = FeedMeta(id: "sslbl_certs", name: "SSLBL", url: "https://sslbl.abuse.ch/blacklist/sslblacklist.csv", homepage: "", license: "CC0", requiresKey: false, enabledByDefault: true, refreshSec: 3600, minRefreshSec: 300, maxAgeSec: 86400, baseSeverity: "high", parser: "sslbl_certs_csv")
        let certs = try! FeedParser.parse(meta: certMeta, data: Data("# comment header\n2026-10-27 15:35:42,b3419f377a0765d386af3f3a61bede653db873f7,TestRAT C&C\n".utf8))
        // The real file uses CRLF: Swift grapheme clusters would otherwise
        // hide every line break from a naive split.
        let crlf = try! FeedParser.parse(meta: certMeta, data: Data("# comment header\r\n2026-10-27 15:35:42,b3419f377a0765d386af3f3a61bede653db873f7,TestRAT C&C\r\n2026-10-27 15:02:13,891b265025da1fe909b4792dfe0f3df462694bef,TestWise C&C\r\n".utf8))
        T.expectEqual(crlf.indicators.count, 2, "CRLF feed must parse")
        T.expectEqual(certs.indicators.first?.type, "cert_sha1")
        T.expectEqual(certs.indicators.first?.malwareFamily, "TestRAT C&C")

        let dropMeta = FeedMeta(id: "spamhaus_drop", name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop_v4.json", homepage: "", license: "Spamhaus DROP terms", requiresKey: false, enabledByDefault: true, refreshSec: 86400, minRefreshSec: 86400, maxAgeSec: 259200, baseSeverity: "medium", parser: "spamhaus_drop_json")
        let drop = try! FeedParser.parse(meta: dropMeta, data: Data(##"{"cidr":"198.51.100.128/25","sblid":"SBL000","rir":"test"}"##.utf8) + Data("\n".utf8) + Data(##"{"type":"metadata","timestamp":1793124842,"records":1,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}"##.utf8))
        T.expectEqual(drop.indicators.count, 1)
        T.expectEqual(drop.feedCopyright, "(c) 2026 The Spamhaus Project SLU")
        T.expect(drop.feedTerms?.contains("spamhaus") ?? false)
        T.expectEqual(FeedUpdater.newestIndicatorDate(drop.indicators) , nil)
    }
    T.test("a structurally valid feed with zero data rows is accepted, not a failure") {
        let dir = tempDirForFeeds(); defer { try? FileManager.default.removeItem(at: dir) }
        let meta = FeedMeta(id: "test_feed", name: "Synthetic", url: "https://feeds.invalid/test.csv", homepage: "", license: "Test", requiresKey: false, enabledByDefault: true, refreshSec: 3600, minRefreshSec: 0, maxAgeSec: 86400, baseSeverity: "high", parser: "test_csv")
        let mock = MockTransportForFeeds()
        mock.responses = [FeedTransportResponse(status: 200, data: Data(testFeedCSVForParser.utf8)),
                          FeedTransportResponse(status: 200, data: Data("type,value,threat,severity\n".utf8))]
        let updater = FeedUpdater(directory: dir, transport: mock, keyStore: InMemoryKeyStore())
        runAsyncForFeeds {
            let (s1, _) = await updater.update(feed: meta, now: Date(), manual: true)
            T.expectEqual(s1.indicatorCount, 6)
            let (s2, o2) = await updater.update(feed: meta, now: Date().addingTimeInterval(10), manual: true)
            T.expect(o2 == .updated, "zero-row file must be accepted, got \(o2)")
            T.expectEqual(s2.indicatorCount, 0)
            // And the persisted index loads in well under a second for reuse.
            let t0 = Date()
            let (store, _) = updater.loadStore(now: Date())
            T.expect(Date().timeIntervalSince(t0) < 1.0)
            T.expectEqual(store.count, 0)
        }
    }
    T.test("support report defangs indicators and credits feeds, with no key material") {
        let m = ThreatMatch(id: "x", indicator: Indicator(feedId: "test_feed", type: "ipv4", value: "203.0.113.50", threat: "botnet_c2", lastSeen: "2026-10-26"), matchedOn: "ipv4", observed: "203.0.113.50", destinationIP: "203.0.113.50", destinationPort: 443, destinationName: nil, dnsName: nil, sni: nil, url: nil, direction: "outbound", connected: true, severity: "high", severityReasons: ["base: high"], frames: [1], filter: "ip.addr==203.0.113.50", evidenceCount: 3, feedName: "Synthetic test feed", feedHomepage: "")
        let intel = ThreatIntelSummary.make(outcome: ThreatIntelOutcome(matches: [m], checkedIPs: 3), feeds: [FeedRef(id: "test_feed", name: "Synthetic test feed", updatedAt: nil, stale: false, indicatorCount: 6)], status: "checked")
        var rep = CaptureReport(packetCount: 20, capturedBytes: 1000, duration: 10)
        rep.facts = CaptureFacts()
        let text = ReportText.supportReport(report: rep, context: SessionContext(interface: "en0"), options: SupportOptions(), comparison: nil, threatIntel: intel)
        T.expect(text.contains("203[.]0[.]113[.]50"), "indicator must be defanged in exports")
        T.expect(!text.contains("203.0.113.50:443") || text.contains("[.]"), "raw indicator form should not be the displayed form")
        T.expect(text.contains("Threat feed matching"))
    }
    T.test("matcher: allowlisted indicator is counted as ignored, not matched") {
        let pkts: [(Double, [UInt8])] = [
            (0, synSeg(client, "203.0.113.50", 51000, 443).1),
            (0.01, synAckSeg("203.0.113.50", client, 443, 51000).1),
        ]
        let rep = analyze(pkts)
        let outcome = IntelMatcher.match(report: rep, store: testFeedStore(), metas: testMetas(), allowlist: [AllowlistEntry(value: "203.0.113.50", reason: "test", addedAt: 0)], now: Date())
        T.expect(!outcome.matches.contains { $0.observed == "203.0.113.50" })
        T.expectEqual(outcome.ignoredByAllowlist, 1)
    }
}

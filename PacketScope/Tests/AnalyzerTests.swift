import Foundation

// Minimal test harness + synthetic PCAP builders (tests only; never used by the app).
enum TestHarness {
    static var passed = 0
    static var failed = 0
    static var currentFailures: [String] = []
    static func test(_ name: String, _ body: () throws -> Void) {
        currentFailures = []
        do {
            try body()
            if currentFailures.isEmpty { passed += 1; print("PASS \(name)") }
            else { failed += 1; print("FAIL \(name): \(currentFailures.joined(separator: "; "))") }
        } catch { failed += 1; print("FAIL \(name): \(error)") }
        fflush(stdout)
    }
    static func expect(_ cond: @autoclosure () -> Bool, _ msg: String = "") {
        if !cond() { currentFailures.append("expectation failed \(msg)") }
    }
    static func expectEqual<T: Equatable>(_ a: @autoclosure () -> T, _ b: @autoclosure () -> T, _ msg: String = "") {
        if a() != b() { currentFailures.append("expected \(b()) got \(a()) \(msg)") }
    }
    static func finish() -> Int32 {
        print("---")
        print("\(passed) test cases passed, \(failed) failed")
        return failed == 0 ? 0 : 1
    }
}

func u16be(_ v: Int) -> [UInt8] { [UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }
func u32be(_ v: UInt32) -> [UInt8] { [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }

func buildPCAP(linkType: Int, packets: [(Double, [UInt8])], little: Bool = true, nano: Bool = false, snaplen: Int = 65535, versionMinor: Int = 4) -> Data {
    var out: [UInt8] = []
    func w16(_ v: Int) { if little { out += [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF)] } else { out += u16be(v) } }
    func w32(_ v: UInt32) { if little { out += [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 24) & 0xFF)] } else { out += u32be(v) } }
    // magic written so the reader sees the intended byte order
    if little { out += nano ? [0x4D, 0x3C, 0xB2, 0xA1] : [0xD4, 0xC3, 0xB2, 0xA1] }
    else { out += nano ? [0xA1, 0xB2, 0x3C, 0x4D] : [0xA1, 0xB2, 0xC3, 0xD4] }
    w16(2); w16(versionMinor); w32(0); w32(0); w32(UInt32(snaplen)); w32(UInt32(linkType))
    for (ts, frame) in packets {
        let sec = UInt32(ts)
        let fracD = ts - Double(sec)
        let frac = nano ? UInt32(fracD * 1_000_000_000) : UInt32(fracD * 1_000_000)
        w32(sec); w32(frac); w32(UInt32(frame.count)); w32(UInt32(frame.count))
        out += frame
    }
    return Data(out)
}

func ipv4Packet(src: String, dst: String, proto: Int, payload: [UInt8], fragment: Bool = false) -> [UInt8] {
    let s = src.split(separator: ".").map { UInt8($0)! }
    let d = dst.split(separator: ".").map { UInt8($0)! }
    var h: [UInt8] = [0x45, 0x00]
    h += u16be(20 + payload.count); h += u16be(1); h += u16be(fragment ? 0x2000 : 0)
    h += [64, UInt8(proto), 0, 0]; h += s; h += d
    return h + payload
}
func udpPacket(sport: Int, dport: Int, payload: [UInt8]) -> [UInt8] { u16be(sport) + u16be(dport) + u16be(8 + payload.count) + u16be(0) + payload }
func tcpPacket(sport: Int, dport: Int, flags: UInt8, payload: [UInt8] = []) -> [UInt8] {
    var h = u16be(sport) + u16be(dport) + u32be(1) + u32be(1)
    h += [0x50, flags]; h += u16be(8192); h += u16be(0); h += u16be(0)
    return h + payload
}
func ethFrame(ethertype: Int, payload: [UInt8], vlan: Int? = nil) -> [UInt8] {
    var f: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
    if let v = vlan { f += u16be(0x8100) + u16be(v) }
    f += u16be(ethertype); return f + payload
}
func dnsName(_ name: String) -> [UInt8] {
    var out: [UInt8] = []
    for label in name.split(separator: ".") { out.append(UInt8(label.count)); out += Array(label.utf8) }
    out.append(0); return out
}
func dnsMessage(id: Int, response: Bool, rcode: Int = 0, name: String, answers: [(String, String)] = [], truncatedFlag: Bool = false) -> [UInt8] {
    let flags = (response ? 0x8000 : 0) | (truncatedFlag ? 0x0200 : 0) | rcode
    var m = u16be(id) + u16be(flags) + u16be(1) + u16be(answers.count) + u16be(0) + u16be(0)
    m += dnsName(name) + u16be(1) + u16be(1)
    for (owner, ip) in answers {
        m += dnsName(owner) + u16be(1) + u16be(1) + u32be(60) + u16be(4)
        m += ip.split(separator: ".").map { UInt8($0)! }
    }
    return m
}
func ethUDP(src: String, dst: String, sport: Int, dport: Int, payload: [UInt8]) -> [UInt8] {
    ethFrame(ethertype: 0x0800, payload: ipv4Packet(src: src, dst: dst, proto: 17, payload: udpPacket(sport: sport, dport: dport, payload: payload)))
}
func ethTCP(src: String, dst: String, sport: Int, dport: Int, flags: UInt8, payload: [UInt8] = []) -> [UInt8] {
    ethFrame(ethertype: 0x0800, payload: ipv4Packet(src: src, dst: dst, proto: 6, payload: tcpPacket(sport: sport, dport: dport, flags: flags, payload: payload)))
}
func rawUDP(src: String, dst: String, sport: Int, dport: Int, payload: [UInt8]) -> [UInt8] {
    ipv4Packet(src: src, dst: dst, proto: 17, payload: udpPacket(sport: sport, dport: dport, payload: payload))
}

func expectThrows(_ body: () throws -> Void, _ check: (Error) -> Bool) {
    do { try body(); TestHarness.currentFailures.append("expected throw") } catch { if !check(error) { TestHarness.currentFailures.append("wrong error: \(error)") } }
}

func registerAnalyzerTests() {
    let T = TestHarness.self
    T.test("empty and truncated PCAP rejected") {
        expectThrows({ _ = try PacketAnalyzer.analyze(data: Data()) }) { $0 is AnalyzerError }
        expectThrows({ _ = try PacketAnalyzer.analyze(data: Data([0xD4, 0xC3, 0xB2, 0xA1, 0])) }) { $0 is AnalyzerError }
    }
    T.test("PCAPNG explicitly rejected") {
        expectThrows({ _ = try PacketAnalyzer.analyze(data: Data([0x0A, 0x0D, 0x0D, 0x0A] + [UInt8](repeating: 0, count: 24))) }) {
            ($0 as? AnalyzerError)?.errorDescription?.contains("PCAPNG") ?? false
        }
    }
    T.test("unsupported link type and version rejected") {
        expectThrows({ _ = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 999, packets: [])) }) { ($0 as? AnalyzerError) != nil }
        expectThrows({ _ = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [], versionMinor: 9)) }) { ($0 as? AnalyzerError) != nil }
    }
    T.test("invalid record lengths and fractions rejected") {
        var d = buildPCAP(linkType: 1, packets: [(1.0, ethUDP(src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: []))])
        // corrupt fraction (bytes 28..32 little endian)
        d[28] = 0xFF; d[29] = 0xFF; d[30] = 0xFF; d[31] = 0xFF
        expectThrows({ _ = try PacketAnalyzer.analyze(data: d) }) { ($0 as? AnalyzerError) != nil }
    }
    T.test("big-endian microsecond DNS query and matched reply timing") {
        let q = ethUDP(src: "192.168.1.10", dst: "8.8.8.8", sport: 40000, dport: 53, payload: dnsMessage(id: 7, response: false, name: "example.com"))
        let r = ethUDP(src: "8.8.8.8", dst: "192.168.1.10", sport: 53, dport: 40000, payload: dnsMessage(id: 7, response: true, name: "example.com", answers: [("example.com", "93.184.216.34")]))
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1000.0, q), (1000.25, r)], little: false))
        T.expectEqual(rep.packetCount, 2)
        T.expectEqual(rep.facts?.matchedDNSPairs, 1)
        T.expect(abs((rep.facts?.averageDNSMilliseconds ?? 0) - 250) < 1)
        T.expectEqual(rep.facts?.domains.first?.name, "example.com")
        T.expectEqual(rep.facts?.domains.first?.addresses, ["93.184.216.34"])
        T.expectEqual(rep.packets.first?.hostname, "example.com")
    }
    T.test("nanosecond timestamps parsed") {
        let p = ethUDP(src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: [1, 2, 3])
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 101, packets: [(5.5, rawUDP(src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: [1]))], nano: true))
        _ = p
        T.expect(abs((rep.facts?.firstTimestamp ?? 0) - 5.5) < 0.001)
    }
    T.test("full-file statistics beyond 2000 displayed rows") {
        var pkts: [(Double, [UInt8])] = []
        for i in 0..<2005 { pkts.append((Double(2000 + i), ethUDP(src: "10.0.0.1", dst: "10.0.0.2", sport: 1000, dport: 2000, payload: [1]))) }
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: pkts))
        T.expectEqual(rep.packetCount, 2005)
        T.expectEqual(rep.packets.count, 2000)
        T.expectEqual(rep.facts?.timeline.reduce(0) { $0 + $1.packets }, 2005)
        T.expect(rep.limitationNotes.contains { $0.contains("2,000") || $0.contains("2000") })
    }
    T.test("DNS error finding and denominators") {
        let q = ethUDP(src: "10.0.0.1", dst: "8.8.8.8", sport: 40000, dport: 53, payload: dnsMessage(id: 1, response: false, name: "bad.example.com"))
        let r = ethUDP(src: "8.8.8.8", dst: "10.0.0.1", sport: 53, dport: 40000, payload: dnsMessage(id: 1, response: true, rcode: 3, name: "bad.example.com"))
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, q), (2, r)]))
        T.expectEqual(rep.facts?.dnsResponses, 1); T.expectEqual(rep.facts?.dnsErrors, 1)
        T.expect(rep.findings.contains { $0.id == "dns-errors" && $0.packetNumbers == [2] })
    }
    T.test("TCP reset finding with TCP denominator") {
        let rst = ethTCP(src: "10.0.0.1", dst: "10.0.0.2", sport: 1234, dport: 443, flags: 0x04)
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, rst)]))
        T.expectEqual(rep.facts?.tcpPackets, 1); T.expectEqual(rep.facts?.tcpResets, 1)
        T.expect(rep.findings.contains { $0.id == "tcp-resets" })
    }
    T.test("plaintext remote and loopback kept as separate findings") {
        let remote = ethTCP(src: "192.168.1.5", dst: "93.184.216.34", sport: 5000, dport: 80, flags: 0x18, payload: Array("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8))
        let local = ethTCP(src: "127.0.0.1", dst: "127.0.0.1", sport: 5001, dport: 8080, flags: 0x18, payload: Array("GET / HTTP/1.1\r\n\r\n".utf8))
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, remote), (2, local)]))
        T.expect(rep.findings.contains { $0.id == "plaintext-remote" && $0.severity == "warning" })
        T.expect(rep.findings.contains { $0.id == "plaintext-local" && $0.severity == "info" })
        T.expect(!rep.packets[0].summary.contains("example.com\r")) // summaries never embed raw payload lines verbatim beyond a safe prefix-free description
    }
    T.test("port number alone does not declare plaintext") {
        let bin = ethTCP(src: "10.0.0.1", dst: "10.0.0.2", sport: 5000, dport: 80, flags: 0x18, payload: [0x00, 0xFF, 0x10, 0x80, 0x01, 0x02])
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, bin)]))
        T.expect(!rep.findings.contains { $0.id.hasPrefix("plaintext") })
        T.expectEqual(rep.packets.first?.protocolName, "TCP")
    }
    T.test("IPv4 fragment is counted without transport decode") {
        let f = ethFrame(ethertype: 0x0800, payload: ipv4Packet(src: "10.0.0.1", dst: "10.0.0.2", proto: 6, payload: tcpPacket(sport: 1, dport: 2, flags: 0x04), fragment: true))
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, f)]))
        T.expectEqual(rep.facts?.tcpPackets, 0)
        T.expect(rep.packets.first?.summary.contains("fragment") ?? false)
    }
    T.test("IPv6 with extension header decodes UDP") {
        let dns = dnsMessage(id: 3, response: false, name: "v6.example.com")
        let udp = udpPacket(sport: 40000, dport: 53, payload: dns)
        var pkt: [UInt8] = [0x60, 0, 0, 0]
        pkt += u16be(8 + udp.count)
        pkt += [0, 64] // next header = hop-by-hop, hop limit
        pkt += [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1] // ::1
        pkt += [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2] // ::2
        pkt += [17, 0, 0, 0, 0, 0, 0, 0] // hop-by-hop: next=UDP, 8 bytes total
        pkt += udp
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 101, packets: [(1, pkt)]))
        T.expectEqual(rep.packets.first?.protocolName, "DNS")
        T.expectEqual(rep.packets.first?.source, "::1")
    }
    T.test("PKTAP v1 attribution, direction, and Unknown for ordinary PCAP") {
        // v1 header: len 156, type 1, dlt=1 (Ethernet), ifname, flags dir-out, pid, comm
        var hdr = [UInt8](repeating: 0, count: 156)
        func put32(_ o: Int, _ v: Int) { hdr[o] = UInt8(v & 0xFF); hdr[o+1] = UInt8((v >> 8) & 0xFF); hdr[o+2] = UInt8((v >> 16) & 0xFF); hdr[o+3] = UInt8((v >> 24) & 0xFF) }
        put32(0, 156); put32(4, 1); put32(8, 1); put32(36, 2); put32(52, 4242)
        let comm = Array("TestApp".utf8); for (i, c) in comm.enumerated() { hdr[56 + i] = c }
        let frame = hdr + ethUDP(src: "10.0.0.5", dst: "8.8.8.8", sport: 1000, dport: 53, payload: dnsMessage(id: 1, response: false, name: "a.example.com"))
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 258, packets: [(1, frame)]))
        let app = rep.facts?.applications.first
        T.expectEqual(app?.name, "TestApp"); T.expectEqual(app?.processID, 4242)
        T.expectEqual(rep.facts?.attributedPackets, 1)
        T.expect(app?.sentBytes ?? 0 > 0)
        T.expectEqual(rep.packets.first?.processName, "TestApp")
        T.expectEqual(rep.packets.first?.direction, "outgoing")
        // Ordinary PCAP: everything Unknown.
        let plain = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, ethUDP(src: "10.0.0.5", dst: "8.8.8.8", sport: 1, dport: 2, payload: [1]))]))
        T.expectEqual(plain.facts?.applications.first?.name, "Unknown")
        T.expectEqual(plain.facts?.unattributedPackets, 1)
    }
    T.test("PKTAP v2 attribution and malformed PKTAP counted honestly") {
        var hdr = [UInt8](repeating: 0, count: 116)
        hdr[0] = 116 // total header length used by parser when variable fields follow
        hdr[3] = 72   // ifname offset
        hdr[4] = 96   // comm offset
        hdr[5] = 0
        hdr[6] = 1; hdr[7] = 0 // dlt Ethernet (little endian)
        func put32(_ o: Int, _ v: Int) { hdr[o] = UInt8(v & 0xFF); hdr[o+1] = UInt8((v >> 8) & 0xFF); hdr[o+2] = UInt8((v >> 16) & 0xFF); hdr[o+3] = UInt8((v >> 24) & 0xFF) }
        put32(28, 777) // pid
        put32(36, 0x00080001) // V2 flag + direction in
        for (i, c) in Array("lo0".utf8).enumerated() { hdr[72 + i] = c }
        for (i, c) in Array("V2App".utf8).enumerated() { hdr[96 + i] = c }
        let frame = hdr + ethUDP(src: "8.8.8.8", dst: "10.0.0.5", sport: 53, dport: 1000, payload: dnsMessage(id: 2, response: true, name: "b.example.com"))
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 149, packets: [(1, frame)]))
        T.expectEqual(rep.facts?.applications.first?.name, "V2App")
        T.expectEqual(rep.packets.first?.direction, "incoming")
        T.expect(rep.facts?.applications.first?.receivedBytes ?? 0 > 0)
        // Malformed: header length longer than frame.
        var bad = [UInt8](repeating: 0, count: 40)
        bad[0] = 200; bad[1] = 0; bad[2] = 0; bad[3] = 0
        let rep2 = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 258, packets: [(1, bad)]))
        T.expectEqual(rep2.packetCount, 1)
        T.expectEqual(rep2.facts?.applications.first?.name, "Unknown")
    }
    T.test("VLAN-tagged Ethernet decodes IPv4") {
        let inner = ipv4Packet(src: "10.1.1.1", dst: "10.1.1.2", proto: 17, payload: udpPacket(sport: 7, dport: 7, payload: [9]))
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, ethFrame(ethertype: 0x0800, payload: inner, vlan: 42))]))
        T.expectEqual(rep.packets.first?.source, "10.1.1.1")
    }
    T.test("cyclic DNS compression pointer does not crash or match") {
        var m = u16be(9) + u16be(0) + u16be(1) + u16be(0) + u16be(0) + u16be(0)
        m += [0xC0, 0x0C] + u16be(1) + u16be(1) // pointer to itself
        let pkt = ethUDP(src: "10.0.0.1", dst: "8.8.8.8", sport: 40000, dport: 53, payload: m)
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, pkt)]))
        T.expectEqual(rep.packetCount, 1)
        T.expectEqual(rep.facts?.dnsResponses, 0)
    }
    T.test("DNS retries and duplicate responses excluded from timing; mDNS excluded") {
        let q = ethUDP(src: "10.0.0.1", dst: "8.8.8.8", sport: 40000, dport: 53, payload: dnsMessage(id: 5, response: false, name: "retry.example.com"))
        let r = ethUDP(src: "8.8.8.8", dst: "10.0.0.1", sport: 53, dport: 40000, payload: dnsMessage(id: 5, response: true, name: "retry.example.com"))
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, q), (1.1, q), (1.2, r), (1.3, r)]))
        T.expectEqual(rep.facts?.matchedDNSPairs, 0)
        let mdns = ethUDP(src: "10.0.0.1", dst: "224.0.0.251", sport: 5353, dport: 5353, payload: dnsMessage(id: 0, response: false, name: "printer.local"))
        let rep2 = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, mdns)]))
        T.expectEqual(rep2.packets.first?.protocolName, "mDNS")
        T.expectEqual(rep2.facts?.matchedDNSPairs, 0)
    }
    T.test("TCP DNS within one packet matches; truncated DNS excluded") {
        let qmsg = dnsMessage(id: 8, response: false, name: "tcp.example.com")
        let q = ethTCP(src: "10.0.0.1", dst: "8.8.8.8", sport: 40000, dport: 53, flags: 0x18, payload: u16be(qmsg.count) + qmsg)
        let rmsg = dnsMessage(id: 8, response: true, name: "tcp.example.com")
        let r = ethTCP(src: "8.8.8.8", dst: "10.0.0.1", sport: 53, dport: 40000, flags: 0x18, payload: u16be(rmsg.count) + rmsg)
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: [(1, q), (1.5, r)]))
        T.expectEqual(rep.facts?.matchedDNSPairs, 1)
    }
    T.test("import-size limit enforced in analyzer") {
        expectThrows({ _ = try PacketAnalyzer.analyze(data: Data(count: PacketAnalyzer.maxFileBytes + 1)) }) {
            ($0 as? AnalyzerError)?.errorDescription?.contains("100 MiB") ?? false
        }
    }
    T.test("empty capture is a valid honest report") {
        let rep = try PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: []))
        T.expectEqual(rep.packetCount, 0)
        T.expect(rep.limitationNotes.contains { $0.contains("no packets") })
    }
}

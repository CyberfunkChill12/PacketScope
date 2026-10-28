import Foundation

private func syn(_ src: String, _ dst: String, _ sport: Int, _ dport: Int) -> [UInt8] {
    ethTCP(src: src, dst: dst, sport: sport, dport: dport, flags: 0x02)
}
private func synAck(_ src: String, _ dst: String, _ sport: Int, _ dport: Int) -> [UInt8] {
    ethTCP(src: src, dst: dst, sport: sport, dport: dport, flags: 0x12)
}
private func ack(_ src: String, _ dst: String, _ sport: Int, _ dport: Int) -> [UInt8] {
    ethTCP(src: src, dst: dst, sport: sport, dport: dport, flags: 0x10)
}
private func dnsPair(id: Int, name: String, server: String = "192.168.1.1", answer: String? = nil, rcode: Int = 0) -> [(Double, [UInt8])] {
    let q = ethUDP(src: "192.168.1.23", dst: server, sport: 40000 + id, dport: 53, payload: dnsMessage(id: id, response: false, name: name))
    let answers: [(String, String)] = answer.map { [(name, $0)] } ?? []
    let r = ethUDP(src: server, dst: "192.168.1.23", sport: 53, dport: 40000 + id, payload: dnsMessage(id: id, response: true, rcode: rcode, name: name, answers: answers))
    return [(0, q), (0.03, r)]
}
private func results(for packets: [(Double, [UInt8])], base: Double = 1000, goal: CaptureGoal = .website, markers: [Double] = [], durationHint: Double = 0) -> (CaptureReport, CaptureResults) {
    let timed = packets.map { (base + $0.0, $0.1) }
    let rep = try! PacketAnalyzer.analyze(data: buildPCAP(linkType: 1, packets: timed))
    var ctx = SessionContext(goal: goal, interface: "en0", startedAt: base)
    ctx.markers = markers.map { ProblemMarker(timestamp: base + $0) }
    return (rep, CaptureResultsBuilder.build(report: rep, context: ctx, kernelDrops: 0))
}

func registerResultsTests() {
    let T = TestHarness.self

    T.test("fixture normal short capture is inconclusive with quantified coverage") {
        var pkts: [(Double, [UInt8])] = []
        var t = 0.0
        for i in 1...9 {
            for (dt, f) in dnsPair(id: i, name: "host\(i).example.com", answer: "203.0.113.\(10 + i)") { pkts.append((t + dt, f)) }
            t += 0.3
        }
        // 4 successful TCP connections
        for i in 0..<4 {
            let ip = "203.0.113.\(11 + i)"
            pkts.append((t, syn("192.168.1.23", ip, 51000 + i, 443)))
            pkts.append((t + 0.02, synAck(ip, "192.168.1.23", 443, 51000 + i)))
            pkts.append((t + 0.04, ack("192.168.1.23", ip, 51000 + i, 443)))
            t += 0.2
        }
        // 71 QUIC packets (encrypted, skipped) + a few other UDP
        for _ in 0..<71 { pkts.append((t, ethUDP(src: "192.168.1.23", dst: "198.51.100.24", sport: 52000, dport: 443, payload: [0xC0, 0, 0, 0, 1, 9, 9, 9]))); t += 0.01 }
        let (rep, r) = results(for: pkts)
        T.expectEqual(r.verdict, "inconclusive")
        T.expect(r.tooShort)
        T.expectEqual(r.packets, rep.packetCount)
        T.expectEqual(r.mix.reduce(0) { $0 + $1.count }, r.packets, "mix must add up")
        T.expectEqual(r.skipped.first?.reason, "encrypted_quic")
        T.expectEqual(r.skipped.first?.packets, 71)
        T.expectEqual(r.checkedPackets, r.packets - 71)
        T.expectEqual(r.dnsAnswered, 9)
        T.expect(r.dnsAvgMs != nil)
    }

    T.test("fixture unanswered connection is a likely cause, step 3 failed here") {
        var pkts: [(Double, [UInt8])] = []
        for (dt, f) in dnsPair(id: 1, name: "api.example.com", answer: "203.0.113.10") { pkts.append((dt + 11.9, f)) }
        let synTimes = [12.04, 13.05, 15.07, 19.10, 27.12, 33.04]
        for (i, st) in synTimes.enumerated() {
            pkts.append((st, syn("192.168.1.23", "203.0.113.10", i == 5 ? 51562 : 51544, 443)))
        }
        // One other connection succeeds, so the internet path itself works.
        pkts.append((5, syn("192.168.1.23", "203.0.113.99", 51000, 443)))
        pkts.append((5.05, synAck("203.0.113.99", "192.168.1.23", 443, 51000)))
        pkts.append((5.08, ack("192.168.1.23", "203.0.113.99", 51000, 443)))
        // Filler answered traffic so the capture holds >= 10 packets and spans ~60 s.
        for i in 0..<12 { pkts.append((40 + Double(i), ack("192.168.1.23", "203.0.113.99", 51000, 443))) }
        pkts.sort { $0.0 < $1.0 }
        let (rep, r) = results(for: pkts, markers: [14])
        T.expectEqual(r.verdict, "cause_found")
        let dest = r.destinations.first(where: { $0.address == "203.0.113.10" })
        T.expectEqual(dest?.outcome, "no_reply")
        T.expectEqual(dest?.name, "api.example.com")
        T.expectEqual(dest?.nameSource, "dns")
        let path = r.paths.first(where: { $0.destination == "api.example.com" })
        T.expectEqual(path?.stages.first(where: { $0.id == "tcp" })?.status, "failed")
        T.expectEqual(path?.stages.first(where: { $0.id == "tls" })?.status, "not_reached")
        T.expectEqual(path?.stages.first(where: { $0.id == "app" })?.status, "not_reached")
        let finding = r.findings.first(where: { $0.id == "unanswered-connection" })
        T.expectEqual(finding?.severity, "likely_cause")
        T.expectEqual(finding?.evidence.count, 6)
        T.expectEqual(finding?.evidence.frames.count, 6)
        T.expect(finding?.evidence.filter.hasPrefix("frame.number in {") ?? false, "unanswered evidence filter must be built from evidence frames, got \(finding?.evidence.filter ?? "-")")
        _ = rep
    }

    T.test("fixture nonexistent name fails at step 2 and names the domain") {
        var pkts: [(Double, [UInt8])] = []
        for (dt, f) in dnsPair(id: 1, name: "no-such-host-4821.example.com", rcode: 3) { pkts.append((dt, f)) }
        for i in 0..<10 { pkts.append((1 + Double(i), ack("192.168.1.23", "203.0.113.5", 51000, 443))) }
        let (_, r) = results(for: pkts)
        T.expectEqual(r.verdict, "cause_found")
        T.expect(r.findings.contains { $0.id == "dns-name-not-found" && $0.title.contains("no-such-host-4821.example.com") })
        T.expectEqual(r.paths.first?.stages.first(where: { $0.id == "dns" })?.status, "failed")
    }

    T.test("fixture refused connection says refused, not never answered") {
        var pkts: [(Double, [UInt8])] = [(0, syn("192.168.1.23", "192.168.1.1", 51000, 81)),
                                         (0.05, ethTCP(src: "192.168.1.1", dst: "192.168.1.23", sport: 81, dport: 51000, flags: 0x14))]
        for i in 0..<10 { pkts.append((1 + Double(i), ack("192.168.1.23", "203.0.113.5", 51001, 443))) }
        let (_, r) = results(for: pkts)
        let dest = r.destinations.first(where: { $0.address == "192.168.1.1" })
        T.expectEqual(dest?.outcome, "refused")
        T.expect(r.findings.contains { $0.id == "refused-connection" })
        T.expect(!r.findings.contains { $0.id == "unanswered-connection" })
        T.expect(r.findings.first(where: { $0.id == "refused-connection" })?.observed.contains("refused") ?? false)
    }

    T.test("fixture mostly encrypted shows checked vs skipped with reason") {
        var pkts: [(Double, [UInt8])] = []
        for (dt, f) in dnsPair(id: 1, name: "video.example.com", answer: "198.51.100.24") { pkts.append((dt, f)) }
        for i in 0..<40 { pkts.append((1 + Double(i) * 0.5, ethUDP(src: "192.168.1.23", dst: "198.51.100.24", sport: 52000, dport: 443, payload: [0xC0, 0, 0, 0, 1, 1, 2, 3]))) }
        let (_, r) = results(for: pkts, markers: [2])
        T.expectEqual(r.destinations.first(where: { $0.address == "198.51.100.24" })?.outcome, "not_checked")
        T.expectEqual(r.skipped.first?.reason, "encrypted_quic")
        T.expectEqual(r.skipped.first?.packets, 40)
        T.expect(r.checkedPercent < 70)
        T.expectEqual(r.verdict, "inconclusive")
        T.expectEqual(r.mix.reduce(0) { $0 + $1.count }, r.packets)
    }

    T.test("DNS stats report average, p95 and slowest; unanswered counted separately") {
        var pkts: [(Double, [UInt8])] = []
        for (dt, f) in dnsPair(id: 1, name: "a.example.com", answer: "203.0.113.1") { pkts.append((dt, f)) }
        // Unanswered query for another name.
        pkts.append((1, ethUDP(src: "192.168.1.23", dst: "192.168.1.1", sport: 41000, dport: 53, payload: dnsMessage(id: 99, response: false, name: "silent.example.com"))))
        for i in 0..<10 { pkts.append((2 + Double(i), ack("192.168.1.23", "203.0.113.5", 51000, 443))) }
        let (_, r) = results(for: pkts)
        T.expectEqual(r.dnsQueries, 2)
        T.expectEqual(r.dnsAnswered, 1)
        T.expectEqual(r.dnsUnanswered, 1)
        T.expect(r.dnsAvgMs != nil && r.dnsMaxMs != nil && r.dnsP95Ms != nil)
        T.expectEqual(r.dnsLookups.first(where: { $0.name == "silent.example.com" })?.milliseconds, nil)
    }

    T.test("every number in the template summary exists in the structured results") {
        var pkts: [(Double, [UInt8])] = []
        for (dt, f) in dnsPair(id: 1, name: "api.example.com", answer: "203.0.113.10") { pkts.append((dt + 11.9, f)) }
        for st in [12.04, 13.05, 15.07, 19.10] { pkts.append((st, syn("192.168.1.23", "203.0.113.10", 51544, 443))) }
        for i in 0..<10 { pkts.append((40 + Double(i), ack("192.168.1.23", "203.0.113.99", 51000, 443))) }
        pkts.sort { $0.0 < $1.0 }
        let (_, r) = results(for: pkts, markers: [14])
        let allowed = SummaryValidator.allowedNumberTokens(results: r)
        let text = r.templateSummary.headline + " " + r.templateSummary.body
        for token in SummaryValidator.matches(#"[0-9][0-9,]*\.?[0-9]*"#, in: text) {
            let v = Double(token.replacingOccurrences(of: ",", with: ""))!
            let variants: Set<String> = [token, String(v), String(format: "%.1f", v), String(format: "%.0f", v)]
            T.expect(!variants.isDisjoint(with: allowed), "number \(token) not in results")
        }
    }

    T.test("summary validator rejects invented numbers, bad citations, long headlines") {
        var pkts: [(Double, [UInt8])] = []
        for (dt, f) in dnsPair(id: 1, name: "api.example.com", answer: "203.0.113.10") { pkts.append((dt, f)) }
        for i in 0..<12 { pkts.append((1 + Double(i), ack("192.168.1.23", "203.0.113.10", 51000, 443))) }
        let (_, r) = results(for: pkts, markers: [1])
        let good = ##"{"headline":"Connections to api.example.com were seen","body":"The capture recorded \##(r.packets) packets. See api.example.com in the destinations.","nextStep":"Capture again and mark the moment.","citations":[{"text":"api.example.com","anchor":"#destinations"}]}"##
        T.expect(SummaryValidator.validate(jsonText: good, results: r) != nil)
        let invented = ##"{"headline":"There were 999 failures","body":"All 999 attempts failed.","nextStep":"Retry.","citations":[]}"##
        T.expect(SummaryValidator.validate(jsonText: invented, results: r) == nil)
        let badCitation = ##"{"headline":"A short headline","body":"Nothing unusual was recorded.","nextStep":"Retry.","citations":[{"text":"this phrase is absent","anchor":"#dns"}]}"##
        T.expect(SummaryValidator.validate(jsonText: badCitation, results: r) == nil)
        let long = "{\"headline\":\"" + String(repeating: "x", count: 120) + "\",\"body\":\"One sentence.\",\"nextStep\":\"Retry.\",\"citations\":[]}"
        T.expect(SummaryValidator.validate(jsonText: long, results: r) == nil)
        // Template fallback is never empty.
        T.expect(!r.templateSummary.headline.isEmpty && !r.templateSummary.body.isEmpty)
    }

    T.test("user log file validation is by content, not extension") {
        let dir = NSTemporaryDirectory() + "ps-logval-\(UUID().uuidString)"
        try! FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        // A classic PCAP saved with a .log name must be accepted.
        let pcap = buildPCAP(linkType: 1, packets: [(1000.0, ethUDP(src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: [1]))])
        let logURL = URL(fileURLWithPath: dir + "/my-capture.log")
        try! pcap.write(to: logURL)
        T.expect(AppModel.logFileValidationError(at: logURL) == nil)
        // A plain-text log gets a clear explanation, not silent failure.
        let textURL = URL(fileURLWithPath: dir + "/notes.log")
        try! Data("2026-10-27 app started\n".utf8).write(to: textURL)
        let textErr = AppModel.logFileValidationError(at: textURL)
        T.expect(textErr?.contains("classic PCAP") ?? false)
        // PCAPNG is called out distinctly.
        let ngURL = URL(fileURLWithPath: dir + "/capture.pcapng")
        try! Data([0x0A, 0x0D, 0x0D, 0x0A] + [UInt8](repeating: 0, count: 24)).write(to: ngURL)
        T.expect(AppModel.logFileValidationError(at: ngURL)?.contains("PCAPNG") ?? false)
    }
    T.test("an imported log file produces the same results and insights as a direct capture") {
        var pkts: [(Double, [UInt8])] = []
        for (dt, f) in dnsPair(id: 1, name: "api.example.com", answer: "203.0.113.10") { pkts.append((dt + 11.9, f)) }
        for st in [12.04, 13.05, 15.07, 19.10, 27.12, 33.04] { pkts.append((st, syn("192.168.1.23", "203.0.113.10", 51544, 443))) }
        for i in 0..<10 { pkts.append((40 + Double(i), ack("192.168.1.23", "203.0.113.99", 51000, 443))) }
        pkts.sort { $0.0 < $1.0 }
        let data = buildPCAP(linkType: 1, packets: pkts.map { (1000 + $0.0, $0.1) })
        // Direct analysis, as for a PacketScope capture.
        let direct = try! PacketAnalyzer.analyze(data: data)
        // Imported-file analysis: copied to a session-style file first, as the app does.
        let dir = NSTemporaryDirectory() + "ps-import-\(UUID().uuidString)"
        try! FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let fileURL = URL(fileURLWithPath: dir + "/traffic.pcap")
        try! data.write(to: fileURL)
        T.expect(AppModel.logFileValidationError(at: fileURL) == nil)
        let imported = try! PacketAnalyzer.analyze(url: fileURL)
        T.expectEqual(imported.packetCount, direct.packetCount)
        var importedCtx = SessionContext(goal: .background, interface: "Imported: my-capture.log", startedAt: 1000, isImported: true)
        importedCtx.markers = [ProblemMarker(timestamp: 1014)]
        let r = CaptureResultsBuilder.build(report: imported, context: importedCtx, kernelDrops: 0)
        T.expectEqual(r.verdict, "cause_found")
        T.expect(r.findings.contains { $0.id == "unanswered-connection" })
        T.expect(r.paths.first(where: { $0.destination == "api.example.com" })?.stages.first(where: { $0.id == "tcp" })?.status == "failed")
    }
    T.test("display filters match Wireshark counts (tshark, when available)") {
        // Locate tshark; skip quietly where it is not installed (dev tool only).
        let tsharkPath = ["/opt/homebrew/bin/tshark", "/usr/local/bin/tshark", "/usr/bin/tshark"].first { FileManager.default.isExecutableFile(atPath: $0) }
        guard let tsharkPath = tsharkPath else { print("NOTE: tshark not installed; filter-count check skipped"); return }
        func tsharkCount(_ pcap: URL, _ filter: String) -> Int {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: tsharkPath)
            proc.arguments = ["-r", pcap.path, "-Y", filter, "-T", "fields", "-e", "frame.number"]
            let out = Pipe(); proc.standardOutput = out; proc.standardError = Pipe()
            try! proc.run()
            let data = out.fileHandleForReading.readDataToEndOfFile()
            proc.waitUntilExit()
            return String(data: data, encoding: .utf8)?.split(whereSeparator: { $0 == "\n" }).count ?? -1
        }
        // Fixture: 3 unanswered SYNs + 1 unanswered DNS query.
        var pkts: [(Double, [UInt8])] = []
        pkts.append((0, ethUDP(src: "192.168.1.23", dst: "192.168.1.1", sport: 40000, dport: 53, payload: dnsMessage(id: 7, response: false, name: "silent.example.com"))))
        for i in 0..<3 { pkts.append((1 + Double(i), syn("192.168.1.23", "203.0.113.10", 51544, 443))) }
        for i in 0..<10 { pkts.append((30 + Double(i), ethTCP(src: "192.168.1.23", dst: "203.0.113.99", sport: 51000, dport: 443, flags: 0x10))) }
        // syn() builds Ethernet frames; analyze as Ethernet here.
        let data = buildPCAP(linkType: 1, packets: pkts.map { (1000 + $0.0, $0.1) })
        let dir = NSTemporaryDirectory() + "ps-filter-\(UUID().uuidString)"
        try! FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let url = URL(fileURLWithPath: dir + "/fixture.pcap")
        try! data.write(to: url)
        let rep = try! PacketAnalyzer.analyze(url: url)
        let unansweredCheck = rep.facts?.checks.first { $0.id == "tcp-unanswered" }
        T.expectEqual(unansweredCheck?.count, 3)
        T.expect(unansweredCheck?.filter.hasPrefix("frame.number in {") ?? false)
        T.expectEqual(tsharkCount(url, unansweredCheck?.filter ?? ""), 3, "tshark must match the shown unanswered count")
        let dnsCheck = rep.facts?.checks.first { $0.id == "dns-unanswered" }
        T.expectEqual(dnsCheck?.count, 1)
        T.expectEqual(dnsCheck?.filter, "dns.flags.response == 0 && !dns.response_in")
        T.expectEqual(tsharkCount(url, dnsCheck?.filter ?? ""), 1, "tshark must match the shown unanswered-DNS count")
        // The finding evidence filter reproduces the SYN packets exactly.
        let r = CaptureResultsBuilder.build(report: rep, context: SessionContext(goal: .website, interface: "en0"), kernelDrops: 0)
        let finding = r.findings.first { $0.id == "unanswered-connection" }
        T.expectEqual(tsharkCount(url, finding?.evidence.filter ?? ""), 3, "tshark must match the finding evidence count")
    }
    T.test("export these packets writes only the listed frames") {
        let pkts: [(Double, [UInt8])] = (0..<5).map { (Double($0), ethUDP(src: "10.0.0.1", dst: "10.0.0.2", sport: 1000, dport: 2000, payload: [UInt8($0)])) }
        let data = buildPCAP(linkType: 1, packets: pkts.map { (1000 + $0.0, $0.1) })
        let dir = NSTemporaryDirectory() + "ps-export-\(UUID().uuidString)"
        try! FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let src = URL(fileURLWithPath: dir + "/in.pcap")
        let dst = URL(fileURLWithPath: dir + "/out.pcap")
        try! data.write(to: src)
        try! PacketAnalyzer.exportPackets(from: src, frames: [2, 4], to: dst)
        let rep = try! PacketAnalyzer.analyze(url: dst)
        T.expectEqual(rep.packetCount, 2)
    }
}

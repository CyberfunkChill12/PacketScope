import Foundation

private func assistantReport(appCount: Int = 2) -> CaptureReport {
    var facts = CaptureFacts()
    facts.firstTimestamp = 1000; facts.lastTimestamp = 1060
    facts.dnsResponses = 10; facts.dnsErrors = 1; facts.tcpPackets = 40; facts.tcpResets = 2
    facts.averageDNSMilliseconds = 80; facts.matchedDNSPairs = 5
    var apps: [AppTraffic] = []
    for i in 0..<appCount { apps.append(AppTraffic(name: "App\(i)", processID: 100 + i, packets: i + 1, bytes: (i + 1) * 100, sentBytes: 10, receivedBytes: 20, packetNumbers: [i + 1])) }
    apps.append(AppTraffic(name: "Unknown", packets: 7, bytes: 700, packetNumbers: [99]))
    facts.applications = apps
    facts.attributedPackets = 20; facts.unattributedPackets = 7
    var rep = CaptureReport(packetCount: 50, capturedBytes: 9000, duration: 60,
                            findings: [Finding(id: "dns-errors", severity: "warning", title: "DNS error replies observed", evidence: "1 of 10 visible DNS replies were errors.", recommendation: "Check the DNS server.", packetNumbers: [3])])
    rep.facts = facts
    rep.packets = [PacketRecord(id: 1, timestamp: 1000, source: "192.168.1.10", destination: "8.8.8.8", protocolName: "DNS", length: 60, summary: "DNS query")]
    return rep
}

func registerAssistantTests() {
    let T = TestHarness.self
    T.test("sanitizer strips control and bidi characters and bounds length") {
        let out = TextSanitizer.clean("hi\u{202E}evil\u{0001} text", maxLength: 5)
        T.expectEqual(out.count, 5); T.expect(!out.contains("\u{202E}"))
    }
    T.test("evidence JSON is valid and bounded to 8000 bytes with large inputs") {
        var rep = assistantReport(appCount: 60)
        rep.packets = (0..<200).map { PacketRecord(id: $0 + 1, timestamp: 1000, source: "10.0.0.1", destination: "10.0.0.2", protocolName: "TCP", length: 10, summary: String(repeating: "x", count: 200)) }
        rep.findings = (0..<10).map { Finding(id: "f\($0)", severity: "info", title: "F\($0)", evidence: String(repeating: "e", count: 300), recommendation: "r", packetNumbers: [1]) }
        let ev = EvidenceBuilder.build(report: rep, context: SessionContext(symptom: String(repeating: "s", count: 500)), comparison: nil)
        T.expect(ev.json.utf8.count <= 8000)
        T.expect((try? JSONSerialization.jsonObject(with: Data(ev.json.utf8))) != nil)
    }
    T.test("evidence marks partial and incomplete app lists") {
        let rep = assistantReport(appCount: 30)
        let ev = EvidenceBuilder.build(report: rep, context: SessionContext(), comparison: nil)
        T.expectEqual(ev.appListComplete, false)
        T.expect(ev.isPartial)
    }
    T.test("evidence includes whole-capture scope counts and loopback scope warning") {
        let ev = EvidenceBuilder.build(report: assistantReport(), context: SessionContext(), comparison: nil)
        T.expect(ev.json.contains("wholeCaptureCounts"))
        T.expect(ev.json.contains("do not imply all traffic stayed on this Mac"))
    }
    T.test("validator rejects invented structured packet IDs") {
        T.expectEqual(AIOutputValidator.validate(text: "See packets.", packetNumbers: [12345], allowed: [1, 2]), false)
    }
    T.test("validator rejects inline packet references that bypass validation") {
        T.expectEqual(AIOutputValidator.validate(text: "Look at #999 now.", packetNumbers: [], allowed: [1, 2]), false)
        T.expectEqual(AIOutputValidator.validate(text: "Look at #2 now.", packetNumbers: [2], allowed: [1, 2]), true)
    }
    T.test("validator rejects oversize output and too many references") {
        T.expectEqual(AIOutputValidator.validate(text: String(repeating: "a", count: 3000), packetNumbers: [], allowed: []), false)
        T.expectEqual(AIOutputValidator.validate(text: "ok", packetNumbers: [1, 2, 3, 4, 5, 6, 7], allowed: [1, 2, 3, 4, 5, 6, 7]), false)
    }
    T.test("app answers are exact, capped at 20 groups with omission count") {
        let rep = assistantReport(appCount: 30)
        let (text, _) = RulesGuide.answer(question: "Which apps were communicating?", report: rep, context: SessionContext(), comparison: nil, baselineAvailable: false)
        T.expect(text.contains("App29")) // highest-volume group first
        T.expect(!text.contains("App0:")) // low-volume groups omitted beyond the 20-group cap
        T.expect(text.contains("further group"))
        T.expect(text.contains("Unknown covers 7 packets"))
    }
    T.test("marker answer reports offsets and retained-window scope") {
        var ctx = SessionContext(); ctx.markers = [ProblemMarker(timestamp: 1002)]
        let (text, refs) = RulesGuide.answer(question: "What happened near my marked moments?", report: assistantReport(), context: ctx, comparison: nil, baselineAvailable: false)
        T.expect(text.contains("Marker at 2.0 s"))
        T.expect(text.contains("not proof of a network fault"))
        _ = refs
    }
    T.test("marker answer with no markers is honest") {
        let (text, _) = RulesGuide.answer(question: "What happened near my marked moments?", report: assistantReport(), context: SessionContext(), comparison: nil, baselineAvailable: false)
        T.expect(text.contains("No moments were marked"))
    }
    T.test("comparison answer without baseline explains how to set one") {
        let (text, _) = RulesGuide.answer(question: "What changed between captures?", report: assistantReport(), context: SessionContext(), comparison: nil, baselineAvailable: false)
        T.expect(text.contains("No baseline is selected"))
    }
    T.test("comparison answer uses exact metrics and causation caveat") {
        let rep = assistantReport()
        let cmp = ComparisonEngine.compare(baseline: rep, current: rep, baselineContext: SessionContext(), currentContext: SessionContext())
        let (text, _) = RulesGuide.answer(question: "What changed between captures?", report: rep, context: SessionContext(), comparison: cmp, baselineAvailable: true)
        T.expect(text.contains("DNS error reply share"))
        T.expect(text.contains("cannot establish causation"))
    }
    T.test("flagged answer cites findings and packets") {
        let (text, refs) = RulesGuide.answer(question: "Why was this flagged?", report: assistantReport(), context: SessionContext(), comparison: nil, baselineAvailable: false)
        T.expect(text.contains("DNS error replies observed"))
        T.expectEqual(refs, [3])
    }
    T.test("DNS answer reports denominators and timing scope") {
        let (text, _) = RulesGuide.answer(question: "Tell me about DNS", report: assistantReport(), context: SessionContext(), comparison: nil, baselineAvailable: false)
        T.expect(text.contains("10 visible DNS replies"))
        T.expect(text.contains("not page-load time"))
    }
    T.test("slow answer never calls captured volume a speed test result") {
        let (text, _) = RulesGuide.answer(question: "Why is my connection slow?", report: assistantReport(), context: SessionContext(), comparison: nil, baselineAvailable: false)
        T.expect(text.contains("not a speed test"))
    }
    T.test("privacy answer states everything stays on this Mac") {
        let (text, _) = RulesGuide.answer(question: "Is anything uploaded or shared?", report: assistantReport(), context: SessionContext(), comparison: nil, baselineAvailable: false)
        T.expect(text.contains("no telemetry") || text.contains("Everything is analyzed on this Mac"))
    }
    T.test("Unknown answer is exact and not alarmist") {
        let (text, _) = RulesGuide.answer(question: "What is Unknown?", report: assistantReport(), context: SessionContext(), comparison: nil, baselineAvailable: false)
        T.expect(text.contains("not automatically suspicious"))
    }
    T.test("unsupported questions are explained, not invented") {
        let (text, _) = RulesGuide.answer(question: "What is the Wi-Fi password of my neighbour?", report: assistantReport(), context: SessionContext(), comparison: nil, baselineAvailable: false)
        T.expect(text.contains("cannot establish"))
    }
    T.test("no-capture answer asks for a capture first") {
        let (text, _) = RulesGuide.answer(question: "Why was this flagged?", report: nil, context: nil, comparison: nil, baselineAvailable: false)
        T.expect(text.contains("no capture loaded"))
    }
    T.test("factual lookups route to rules even when AI is enabled") {
        T.expect(RulesGuide.isFactualLookup("Which apps were communicating?"))
        T.expect(RulesGuide.isFactualLookup("What happened near my marked moments?"))
        T.expect(RulesGuide.isFactualLookup("What changed between captures?"))
        T.expect(!RulesGuide.isFactualLookup("Why was this flagged?"))
    }
    T.test("on-device AI availability is reported distinctly") {
        let s = OnDeviceAI.availabilityDescription()
        T.expect(!s.isEmpty)
        T.expect(s == "available" || s.hasPrefix("unavailable"))
    }
    T.test("assistant source labels are exact") {
        T.expectEqual(AssistantSource.rules, "Local evidence guide · rules, no AI")
        T.expectEqual(AssistantSource.ai, "On-device AI · Apple Foundation Models")
    }
}

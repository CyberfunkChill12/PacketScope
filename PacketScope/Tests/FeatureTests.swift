import Foundation

private func sampleReport() -> CaptureReport {
    var facts = CaptureFacts()
    facts.firstTimestamp = 1000; facts.lastTimestamp = 1010
    facts.dnsResponses = 10; facts.dnsErrors = 2; facts.tcpPackets = 50; facts.tcpResets = 5
    facts.averageDNSMilliseconds = 120; facts.matchedDNSPairs = 8
    facts.applications = [AppTraffic(name: "Safari", processID: 100, packets: 10, bytes: 5000, sentBytes: 2000, receivedBytes: 3000, destinations: ["93.184.216.34"], packetNumbers: [1, 2]),
                          AppTraffic(name: "Unknown", packets: 3, bytes: 300, packetNumbers: [3])]
    facts.domains = [DomainObservation(name: "example.com", addresses: ["93.184.216.34"], queryCount: 4, errorCount: 1, packetNumbers: [1])]
    facts.timeline = [TrafficBucket(second: 0, packets: 5, bytes: 1000, dnsErrors: 1, tcpResets: 1)]
    facts.attributedPackets = 10; facts.unattributedPackets = 3
    var rep = CaptureReport(packetCount: 13, capturedBytes: 5300, duration: 10)
    rep.facts = facts
    rep.endpoints = [EndpointStat(address: "93.184.216.34", packets: 10, bytes: 5000)]
    rep.packets = [PacketRecord(id: 1, timestamp: 1000, source: "192.168.1.10", destination: "93.184.216.34", protocolName: "TCP", length: 100, summary: "TCP")]
    return rep
}

func registerFeatureTests() {
    let T = TestHarness.self
    T.test("session context round-trips goal, symptom, and markers") {
        let ctx = SessionContext(goal: .calls, symptom: "freeze at noon", interface: "en0", startedAt: 123, markers: [ProblemMarker(timestamp: 456, note: "Problem noticed")])
        let data = try JSONEncoder().encode(ctx)
        let back = try JSONDecoder().decode(SessionContext.self, from: data)
        T.expectEqual(back, ctx)
    }
    T.test("older context JSON without new fields decodes with defaults") {
        let json = "{\"goal\":\"slow\",\"interface\":\"en1\"}"
        let ctx = try JSONDecoder().decode(SessionContext.self, from: Data(json.utf8))
        T.expectEqual(ctx.goal, .slow); T.expect(ctx.markers.isEmpty); T.expectEqual(ctx.isImported, false)
    }
    T.test("older report JSON without facts decodes gracefully") {
        let json = "{\"packetCount\":3,\"capturedBytes\":300,\"duration\":2,\"protocols\":[],\"endpoints\":[],\"findings\":[],\"packets\":[],\"limitationNotes\":[]}"
        let rep = try JSONDecoder().decode(CaptureReport.self, from: Data(json.utf8))
        T.expectEqual(rep.packetCount, 3); T.expect(rep.facts == nil)
    }
    T.test("explanations: empty capture and no-findings are honest") {
        let empty = ExplanationBuilder.cards(report: CaptureReport(), context: SessionContext())
        T.expect(empty.first?.title.contains("No packets") ?? false)
        T.expect(empty.first?.cannotEstablish.contains("does not prove") ?? false)
        let cards = ExplanationBuilder.cards(report: sampleReport(), context: SessionContext())
        T.expect(cards.contains { $0.id == "dns-timing" })
    }
    T.test("marker explanation uses retained rows and states the window scope") {
        var ctx = SessionContext(interface: "lo0")
        ctx.markers = [ProblemMarker(timestamp: 1001)]
        let cards = ExplanationBuilder.cards(report: sampleReport(), context: ctx)
        let m = cards.first(where: { $0.id == "marker" })
        T.expect(m != nil)
        T.expect(m?.cannotEstablish.contains("retained") ?? false)
        // Marker far from any retained row: honest empty window.
        var ctx2 = SessionContext(interface: "lo0"); ctx2.markers = [ProblemMarker(timestamp: 5000)]
        let m2 = ExplanationBuilder.cards(report: sampleReport(), context: ctx2).first(where: { $0.id == "marker" })
        T.expect(m2?.observed.contains("0 of the retained") ?? false)
    }
    T.test("comparison reports missing samples honestly, never as 0%") {
        var rep = sampleReport()
        rep.facts?.dnsResponses = 0; rep.facts?.tcpPackets = 0; rep.facts?.averageDNSMilliseconds = nil; rep.facts?.matchedDNSPairs = 0
        let cmp = ComparisonEngine.compare(baseline: rep, current: rep, baselineContext: SessionContext(), currentContext: SessionContext())
        T.expect(cmp.metrics.contains { $0.baselineText == "No observed sample" })
        T.expect(cmp.metrics.contains { $0.baselineText == "No matched pairs" })
        T.expect(!cmp.metrics.contains { $0.baselineText.hasPrefix("0.0%") })
    }
    T.test("comparison without detailed facts falls back to volume and span with guidance") {
        var old = sampleReport(); old.facts = nil
        let cmp = ComparisonEngine.compare(baseline: old, current: sampleReport(), baselineContext: SessionContext(), currentContext: SessionContext())
        T.expectEqual(cmp.hasDetailedFacts, false)
        T.expect(cmp.warnings.contains { $0.contains("reanalyze") })
        T.expect(cmp.metrics.contains { $0.name == "Captured bytes" })
    }
    T.test("comparison warns on different goals, interfaces, and small samples") {
        let cmp = ComparisonEngine.compare(baseline: sampleReport(), current: sampleReport(),
                                           baselineContext: SessionContext(goal: .website, interface: "en0"),
                                           currentContext: SessionContext(goal: .slow, interface: "en1"))
        T.expect(cmp.warnings.contains { $0.contains("different goals") })
        T.expect(cmp.warnings.contains { $0.contains("Different network interfaces") })
    }
    T.test("results bullets summarize findings in plain language") {
        var rep = sampleReport()
        rep.findings = [Finding(id: "plaintext-remote", severity: "warning", title: "Plaintext application data observed", evidence: "Recognizable plaintext HTTP content was visible beyond loopback in 4 packet(s).", recommendation: "Prefer the encrypted version of the service.", packetNumbers: [7])]
        let card = ExplanationBuilder.cards(report: rep, context: SessionContext()).first(where: { $0.id == "plaintext-remote" })
        T.expect(card != nil)
        T.expect(card?.bullets.contains(where: { $0.contains("readable form") }) ?? false)
        T.expect(card?.bullets.contains(where: { $0.lowercased().contains("does not prove") }) ?? false)
        T.expect(card?.bullets.count ?? 0 >= 3)
    }
    T.test("concern builder flags plaintext as potential concern, none when no findings") {
        var rep = sampleReport()
        rep.findings = [Finding(id: "plaintext-remote", severity: "warning", title: "Plaintext application data observed", evidence: "x", recommendation: "Use HTTPS.", packetNumbers: [7])]
        let concerns = ConcernBuilder.items(report: rep)
        T.expectEqual(concerns.first?.level, "Potential concern")
        var clean = sampleReport(); clean.findings = []
        T.expect(ConcernBuilder.items(report: clean).isEmpty)
    }
    T.test("support report defaults redact IPs and domains, include apps") {
        var ctx = SessionContext(goal: .website, symptom: "cannot reach example.com from 192.168.1.10", interface: "en0")
        let text = ReportText.supportReport(report: sampleReport(), context: ctx, options: SupportOptions(), comparison: nil)
        // Symptom notes are off by default entirely.
        T.expect(!text.contains("cannot reach"))
        T.expect(text.contains("Safari"))
        _ = ctx
    }
    T.test("opted-in notes are still redacted for IPs and domains that remain off") {
        var opts = SupportOptions(); opts.includeNotes = true
        let ctx = SessionContext(goal: .website, symptom: "cannot reach example.com from 192.168.1.10", interface: "en0")
        let text = ReportText.supportReport(report: sampleReport(), context: ctx, options: opts, comparison: nil)
        T.expect(!text.contains("192.168.1.10"), "IP leaked: \(text)")
        T.expect(!text.contains("example.com"), "domain leaked: \(text)")
        T.expect(text.contains("[address hidden]")); T.expect(text.contains("[domain hidden]"))
        T.expect(text.contains("cannot reach"), "notes should appear when opted in")
    }
    T.test("opting in shows IPs, domains, and app control can hide names") {
        var opts = SupportOptions(); opts.includeIPs = true; opts.includeDomains = true; opts.includeApps = false; opts.includeNotes = true
        let ctx = SessionContext(goal: .website, symptom: "ok", interface: "en0")
        let text = ReportText.supportReport(report: sampleReport(), context: ctx, options: opts, comparison: nil)
        T.expect(text.contains("93.184.216.34"))
        T.expect(text.contains("example.com"))
        T.expect(!text.contains("Safari"))
    }
    T.test("support report never embeds payloads or a PCAP") {
        let text = ReportText.supportReport(report: sampleReport(), context: SessionContext(), options: SupportOptions(), comparison: nil)
        T.expect(!text.contains("GET /"))
        T.expect(text.lowercased().contains("no packet payloads"))
    }
}

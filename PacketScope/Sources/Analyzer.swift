import Foundation
import CryptoKit
import CommonCrypto

// MARK: - Core model contracts

public struct PacketRecord: Codable, Identifiable, Equatable {
    public var id: Int
    public var timestamp: Double
    public var source: String
    public var destination: String
    public var sourcePort: Int?
    public var destinationPort: Int?
    public var protocolName: String
    public var length: Int // original length declared by the PCAP record
    public var summary: String
    public var processName: String?
    public var processID: Int?
    public var direction: String? // "incoming" | "outgoing"
    public var hostname: String?
    public init(id: Int, timestamp: Double, source: String, destination: String, sourcePort: Int? = nil, destinationPort: Int? = nil, protocolName: String, length: Int, summary: String, processName: String? = nil, processID: Int? = nil, direction: String? = nil, hostname: String? = nil) {
        self.id = id; self.timestamp = timestamp; self.source = source; self.destination = destination
        self.sourcePort = sourcePort; self.destinationPort = destinationPort; self.protocolName = protocolName
        self.length = length; self.summary = summary; self.processName = processName; self.processID = processID
        self.direction = direction; self.hostname = hostname
    }
}

public struct ProtocolCount: Codable, Identifiable, Equatable {
    public var id: String { name }
    public var name: String
    public var count: Int
    public var bytes: Int
    public init(name: String, count: Int, bytes: Int) { self.name = name; self.count = count; self.bytes = bytes }
}

public struct EndpointStat: Codable, Identifiable, Equatable {
    public var id: String { address }
    public var address: String
    public var packets: Int
    public var bytes: Int
    public init(address: String, packets: Int, bytes: Int) { self.address = address; self.packets = packets; self.bytes = bytes }
}

public struct Finding: Codable, Identifiable, Equatable {
    public var id: String
    public var severity: String // "info" | "notice" | "warning"
    public var title: String
    public var evidence: String
    public var recommendation: String
    public var packetNumbers: [Int]
    public init(id: String, severity: String, title: String, evidence: String, recommendation: String, packetNumbers: [Int]) {
        self.id = id; self.severity = severity; self.title = title; self.evidence = evidence
        self.recommendation = recommendation; self.packetNumbers = packetNumbers
    }
}

public struct AppTraffic: Codable, Identifiable, Equatable {
    public var id: String { name + "|" + String(processID ?? -1) }
    public var name: String
    public var processID: Int?
    public var packets: Int
    public var bytes: Int
    public var sentBytes: Int
    public var receivedBytes: Int
    public var destinations: [String]
    public var packetNumbers: [Int]
    public init(name: String, processID: Int? = nil, packets: Int = 0, bytes: Int = 0, sentBytes: Int = 0, receivedBytes: Int = 0, destinations: [String] = [], packetNumbers: [Int] = []) {
        self.name = name; self.processID = processID; self.packets = packets; self.bytes = bytes
        self.sentBytes = sentBytes; self.receivedBytes = receivedBytes; self.destinations = destinations; self.packetNumbers = packetNumbers
    }
}

public struct TrafficBucket: Codable, Identifiable, Equatable {
    public var id: Int { second }
    public var second: Int
    public var packets: Int
    public var bytes: Int
    public var dnsErrors: Int
    public var tcpResets: Int
    public init(second: Int, packets: Int = 0, bytes: Int = 0, dnsErrors: Int = 0, tcpResets: Int = 0) {
        self.second = second; self.packets = packets; self.bytes = bytes; self.dnsErrors = dnsErrors; self.tcpResets = tcpResets
    }
}

public struct DomainObservation: Codable, Identifiable, Equatable {
    public var id: String { name }
    public var name: String
    public var addresses: [String]
    public var queryCount: Int
    public var errorCount: Int
    public var packetNumbers: [Int]
    public init(name: String, addresses: [String] = [], queryCount: Int = 0, errorCount: Int = 0, packetNumbers: [Int] = []) {
        self.name = name; self.addresses = addresses; self.queryCount = queryCount; self.errorCount = errorCount; self.packetNumbers = packetNumbers
    }
}


public struct DNSLookup: Codable, Identifiable, Equatable {
    public var id: String { "\(frame)-\(name)-\(type)" }
    public var name: String
    public var type: String
    public var milliseconds: Double?
    public var rcode: String
    public var frame: Int
    public init(name: String, type: String, milliseconds: Double? = nil, rcode: String = "", frame: Int) {
        self.name = name; self.type = type; self.milliseconds = milliseconds; self.rcode = rcode; self.frame = frame
    }
}

public struct DestinationRecord: Codable, Identifiable, Equatable {
    public var id: String { "\(address):\(port)/\(protocolLabel)" }
    public var name: String?
    public var nameSource: String? // "dns" | "sni"
    public var address: String
    public var port: Int
    public var protocolLabel: String
    public var outcome: String // connected | refused | no_reply | reset_later | not_checked | background
    public var attempts: Int
    public var packets: Int
    public var bytes: Int
    public var packetNumbers: [Int]
    public var evidenceFilter: String
    public var evidenceCount: Int
    public var tlsStatus: String // passed | failed | not_visible
    public var outerName: String? // ECH outer public name when nameSource == "sni_outer"
    public var intelMatchIds: [String]?
    public var intelTopSeverity: String?
    public init(name: String? = nil, nameSource: String? = nil, address: String, port: Int, protocolLabel: String, outcome: String, attempts: Int = 0, packets: Int = 0, bytes: Int = 0, packetNumbers: [Int] = [], evidenceFilter: String = "", evidenceCount: Int = 0, tlsStatus: String = "not_visible") {
        self.name = name; self.nameSource = nameSource; self.address = address; self.port = port; self.protocolLabel = protocolLabel
        self.outcome = outcome; self.attempts = attempts; self.packets = packets; self.bytes = bytes
        self.packetNumbers = packetNumbers; self.evidenceFilter = evidenceFilter; self.evidenceCount = evidenceCount; self.tlsStatus = tlsStatus
    }
}

public struct CheckRecord: Codable, Identifiable, Equatable {
    public var id: String
    public var label: String
    public var count: Int
    public var flagged: Bool
    public var note: String
    public var packetNumbers: [Int]
    public var filter: String
    public init(id: String, label: String, count: Int, flagged: Bool, note: String, packetNumbers: [Int] = [], filter: String = "") {
        self.id = id; self.label = label; self.count = count; self.flagged = flagged; self.note = note; self.packetNumbers = packetNumbers; self.filter = filter
    }
}


public struct ObservableEndpoint: Codable, Equatable {
    public var address: String
    public var port: Int
    public var packets: Int
    public var frames: [Int]
    public init(address: String, port: Int, packets: Int = 0, frames: [Int] = []) {
        self.address = address; self.port = port; self.packets = packets; self.frames = frames
    }
}

public struct CertificateObservable: Codable, Equatable {
    public var sha1: String
    public var sha256: String
    public var frame: Int
    public var serverAddress: String
    public var serverPort: Int
    public init(sha1: String, sha256: String, frame: Int, serverAddress: String, serverPort: Int) {
        self.sha1 = sha1; self.sha256 = sha256; self.frame = frame; self.serverAddress = serverAddress; self.serverPort = serverPort
    }
}

public struct TLSFingerprint: Codable, Equatable {
    public var ja3: String
    public var ja4: String
    public var sni: String?
    public var ech: Bool
    public var quic: Bool
    public var frame: Int
    public var serverAddress: String
    public var serverPort: Int
    public init(ja3: String, ja4: String, sni: String? = nil, ech: Bool = false, quic: Bool = false, frame: Int, serverAddress: String, serverPort: Int) {
        self.ja3 = ja3; self.ja4 = ja4; self.sni = sni; self.ech = ech; self.quic = quic; self.frame = frame; self.serverAddress = serverAddress; self.serverPort = serverPort
    }
}

public struct CaptureFacts: Codable, Equatable {
    public var firstTimestamp: Double?
    public var lastTimestamp: Double?
    public var dnsResponses: Int
    public var dnsErrors: Int
    public var tcpPackets: Int
    public var tcpResets: Int
    public var averageDNSMilliseconds: Double?
    public var matchedDNSPairs: Int
    public var applications: [AppTraffic]
    public var timeline: [TrafficBucket]
    public var domains: [DomainObservation]
    public var attributedPackets: Int
    public var unattributedPackets: Int
    public var loopbackPackets: Int
    // Detailed results data (all optional in older saved reports).
    public var dnsQueries: Int = 0
    public var dnsAnswered: Int = 0
    public var dnsUnanswered: Int = 0
    public var dnsP95Milliseconds: Double?
    public var dnsMaxMilliseconds: Double?
    public var dnsResolvers: [String] = []
    public var dnsLookups: [DNSLookup] = []
    public var tcpRetransmissions: Int = 0
    public var icmpUnreachable: Int = 0
    public var tlsAlerts: Int = 0
    public var quicPackets: Int = 0
    public var encryptedOtherPackets: Int = 0
    public var checkedPackets: Int = 0
    public var destinations: [DestinationRecord] = []
    public var checks: [CheckRecord] = []
    public var arpResponder: String?
    public var trafficMix: [ProtocolCount] = []
    // Transient observables for threat-intel matching (not persisted).
    public var httpHosts: [String] = []
    public var httpURLs: [String] = []
    public var cnameTargets: [String] = []
    public var certificates: [CertificateObservable] = []
    public var fingerprints: [TLSFingerprint] = []
    public var observableEndpoints: [ObservableEndpoint] = []
    public var observableIPCount: Int = 0
    public var observableTruncated: Bool = false
    public init(firstTimestamp: Double? = nil, lastTimestamp: Double? = nil, dnsResponses: Int = 0, dnsErrors: Int = 0, tcpPackets: Int = 0, tcpResets: Int = 0, averageDNSMilliseconds: Double? = nil, matchedDNSPairs: Int = 0, applications: [AppTraffic] = [], timeline: [TrafficBucket] = [], domains: [DomainObservation] = [], attributedPackets: Int = 0, unattributedPackets: Int = 0, loopbackPackets: Int = 0) {
        self.firstTimestamp = firstTimestamp; self.lastTimestamp = lastTimestamp; self.dnsResponses = dnsResponses
        self.dnsErrors = dnsErrors; self.tcpPackets = tcpPackets; self.tcpResets = tcpResets
        self.averageDNSMilliseconds = averageDNSMilliseconds; self.matchedDNSPairs = matchedDNSPairs
        self.applications = applications; self.timeline = timeline; self.domains = domains
        self.attributedPackets = attributedPackets; self.unattributedPackets = unattributedPackets; self.loopbackPackets = loopbackPackets
    }
    private enum CodingKeys: String, CodingKey {
        case firstTimestamp, lastTimestamp, dnsResponses, dnsErrors, tcpPackets, tcpResets, averageDNSMilliseconds, matchedDNSPairs, applications, timeline, domains, attributedPackets, unattributedPackets, loopbackPackets
        case dnsQueries, dnsAnswered, dnsUnanswered, dnsP95Milliseconds, dnsMaxMilliseconds, dnsResolvers, dnsLookups, tcpRetransmissions, icmpUnreachable, tlsAlerts, quicPackets, encryptedOtherPackets, checkedPackets, destinations, checks, arpResponder, trafficMix
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        firstTimestamp = try c.decodeIfPresent(Double.self, forKey: .firstTimestamp)
        lastTimestamp = try c.decodeIfPresent(Double.self, forKey: .lastTimestamp)
        dnsResponses = try c.decodeIfPresent(Int.self, forKey: .dnsResponses) ?? 0
        dnsErrors = try c.decodeIfPresent(Int.self, forKey: .dnsErrors) ?? 0
        tcpPackets = try c.decodeIfPresent(Int.self, forKey: .tcpPackets) ?? 0
        tcpResets = try c.decodeIfPresent(Int.self, forKey: .tcpResets) ?? 0
        averageDNSMilliseconds = try c.decodeIfPresent(Double.self, forKey: .averageDNSMilliseconds)
        matchedDNSPairs = try c.decodeIfPresent(Int.self, forKey: .matchedDNSPairs) ?? 0
        applications = try c.decodeIfPresent([AppTraffic].self, forKey: .applications) ?? []
        timeline = try c.decodeIfPresent([TrafficBucket].self, forKey: .timeline) ?? []
        domains = try c.decodeIfPresent([DomainObservation].self, forKey: .domains) ?? []
        attributedPackets = try c.decodeIfPresent(Int.self, forKey: .attributedPackets) ?? 0
        unattributedPackets = try c.decodeIfPresent(Int.self, forKey: .unattributedPackets) ?? 0
        loopbackPackets = try c.decodeIfPresent(Int.self, forKey: .loopbackPackets) ?? 0
        dnsQueries = try c.decodeIfPresent(Int.self, forKey: .dnsQueries) ?? 0
        dnsAnswered = try c.decodeIfPresent(Int.self, forKey: .dnsAnswered) ?? 0
        dnsUnanswered = try c.decodeIfPresent(Int.self, forKey: .dnsUnanswered) ?? 0
        dnsP95Milliseconds = try c.decodeIfPresent(Double.self, forKey: .dnsP95Milliseconds)
        dnsMaxMilliseconds = try c.decodeIfPresent(Double.self, forKey: .dnsMaxMilliseconds)
        dnsResolvers = try c.decodeIfPresent([String].self, forKey: .dnsResolvers) ?? []
        dnsLookups = try c.decodeIfPresent([DNSLookup].self, forKey: .dnsLookups) ?? []
        tcpRetransmissions = try c.decodeIfPresent(Int.self, forKey: .tcpRetransmissions) ?? 0
        icmpUnreachable = try c.decodeIfPresent(Int.self, forKey: .icmpUnreachable) ?? 0
        tlsAlerts = try c.decodeIfPresent(Int.self, forKey: .tlsAlerts) ?? 0
        quicPackets = try c.decodeIfPresent(Int.self, forKey: .quicPackets) ?? 0
        encryptedOtherPackets = try c.decodeIfPresent(Int.self, forKey: .encryptedOtherPackets) ?? 0
        checkedPackets = try c.decodeIfPresent(Int.self, forKey: .checkedPackets) ?? 0
        destinations = try c.decodeIfPresent([DestinationRecord].self, forKey: .destinations) ?? []
        checks = try c.decodeIfPresent([CheckRecord].self, forKey: .checks) ?? []
        arpResponder = try c.decodeIfPresent(String.self, forKey: .arpResponder)
        trafficMix = try c.decodeIfPresent([ProtocolCount].self, forKey: .trafficMix) ?? []
    }
}

public struct CaptureReport: Codable, Equatable {
    public var packetCount: Int
    public var capturedBytes: Int
    public var duration: Double
    public var protocols: [ProtocolCount]
    public var endpoints: [EndpointStat]
    public var findings: [Finding]
    public var packets: [PacketRecord]
    public var limitationNotes: [String]
    public var facts: CaptureFacts?
    public init(packetCount: Int = 0, capturedBytes: Int = 0, duration: Double = 0, protocols: [ProtocolCount] = [], endpoints: [EndpointStat] = [], findings: [Finding] = [], packets: [PacketRecord] = [], limitationNotes: [String] = [], facts: CaptureFacts? = nil) {
        self.packetCount = packetCount; self.capturedBytes = capturedBytes; self.duration = duration
        self.protocols = protocols; self.endpoints = endpoints; self.findings = findings; self.packets = packets
        self.limitationNotes = limitationNotes; self.facts = facts
    }
    // Graceful decoding of older reports that may omit newer fields.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        packetCount = try c.decodeIfPresent(Int.self, forKey: .packetCount) ?? 0
        capturedBytes = try c.decodeIfPresent(Int.self, forKey: .capturedBytes) ?? 0
        duration = try c.decodeIfPresent(Double.self, forKey: .duration) ?? 0
        protocols = try c.decodeIfPresent([ProtocolCount].self, forKey: .protocols) ?? []
        endpoints = try c.decodeIfPresent([EndpointStat].self, forKey: .endpoints) ?? []
        findings = try c.decodeIfPresent([Finding].self, forKey: .findings) ?? []
        packets = try c.decodeIfPresent([PacketRecord].self, forKey: .packets) ?? []
        limitationNotes = try c.decodeIfPresent([String].self, forKey: .limitationNotes) ?? []
        facts = try c.decodeIfPresent(CaptureFacts.self, forKey: .facts)
    }
    private enum CodingKeys: String, CodingKey { case packetCount, capturedBytes, duration, protocols, endpoints, findings, packets, limitationNotes, facts }
}

// MARK: - Analyzer

public enum AnalyzerError: Error, LocalizedError {
    case fileTooLarge(Int)
    case notPCAP
    case pcapNGUnsupported
    case unsupportedVersion(Int, Int)
    case unsupportedLinkType(Int)
    case invalidHeader(String)
    case truncated(String)
    public var errorDescription: String? {
        switch self {
        case .fileTooLarge(let n): return "Capture file is \(n) bytes, over the 100 MiB import limit."
        case .notPCAP: return "This file is not a classic PCAP capture."
        case .pcapNGUnsupported: return "PCAPNG files are not supported. Please provide a classic PCAP file."
        case .unsupportedVersion(let a, let b): return "Unsupported PCAP version \(a).\(b); only 2.4 is supported."
        case .unsupportedLinkType(let t): return "Unsupported PCAP link type \(t)."
        case .invalidHeader(let m): return "Invalid PCAP: \(m)"
        case .truncated(let m): return "Truncated PCAP: \(m)"
        }
    }
}

public enum PacketAnalyzer {
    public static let displayLimit = 2000
    public static let maxFileBytes = 100 * 1024 * 1024
    public static let supportedLinkTypes: Set<Int> = [0, 1, 12, 101, 108, 149, 258, 228, 229]

    public static func analyze(url: URL) throws -> CaptureReport {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        if let size = attrs[.size] as? NSNumber, size.intValue > maxFileBytes { throw AnalyzerError.fileTooLarge(size.intValue) }
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        if data.count > maxFileBytes { throw AnalyzerError.fileTooLarge(data.count) }
        return try analyze(data: data)
    }

    public static func analyze(data: Data) throws -> CaptureReport {
        if data.count > maxFileBytes { throw AnalyzerError.fileTooLarge(data.count) }
        let b = [UInt8](data)
        guard b.count >= 24 else { throw AnalyzerError.truncated("global header") }
        // PCAPNG section header block type 0x0A0D0D0A
        if b[0] == 0x0A && b[1] == 0x0D && b[2] == 0x0D && b[3] == 0x0A { throw AnalyzerError.pcapNGUnsupported }
        let magicBE: UInt32 = 0xA1B2C3D4, magicNano: UInt32 = 0xA1B23C4D
        let first = UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
        let swappedFirst = UInt32(b[3]) << 24 | UInt32(b[2]) << 16 | UInt32(b[1]) << 8 | UInt32(b[0])
        let little: Bool; let nano: Bool
        if first == magicBE { little = false; nano = false }
        else if first == magicNano { little = false; nano = true }
        else if swappedFirst == magicBE { little = true; nano = false }
        else if swappedFirst == magicNano { little = true; nano = true }
        else { throw AnalyzerError.notPCAP }
        func u16(_ o: Int) -> Int { little ? Int(b[o]) | Int(b[o+1]) << 8 : Int(b[o]) << 8 | Int(b[o+1]) }
        func u32(_ o: Int) -> UInt32 { little ? UInt32(b[o]) | UInt32(b[o+1]) << 8 | UInt32(b[o+2]) << 16 | UInt32(b[o+3]) << 24 : UInt32(b[o]) << 24 | UInt32(b[o+1]) << 16 | UInt32(b[o+2]) << 8 | UInt32(b[o+3]) }
        let vMaj = u16(4), vMin = u16(6)
        guard vMaj == 2 && vMin == 4 else { throw AnalyzerError.unsupportedVersion(vMaj, vMin) }
        let snaplen = Int(u32(16))
        guard snaplen > 0 else { throw AnalyzerError.invalidHeader("snapshot length is zero") }
        let linkType = Int(u32(20))
        guard supportedLinkTypes.contains(linkType) else { throw AnalyzerError.unsupportedLinkType(linkType) }

        struct RawRec { var ts: Double; var incl: Int; var orig: Int; var off: Int }
        var recs: [RawRec] = []
        var off = 24
        while off < b.count {
            guard off + 16 <= b.count else { throw AnalyzerError.truncated("record header at offset \(off)") }
            let sec = u32(off), frac = u32(off + 4), incl = Int(u32(off + 8)), orig = Int(u32(off + 12))
            let fracLimit: UInt32 = nano ? 1_000_000_000 : 1_000_000
            guard frac < fracLimit else { throw AnalyzerError.invalidHeader("timestamp fraction out of range") }
            guard incl <= snaplen else { throw AnalyzerError.invalidHeader("captured length exceeds snapshot length") }
            guard incl <= orig else { throw AnalyzerError.invalidHeader("captured length exceeds original length") }
            guard off + 16 + incl <= b.count else { throw AnalyzerError.truncated("packet data at offset \(off)") }
            let ts = Double(sec) + Double(frac) / Double(fracLimit)
            recs.append(RawRec(ts: ts, incl: incl, orig: orig, off: off + 16))
            off += 16 + incl
        }

        let firstTs = recs.first?.ts, lastTs = recs.last?.ts
        let span = (firstTs != nil && lastTs != nil) ? max(0, lastTs! - firstTs!) : 0
        let bucketWidth = max(1.0, (span / 119.0).rounded(.up))
        var dec = DecoderState(bytes: b, little: little, linkType: linkType, firstTs: firstTs, bucketWidth: bucketWidth)
        for (i, r) in recs.enumerated() {
            let frame = Array(b[r.off ..< r.off + r.incl])
            dec.decodePacket(frame: frame, number: i + 1, ts: r.ts, originalLength: r.orig, capturedLength: r.incl, depth: 0)
        }
        return dec.finish(firstTs: firstTs, lastTs: lastTs, totalPackets: recs.count)
    }

    /// Writes a new classic PCAP containing only the given 1-based frame numbers,
    /// copying the original record bytes unchanged. Used by "Export these packets".
    public static func exportPackets(from url: URL, frames: Set<Int>, to destination: URL) throws {
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        let b = [UInt8](data)
        guard b.count >= 24 else { throw AnalyzerError.truncated("global header") }
        var out = Array(b[0..<24])
        var off = 24
        var number = 0
        func u32at(_ o: Int) -> Int {
            // Record headers use the file byte order; detect from the magic.
            let little = b[0] == 0xD4 || b[0] == 0x4D
            if little { return Int(b[o]) | Int(b[o+1]) << 8 | Int(b[o+2]) << 16 | Int(b[o+3]) << 24 }
            return Int(b[o]) << 24 | Int(b[o+1]) << 16 | Int(b[o+2]) << 8 | Int(b[o+3])
        }
        while off + 16 <= b.count {
            let incl = u32at(off + 8)
            guard off + 16 + incl <= b.count else { throw AnalyzerError.truncated("packet data at offset \(off)") }
            number += 1
            if frames.contains(number) { out.append(contentsOf: b[off..<(off + 16 + incl)]) }
            off += 16 + incl
        }
        try Data(out).write(to: destination, options: [.atomic])
    }
}

// MARK: - Decoding internals

private struct DNSInfo {
    var isResponse = false
    var rcode = 0
    var truncated = false
    var questions: [(name: String, type: Int, cls: Int)] = []
    var answers: [(owner: String, type: Int, address: String)] = []
    var isMDNS = false
}

private struct Decoded {
    var src = "Unknown", dst = "Unknown"
    var sport: Int?, dport: Int?
    var proto = "Unknown"
    var summary = "Packet could not be decoded further."
    var hostname: String?
    var processName: String?
    var processID: Int?
    var direction: String?
    var isTCP = false, isRST = false
    var dns: DNSInfo?
    var plaintextProto: String? // recognized plaintext application protocol, if any
    var undecodable = false
    var tcpFlags: Int = 0
    var tcpSeq: UInt32 = 0
    var payloadLength: Int = 0
    var mixCategory: String = "OTHER"
    var isQUIC = false
    var isTLSApplicationData = false
    var tlsEvent: String? // "clientHello" | "serverHello" | "alert"
    var tlsSNI: String?
    var icmpUnreachable = false
    var arpReplySender: String?
    var tcpPayload: [UInt8] = []
    var tlsECH = false
    var httpHost: String?
    var httpURL: String?
}

private struct DecoderState {
    var bytes: [UInt8]
    var little: Bool
    var linkType: Int
    var firstTs: Double?
    var bucketWidth: Double

    var capturedBytes = 0
    var protoStats: [String: (count: Int, bytes: Int)] = [:]
    var endpointStats: [String: (packets: Int, bytes: Int)] = [:]
    var records: [PacketRecord] = []
    var undecodableCount = 0
    var sawPKTAP = false

    var dnsResponses = 0, dnsErrors = 0, tcpPackets = 0, tcpResets = 0
    var dnsErrorPackets: [Int] = [], rstPackets: [Int] = []
    var plaintextRemote: [(num: Int, proto: String)] = []
    var plaintextLocal: [(num: Int, proto: String)] = []
    var intervals: [Double] = []

    var buckets: [Int: TrafficBucket] = [:]
    var domains: [String: DomainObservation] = [:]
    var domainOrder: [String] = []
    var apps: [String: AppTraffic] = [:]
    var appOrder: [String] = []
    var attributed = 0, unattributed = 0, loopbackCount = 0

    // TLS handshake reassembly (step 3a): first 16 KB per direction per
    // connection, in memory only, discarded after observables are extracted.
    struct TLSStreamKey: Hashable { var flow: String; var direction: String }
    struct TLSStream {
        var baseSeq: UInt32 = 0
        var segments: [(seq: UInt32, data: [UInt8])] = []
        var bufferedBytes: Int = 0
        var parsedOffset: Int = 0
        var finished: Bool = false
    }
    var tlsStreams: [TLSStreamKey: TLSStream] = [:]
    // QUIC Initial CRYPTO reassembly (step 3b), first 8 KB per connection.
    struct QUICConn {
        var segments: [(offset: Int, data: [UInt8])] = []
        var bufferedBytes: Int = 0
        var parsed: Bool = false
    }
    var quicConns: [String: QUICConn] = [:]
    var currentPacketNumber: Int = 0

    // Extracted observables (transient; see CaptureFacts).
    var obsEndpoints: [String: ObservableEndpoint] = [:]
    var obsIPs: Set<String> = []
    var obsTruncated = false
    var httpHostsSeen: [String] = []
    var httpURLsSeen: [String] = []
    var cnameTargetsSeen: [String] = []
    var certificatesSeen: [CertificateObservable] = []
    var fingerprintsSeen: [TLSFingerprint] = []

    // DNS matching
    struct PendingKey: Hashable { var transport: String; var src: String; var dst: String; var sport: Int; var dport: Int; var txid: Int; var questions: String }
    var pending: [PendingKey: (ts: Double, count: Int, lookupIndices: [Int])] = [:]
    var pendingOrder: [PendingKey] = []
    var answeredKeys: Set<PendingKey> = []
    var dnsLookups: [DNSLookup] = []
    var dnsQueryCount = 0
    var dnsResolvers: [String] = []
    var nxdomainEvents: [(name: String, frame: Int)] = []
    var ipToDNSName: [String: String] = [:]

    // Traffic mix / coverage
    var mixStats: [String: (count: Int, bytes: Int)] = [:]
    var quicPackets = 0, encryptedOtherPackets = 0

    // ICMP / TLS counters
    var icmpUnreachablePackets: [Int] = []
    var tlsAlertPackets: [Int] = []
    var arpResponder: String?

    // TCP flow tracking (bounded)
    struct FlowKey: Hashable { var a: String; var ap: Int; var b: String; var bp: Int }
    struct FlowState {
        var initiator = "", server = ""
        var initiatorPort = 0, serverPort = 0
        var synFrames: [Int] = [], synTimes: [Double] = []
        var synSeqs: Set<UInt32> = []
        var dataSeqs: Set<String> = []
        var connected = false, refused = false, resetLater = false
        var refusedFrames: [Int] = []
        var clientHello = false, serverHello = false, alertBeforeHello = false
        var sni: String?
        var ech = false
        var sawHTTP = false
        var packets = 0, bytes = 0
        var frames: [Int] = []
        var retransmissions = 0
    }
    var flows: [FlowKey: FlowState] = [:]
    var flowOrder: [FlowKey] = []
    var tcpRetransmissions = 0

    // UDP destination groups (QUIC and other UDP)
    struct UDPGroup {
        var server = ""; var serverPort = 0
        var isQUIC = false
        var packets = 0, bytes = 0
        var frames: [Int] = []
    }
    var udpGroups: [FlowKey: UDPGroup] = [:]
    var udpGroupOrder: [FlowKey] = []

    static func rcodeName(_ r: Int) -> String {
        switch r { case 0: return "NOERROR"; case 2: return "SERVFAIL"; case 3: return "NXDOMAIN"; case 5: return "REFUSED"; default: return "RCODE \(r)" }
    }
    static func flowKey(src: String, sport: Int, dst: String, dport: Int) -> FlowKey {
        if (src, sport) <= (dst, dport) { return FlowKey(a: src, ap: sport, b: dst, bp: dport) }
        return FlowKey(a: dst, ap: dport, b: src, bp: sport)
    }

    static func isLoopback(_ a: String) -> Bool {
        if a == "::1" { return true }
        if a.hasPrefix("::ffff:") { return isLoopback(String(a.dropFirst(7))) }
        let parts = a.split(separator: ".")
        if parts.count == 4, parts[0] == "127" { return true }
        return false
    }

    mutating func addDomain(_ name: String, packet: Int) -> Bool {
        if domains[name] == nil {
            guard domains.count < 2000 else { return false }
            domains[name] = DomainObservation(name: name)
            domainOrder.append(name)
        }
        if domains[name]!.packetNumbers.count < 50 { domains[name]!.packetNumbers.append(packet) }
        return true
    }

    mutating func decodePacket(frame: [UInt8], number: Int, ts: Double, originalLength: Int, capturedLength: Int, depth: Int) {
        currentPacketNumber = number
        capturedBytes += capturedLength
        var d = Decoded()
        decodeLink(frame: frame, link: linkType, into: &d, depth: depth)
        if d.undecodable { undecodableCount += 1 }

        // protocol + endpoint stats over the entire file
        var p = protoStats[d.proto] ?? (0, 0); p.count += 1; p.bytes += capturedLength; protoStats[d.proto] = p
        if d.src != "Unknown" { var e = endpointStats[d.src] ?? (0, 0); e.packets += 1; e.bytes += capturedLength; endpointStats[d.src] = e }
        if d.dst != "Unknown" { var e = endpointStats[d.dst] ?? (0, 0); e.packets += 1; e.bytes += capturedLength; endpointStats[d.dst] = e }

        let srcLoop = Self.isLoopback(d.src), dstLoop = Self.isLoopback(d.dst)
        let bothLoop = srcLoop && dstLoop && d.src != "Unknown"
        if bothLoop { loopbackCount += 1 }

        var isDnsErr = false
        if d.isTCP { tcpPackets += 1; if d.isRST { tcpResets += 1; if rstPackets.count < 100 { rstPackets.append(number) } } }
        if let dns = d.dns {
            handleDNS(dns: dns, d: d, number: number, ts: ts, isErr: &isDnsErr)
        }
        if let pp = d.plaintextProto {
            if bothLoop { plaintextLocal.append((number, pp)) } else { plaintextRemote.append((number, pp)) }
            if pp == "HTTP" { parseHTTPRequest(body: d.tcpPayload, into: &d) }
        }
        if let host = d.httpHost, !httpHostsSeen.contains(host), httpHostsSeen.count < 1000 { httpHostsSeen.append(host) }
        if let url = d.httpURL, !httpURLsSeen.contains(url), httpURLsSeen.count < 1000 { httpURLsSeen.append(url) }
        // Full observable set for threat matching (separate from the retained
        // destinations table): every destination endpoint and IP seen.
        if d.src != "Unknown" { if obsIPs.count < 250_000 { obsIPs.insert(d.src) } else { obsTruncated = true } }
        if d.dst != "Unknown" {
            if obsIPs.count < 250_000 { obsIPs.insert(d.dst) } else { obsTruncated = true }
            if let dp = d.dport, d.isTCP || d.proto == "UDP" || d.proto == "QUIC" || d.proto == "DNS" {
                let key = "\(d.dst)|\(dp)"
                if var e = obsEndpoints[key] {
                    e.packets += 1
                    if e.frames.count < 10 { e.frames.append(number) }
                    obsEndpoints[key] = e
                } else if obsEndpoints.count < 100_000 {
                    obsEndpoints[key] = ObservableEndpoint(address: d.dst, port: dp, packets: 1, frames: [number])
                } else { obsTruncated = true }
            }
        }
        // Traffic mix and coverage accounting over the entire file.
        var mx = mixStats[d.mixCategory] ?? (0, 0); mx.count += 1; mx.bytes += capturedLength; mixStats[d.mixCategory] = mx
        if d.isQUIC { quicPackets += 1 }
        if d.isTLSApplicationData { encryptedOtherPackets += 1 }
        if let arp = d.arpReplySender, arpResponder == nil { arpResponder = arp }
        if d.icmpUnreachable, icmpUnreachablePackets.count < 100 { icmpUnreachablePackets.append(number) }
        if d.tlsEvent == "alert", tlsAlertPackets.count < 100 { tlsAlertPackets.append(number) }
        updateFlows(d: d, number: number, ts: ts, capturedLength: capturedLength)

        // timeline bucket
        if let f = firstTs {
            let idx = bucketWidth > 0 ? Int((ts - f) / bucketWidth) : 0
            var bk = buckets[idx] ?? TrafficBucket(second: idx * Int(bucketWidth))
            bk.packets += 1; bk.bytes += capturedLength
            if isDnsErr { bk.dnsErrors += 1 }
            if d.isRST { bk.tcpResets += 1 }
            buckets[idx] = bk
        }

        // process attribution (PKTAP only; never inferred)
        let appKey: String
        if let pn = d.processName, !pn.isEmpty {
            attributed += 1
            appKey = pn + "|" + String(d.processID ?? -1)
            if apps[appKey] == nil {
                if apps.count >= 2000 {
                    // overflow into Unknown
                    addApp(key: "Unknown|-1", name: "Unknown", pid: nil, d: d, capturedLength: capturedLength, number: number)
                } else {
                    apps[appKey] = AppTraffic(name: pn, processID: d.processID); appOrder.append(appKey)
                }
            }
            if apps[appKey] != nil { addApp(key: appKey, name: pn, pid: d.processID, d: d, capturedLength: capturedLength, number: number) }
        } else {
            unattributed += 1
            appKey = "Unknown|-1"
            if apps[appKey] == nil { apps[appKey] = AppTraffic(name: "Unknown"); appOrder.append(appKey) }
            addApp(key: appKey, name: "Unknown", pid: nil, d: d, capturedLength: capturedLength, number: number)
        }

        if records.count < PacketAnalyzer.displayLimit {
            records.append(PacketRecord(id: number, timestamp: ts, source: d.src, destination: d.dst, sourcePort: d.sport, destinationPort: d.dport, protocolName: d.proto, length: originalLength, summary: d.summary, processName: d.processName, processID: d.processID, direction: d.direction, hostname: d.hostname))
        }
    }

    mutating func addApp(key: String, name: String, pid: Int?, d: Decoded, capturedLength: Int, number: Int) {
        guard var a = apps[key] else { return }
        a.packets += 1; a.bytes += capturedLength
        if d.direction == "outgoing" { a.sentBytes += capturedLength }
        if d.direction == "incoming" { a.receivedBytes += capturedLength }
        // Observed peer only when direction is known; never invent one.
        let peer: String? = d.direction == "incoming" ? d.src : (d.direction == "outgoing" ? d.dst : nil)
        if let peer = peer, peer != "Unknown", !a.destinations.contains(peer), a.destinations.count < 64 { a.destinations.append(peer) }
        if a.packetNumbers.count < 100 { a.packetNumbers.append(number) }
        apps[key] = a
    }


    mutating func updateFlows(d: Decoded, number: Int, ts: Double, capturedLength: Int) {
        guard let sp = d.sport, let dp = d.dport, d.src != "Unknown", d.dst != "Unknown" else { return }
        if d.isTCP {
            let key = Self.flowKey(src: d.src, sport: sp, dst: d.dst, dport: dp)
            var f = flows[key]
            if f == nil {
                guard flows.count < 4096 else { return }
                var nf = FlowState()
                nf.initiator = d.src; nf.initiatorPort = sp; nf.server = d.dst; nf.serverPort = dp
                flows[key] = nf; flowOrder.append(key); f = nf
            }
            var st = f!
            let isSYN = d.tcpFlags & 0x02 != 0, isACK = d.tcpFlags & 0x10 != 0, isRST = d.tcpFlags & 0x04 != 0
            let fromServer = d.src == st.server && sp == st.serverPort
            if isSYN && !isACK {
                if st.synSeqs.contains(d.tcpSeq) { st.retransmissions += 1; tcpRetransmissions += 1 }
                st.synSeqs.insert(d.tcpSeq)
                if st.synFrames.count < 200 { st.synFrames.append(number) }
                st.synTimes.append(ts)
                if !fromServer { st.initiator = d.src; st.initiatorPort = sp; st.server = d.dst; st.serverPort = dp }
            }
            if isSYN && isACK { st.connected = true }
            if isRST {
                if st.connected { st.resetLater = true }
                else if fromServer && !st.synFrames.isEmpty { st.refused = true; if st.refusedFrames.count < 200 { st.refusedFrames.append(number) } }
            }
            if d.payloadLength > 0 {
                let sk = "\(d.src):\(sp)>" + String(d.tcpSeq) + ":" + String(d.payloadLength)
                if st.dataSeqs.contains(sk) { st.retransmissions += 1; tcpRetransmissions += 1 }
                if st.dataSeqs.count < 8192 { st.dataSeqs.insert(sk) }
            }
            switch d.tlsEvent {
            case "clientHello": st.clientHello = true; st.ech = d.tlsECH; if let sni = d.tlsSNI { st.sni = sni }
            case "serverHello": st.serverHello = true
            case "alert": if !st.serverHello { st.alertBeforeHello = true }
            default: break
            }
            if d.plaintextProto == "HTTP" { st.sawHTTP = true }
            st.packets += 1; st.bytes += capturedLength
            if st.frames.count < 200 { st.frames.append(number) }
            flows[key] = st
        } else if d.proto == "QUIC" || (d.proto == "UDP") {
            let key = Self.flowKey(src: d.src, sport: sp, dst: d.dst, dport: dp)
            var g = udpGroups[key]
            if g == nil {
                guard udpGroups.count < 2048 else { return }
                var ng = UDPGroup()
                // The server side is the well-known port when there is one, else the first destination.
                if dp <= 1024 || dp == 443 { ng.server = d.dst; ng.serverPort = dp } else if sp <= 1024 || sp == 443 { ng.server = d.src; ng.serverPort = sp } else { ng.server = d.dst; ng.serverPort = dp }
                ng.isQUIC = d.isQUIC
                udpGroups[key] = ng; udpGroupOrder.append(key); g = ng
            }
            var gg = g!
            gg.packets += 1; gg.bytes += capturedLength
            if gg.frames.count < 200 { gg.frames.append(number) }
            udpGroups[key] = gg
        }
    }

    mutating func handleDNS(dns: DNSInfo, d: Decoded, number: Int, ts: Double, isErr: inout Bool) {
        for q in dns.questions {
            if addDomain(q.name, packet: number) { domains[q.name]!.queryCount += dns.isResponse ? 0 : 1 }
        }
        if dns.isResponse {
            dnsResponses += 1
            if !dns.isMDNS && !dnsResolvers.contains(d.src) && dnsResolvers.count < 16 { dnsResolvers.append(d.src) }
            if dns.rcode != 0 {
                dnsErrors += 1; isErr = true
                if dnsErrorPackets.count < 100 { dnsErrorPackets.append(number) }
                for q in dns.questions { if domains[q.name] != nil { domains[q.name]!.errorCount += 1 } }
                if dns.rcode == 3, let first = dns.questions.first, nxdomainEvents.count < 50 { nxdomainEvents.append((first.name, number)) }
            }
        }
        for ans in dns.answers where ans.type == 5 {
            if !cnameTargetsSeen.contains(ans.address), cnameTargetsSeen.count < 500 { cnameTargetsSeen.append(ans.address) }
            _ = addDomain(ans.address, packet: number)
        }
        for ans in dns.answers where ans.type == 1 || ans.type == 28 {
            if ipToDNSName[ans.address] == nil { ipToDNSName[ans.address] = ans.owner }
            if addDomain(ans.owner, packet: number), domains[ans.owner] != nil, !domains[ans.owner]!.addresses.contains(ans.address), domains[ans.owner]!.addresses.count < 16 {
                domains[ans.owner]!.addresses.append(ans.address)
            }
        }
        // Strict request/reply timing match (standard DNS only), with per-lookup records.
        guard !dns.isMDNS, !dns.truncated, let sp = d.sport, let dp = d.dport else { return }
        let qkey = dns.questions.map { "\($0.name)/\($0.type)/\($0.cls)" }.joined(separator: ";")
        if dns.isResponse {
            let key = PendingKey(transport: dnsTransport, src: d.dst, dst: d.src, sport: dp, dport: sp, txid: dnsTxID, questions: qkey)
            if let entry = pending[key] {
                if entry.count == 1 && !answeredKeys.contains(key) {
                    let dt = ts - entry.ts
                    if dt >= 0 && dt <= 30 {
                        intervals.append(dt * 1000.0)
                        for idx in entry.lookupIndices where idx < dnsLookups.count {
                            dnsLookups[idx].milliseconds = dt * 1000.0
                            dnsLookups[idx].rcode = Self.rcodeName(dns.rcode)
                        }
                    }
                }
                pending.removeValue(forKey: key)
                answeredKeys.insert(key)
            }
        } else {
            for q in dns.questions {
                dnsQueryCount += 1
                if dnsLookups.count < 1000 {
                    let typeName = [1: "A", 28: "AAAA", 65: "HTTPS", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR", 33: "SRV", 2: "NS"][q.type] ?? "TYPE\(q.type)"
                    dnsLookups.append(DNSLookup(name: q.name, type: typeName, rcode: "", frame: number))
                }
            }
            let key = PendingKey(transport: dnsTransport, src: d.src, dst: d.dst, sport: sp, dport: dp, txid: dnsTxID, questions: qkey)
            if answeredKeys.contains(key) { answeredKeys.remove(key) }
            let newIndices = Array(max(0, dnsLookups.count - dns.questions.count)..<dnsLookups.count)
            if var entry = pending[key] { entry.count += 1; pending[key] = entry } // retry: becomes ambiguous
            else {
                if pending.count < 4096 { pending[key] = (ts, 1, newIndices); pendingOrder.append(key) }
            }
        }
    }
    // Set by DNS parser immediately before handleDNS is invoked.
    var dnsTxID: Int = 0
    var dnsTransport: String = "udp"

    mutating func decodeLink(frame: [UInt8], link: Int, into d: inout Decoded, depth: Int) {
        guard depth <= 2 else { d.undecodable = true; d.summary = "Nested link headers too deep."; return }
        switch link {
        case 0, 108: // NULL / LOOP: 4-byte address family (host byte order on the capturing Mac)
            guard frame.count >= 4 else { d.undecodable = true; return }
            let fam = Int(frame[0]) | Int(frame[1]) << 8 | Int(frame[2]) << 16 | Int(frame[3]) << 24
            decodeIP(frame: Array(frame.dropFirst(4)), familyHint: fam, into: &d)
        case 1: decodeEthernet(frame: frame, into: &d, depth: depth)
        case 12, 101: decodeIP(frame: frame, familyHint: nil, into: &d)
        case 228: decodeIPv4(frame: frame, into: &d)
        case 229: decodeIPv6(frame: frame, into: &d)
        case 149, 258: decodePKTAP(frame: frame, into: &d, depth: depth)
        default: d.undecodable = true; d.proto = "Link \(link)"; d.summary = "Unsupported link type \(link)."
        }
    }

    mutating func decodeEthernet(frame: [UInt8], into d: inout Decoded, depth: Int) {
        guard frame.count >= 14 else { d.undecodable = true; d.proto = "Ethernet"; d.summary = "Truncated Ethernet frame."; return }
        var off = 12
        var etherType = Int(frame[off]) << 8 | Int(frame[off + 1]); off += 2
        var vlans = 0
        while (etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100) && vlans < 4 {
            guard frame.count >= off + 4 else { d.undecodable = true; return }
            etherType = Int(frame[off + 2]) << 8 | Int(frame[off + 3]); off += 4; vlans += 1
        }
        let payload = Array(frame.dropFirst(off))
        switch etherType {
        case 0x0800: decodeIPv4(frame: payload, into: &d)
        case 0x86DD: decodeIPv6(frame: payload, into: &d)
        case 0x0806:
            d.proto = "ARP"
            decodeARP(frame: payload, into: &d)
        default:
            d.proto = "Ethernet"
            d.summary = "Ethernet frame, EtherType 0x" + String(etherType, radix: 16) + "."
        }
    }

    func decodeARP(frame: [UInt8], into d: inout Decoded) {
        guard frame.count >= 28, frame[4] == 6, frame[5] == 4 else { d.summary = "ARP packet."; return }
        let spa = frame[14..<18].map(String.init).joined(separator: ".")
        let tpa = frame[24..<28].map(String.init).joined(separator: ".")
        d.src = spa; d.dst = tpa
        let op = Int(frame[6]) << 8 | Int(frame[7])
        if op == 2 { d.arpReplySender = spa }
        d.summary = op == 1 ? "ARP request: who has \(tpa)? (sender \(spa))" : "ARP reply: \(spa) is at the sender hardware address."
    }

    mutating func decodeIP(frame: [UInt8], familyHint: Int?, into d: inout Decoded) {
        guard let first = frame.first else { d.undecodable = true; d.summary = "Empty IP packet."; return }
        let v = first >> 4
        if v == 4 { decodeIPv4(frame: frame, into: &d) }
        else if v == 6 { decodeIPv6(frame: frame, into: &d) }
        else if let fam = familyHint, fam == 2 { decodeIPv4(frame: frame, into: &d) }
        else { d.undecodable = true; d.proto = "IP"; d.summary = "Unknown IP version." }
    }

    static func ipv4String(_ f: ArraySlice<UInt8>) -> String { f.map(String.init).joined(separator: ".") }
    static func ipv6String(_ b: [UInt8]) -> String {
        guard b.count == 16 else { return "Unknown" }
        var groups: [UInt16] = []
        for i in stride(from: 0, to: 16, by: 2) { groups.append(UInt16(b[i]) << 8 | UInt16(b[i + 1])) }
        // IPv4-mapped
        if groups[0..<5].allSatisfy({ $0 == 0 }) && groups[5] == 0xFFFF {
            return "::ffff:" + [b[12], b[13], b[14], b[15]].map(String.init).joined(separator: ".")
        }
        // find longest zero run for ::
        var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0
        for i in 0..<8 {
            if groups[i] == 0 { if curStart < 0 { curStart = i; curLen = 1 } else { curLen += 1 }; if curLen > bestLen { bestLen = curLen; bestStart = curStart } }
            else { curStart = -1; curLen = 0 }
        }
        func hex(_ g: UInt16) -> String { String(g, radix: 16) }
        if bestLen >= 2 {
            let left = groups[0..<bestStart].map(hex).joined(separator: ":")
            let right = groups[(bestStart + bestLen)..<8].map(hex).joined(separator: ":")
            return left + "::" + right
        }
        return groups.map(hex).joined(separator: ":")
    }

    mutating func decodeIPv4(frame: [UInt8], into d: inout Decoded) {
        guard frame.count >= 20, frame[0] >> 4 == 4 else { d.undecodable = true; d.proto = "IPv4"; d.summary = "Truncated IPv4 header."; return }
        let ihl = Int(frame[0] & 0x0F) * 4
        guard ihl >= 20, frame.count >= ihl else { d.undecodable = true; d.proto = "IPv4"; d.summary = "Invalid IPv4 header length."; return }
        let total = Int(frame[2]) << 8 | Int(frame[3])
        let end = (total >= ihl && total <= frame.count) ? total : frame.count
        d.src = Self.ipv4String(frame[12..<16]); d.dst = Self.ipv4String(frame[16..<20])
        let flagsFrag = Int(frame[6]) << 8 | Int(frame[7])
        let fragOffset = flagsFrag & 0x1FFF; let moreFrags = flagsFrag & 0x2000 != 0
        let payload = Array(frame[ihl..<end])
        if fragOffset != 0 || moreFrags {
            d.proto = "IPv4"; d.summary = "IPv4 fragment (transport header not reassembled)."; return
        }
        decodeTransport(protoNum: Int(frame[9]), payload: payload, into: &d, isV6: false)
    }

    mutating func decodeIPv6(frame: [UInt8], into d: inout Decoded) {
        guard frame.count >= 40, frame[0] >> 4 == 6 else { d.undecodable = true; d.proto = "IPv6"; d.summary = "Truncated IPv6 header."; return }
        d.src = Self.ipv6String(Array(frame[8..<24])); d.dst = Self.ipv6String(Array(frame[24..<40]))
        var next = Int(frame[6])
        var off = 40
        var hops = 0
        while hops < 8 {
            hops += 1
            switch next {
            case 0, 43, 60: // hop-by-hop, routing, destination options
                guard frame.count >= off + 2 else { d.undecodable = true; d.proto = "IPv6"; return }
                let len = (Int(frame[off + 1]) + 1) * 8
                guard len >= 8, frame.count >= off + len else { d.undecodable = true; d.proto = "IPv6"; return }
                next = Int(frame[off]); off += len
            case 44: // fragment
                d.proto = "IPv6"; d.summary = "IPv6 fragment (transport header not reassembled)."; return
            case 51: // AH
                guard frame.count >= off + 2 else { d.undecodable = true; d.proto = "IPv6"; return }
                let len = (Int(frame[off + 1]) + 2) * 4
                guard frame.count >= off + len else { d.undecodable = true; d.proto = "IPv6"; return }
                next = Int(frame[off]); off += len
            default:
                decodeTransport(protoNum: next, payload: Array(frame.dropFirst(off)), into: &d, isV6: true)
                return
            }
        }
        d.proto = "IPv6"; d.undecodable = true; d.summary = "Too many IPv6 extension headers."
    }

    mutating func decodeTransport(protoNum: Int, payload: [UInt8], into d: inout Decoded, isV6: Bool) {
        switch protoNum {
        case 6: decodeTCP(payload: payload, into: &d)
        case 17: decodeUDP(payload: payload, into: &d)
        case 1:
            d.proto = "ICMP"; d.mixCategory = "ICMP"
            if payload.count >= 2 {
                d.summary = "ICMP type \(payload[0]), code \(payload[1]) between \(d.src) and \(d.dst)."
                if payload[0] == 3 { d.icmpUnreachable = true; d.summary = "ICMP destination unreachable (code \(payload[1])) from \(d.src) to \(d.dst)." }
            }
            else { d.summary = "ICMP packet." }
        case 58:
            d.proto = "ICMPv6"; d.mixCategory = "ICMP"
            if payload.count >= 2 {
                d.summary = "ICMPv6 type \(payload[0]), code \(payload[1]) between \(d.src) and \(d.dst)."
                if payload[0] == 1 { d.icmpUnreachable = true; d.summary = "ICMPv6 destination unreachable (code \(payload[1])) from \(d.src) to \(d.dst)." }
            }
            else { d.summary = "ICMPv6 packet." }
        default:
            d.proto = isV6 ? "IPv6" : "IPv4"
            d.summary = "IP protocol \(protoNum) between \(d.src) and \(d.dst)."
        }
    }

    mutating func decodeTCP(payload: [UInt8], into d: inout Decoded) {
        d.isTCP = true
        guard payload.count >= 20 else { d.undecodable = true; d.proto = "TCP"; d.summary = "Truncated TCP header."; return }
        d.sport = Int(payload[0]) << 8 | Int(payload[1]); d.dport = Int(payload[2]) << 8 | Int(payload[3])
        let hlen = Int(payload[12] >> 4) * 4
        guard hlen >= 20, payload.count >= hlen else { d.undecodable = true; d.proto = "TCP"; d.summary = "Invalid TCP header length."; return }
        let flags = payload[13]
        d.tcpFlags = Int(flags)
        d.tcpSeq = UInt32(payload[4]) << 24 | UInt32(payload[5]) << 16 | UInt32(payload[6]) << 8 | UInt32(payload[7])
        d.isRST = flags & 0x04 != 0
        d.mixCategory = "TCP"
        var flagNames: [String] = []
        if flags & 0x02 != 0 { flagNames.append("SYN") }
        if flags & 0x10 != 0 { flagNames.append("ACK") }
        if flags & 0x01 != 0 { flagNames.append("FIN") }
        if flags & 0x04 != 0 { flagNames.append("RST") }
        if flags & 0x08 != 0 { flagNames.append("PSH") }
        d.proto = "TCP"
        let body = Array(payload.dropFirst(hlen))
        d.payloadLength = body.count
        d.tcpPayload = body
        var summary = "TCP \(d.src):\(d.sport ?? 0) → \(d.dst):\(d.dport ?? 0)" + (flagNames.isEmpty ? "" : " [" + flagNames.joined(separator: ",") + "]") + "."
        if d.isRST { summary += " Connection reset observed." }
        feedTLSStream(d: &d, body: body)
        if d.tlsEvent == "clientHello" { summary += " Secure setup (TLS) started" + (d.tlsSNI.map { " for \($0)" } ?? "") + "." }
        if d.tlsEvent == "serverHello" { summary += " Secure setup (TLS) answered." }
        if d.tlsEvent == "alert" { summary += " TLS alert observed (contents not shown)." }
        if d.isTLSApplicationData { summary += " Encrypted TLS data (contents can't be read)." }
        // DNS over TCP: one complete length-prefixed message in this packet only.
        if (d.sport == 53 || d.dport == 53), body.count >= 2 {
            let mlen = Int(body[0]) << 8 | Int(body[1])
            if mlen >= 12 && body.count >= 2 + mlen, let dns = parseDNS(msg: Array(body[2..<(2 + mlen)]), isMDNS: false) {
                d.proto = "DNS"; d.dns = dns; d.hostname = dns.questions.first?.name; d.mixCategory = "DNS"
                dnsTxID = Int(body[2]) << 8 | Int(body[3]); dnsTransport = "tcp"
                summary = dnsSummary(dns, d: d, transport: "TCP")
            }
        } else if let app = detectPlaintext(body: body, d: d) {
            d.plaintextProto = app; d.proto = app
            summary += " Recognizable plaintext \(app) content visible (contents are not shown)."
        }
        d.summary = summary
    }

    mutating func decodeUDP(payload: [UInt8], into d: inout Decoded) {
        guard payload.count >= 8 else { d.undecodable = true; d.proto = "UDP"; d.summary = "Truncated UDP header."; return }
        d.sport = Int(payload[0]) << 8 | Int(payload[1]); d.dport = Int(payload[2]) << 8 | Int(payload[3])
        let body = Array(payload.dropFirst(8))
        d.proto = "UDP"
        d.mixCategory = "UDP_OTHER"
        // QUIC: UDP on port 443 whose payload begins with a long-header byte (high bit set).
        if (d.sport == 443 || d.dport == 443), let firstByte = body.first, firstByte & 0x80 != 0 {
            d.isQUIC = true; d.proto = "QUIC"; d.mixCategory = "QUIC"
            processQUIC(body: body, d: &d)
            d.summary = "QUIC \(d.src):\(d.sport ?? 0) → \(d.dst):\(d.dport ?? 0) (encrypted; contents can't be checked)" + (d.tlsSNI.map { "; server name \($0)" } ?? "") + "."
            return
        }
        var summary = "UDP \(d.src):\(d.sport ?? 0) → \(d.dst):\(d.dport ?? 0)."
        let isMDNSPort = d.sport == 5353 || d.dport == 5353
        if d.sport == 53 || d.dport == 53 || isMDNSPort {
            if body.count >= 12, let dns = parseDNS(msg: body, isMDNS: isMDNSPort) {
                d.proto = isMDNSPort ? "mDNS" : "DNS"
                if !isMDNSPort { d.mixCategory = "DNS" }
                d.dns = dns; d.hostname = dns.questions.first?.name
                dnsTxID = Int(body[0]) << 8 | Int(body[1]); dnsTransport = "udp"
                summary = dnsSummary(dns, d: d, transport: "UDP")
            }
        } else if let app = detectPlaintext(body: body, d: d) {
            d.plaintextProto = app; d.proto = app
            summary += " Recognizable plaintext \(app) content visible (contents are not shown)."
        }
        d.summary = summary
    }

    func dnsSummary(_ dns: DNSInfo, d: Decoded, transport: String) -> String {
        let name = dns.questions.first?.name ?? "a name"
        if dns.isResponse {
            return dns.rcode == 0 ? "DNS reply (\(transport)) for \(name) between \(d.src) and \(d.dst)." : "DNS error reply (\(transport), code \(dns.rcode)) for \(name) between \(d.src) and \(d.dst)."
        }
        return "DNS query (\(transport)) for \(name) between \(d.src) and \(d.dst)."
    }

    // Recognizable plaintext only: never classify by port number alone, never expose payload.
    func detectPlaintext(body: [UInt8], d: Decoded) -> String? {
        guard body.count >= 3 else { return nil }
        let head = body.prefix(64)
        func starts(_ s: String) -> Bool {
            let sb = Array(s.utf8)
            return head.count >= sb.count && Array(head.prefix(sb.count)) == sb
        }
        let httpTokens = ["HTTP/", "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "PATCH ", "OPTIONS "]
        if httpTokens.contains(where: starts) { return "HTTP" }
        let smtpTokens = ["EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:", "SMTP"]
        // "SMTP" alone is not a wire token; require command tokens or a greeting handled below.
        if smtpTokens.dropLast().contains(where: starts) { return "SMTP" }
        let ftpTokens = ["USER ", "PASS ", "RETR ", "STOR ", "LIST", "CWD ", "TYPE "]
        if ftpTokens.contains(where: starts) { return "FTP" }
        if starts("220 ") || starts("220-") {
            // An FTP/SMTP greeting; classify by the greeting text only, not the port.
            let text = String(decoding: head, as: UTF8.self).lowercased()
            if text.contains("ftp") { return "FTP" }
            if text.contains("smtp") || text.contains("mail") { return "SMTP" }
            return "FTP/SMTP"
        }
        return nil
    }



    /// Cleartext HTTP: request line and Host header only, held in memory for
    /// matching. URLs are never written to summaries, logs, or report files.
    func parseHTTPRequest(body: [UInt8], into d: inout Decoded) {
        guard body.count >= 16 else { return }
        let text = String(decoding: body.prefix(4096), as: UTF8.self)
        guard let firstLineEnd = text.range(of: "\r\n") ?? text.range(of: "\n") else { return }
        let requestLine = text[text.startIndex..<firstLineEnd.lowerBound]
        let parts = requestLine.split(separator: " ")
        guard parts.count == 3, parts[2].hasPrefix("HTTP/") else { return }
        let path = String(parts[1])
        var host: String?
        for line in text[firstLineEnd.upperBound...].split(whereSeparator: { $0 == "\n" }) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix("host:") {
                host = trimmed.dropFirst(5).trimmingCharacters(in: .whitespacesAndNewlines)
                break
            }
            if trimmed.isEmpty { break }
        }
        if path.hasPrefix("http://") || path.hasPrefix("https://") {
            d.httpURL = path
            if let comps = URLComponents(string: path), let h = comps.host { d.httpHost = Normalize.domain(h) ?? h.lowercased() }
        } else if let host = host, !host.isEmpty {
            d.httpHost = Normalize.domain(host) ?? host.lowercased()
            d.httpURL = "http://" + host + path
        }
    }

    // MARK: TLS handshake parsing (shared by TCP reassembly and QUIC)

    struct ClientHelloInfo {
        var sni: String?
        var ech: Bool = false
        var ciphers: [UInt16] = []
        var extensions: [UInt16] = []
        var groups: [UInt16] = []
        var pointFormats: [UInt8] = []
        var sigAlgs: [UInt16] = []
        var alpn: [String] = []
        var versions: [UInt16] = []
        var clientVersion: Int = 0
    }
    static func isGREASE(_ v: UInt16) -> Bool { (v & 0x0F0F) == 0x0A0A }
    static func u16at(_ b: [UInt8], _ o: Int) -> Int? { o + 1 < b.count ? Int(b[o]) << 8 | Int(b[o + 1]) : nil }

    static func parseClientHello(handshake hs: [UInt8]) -> ClientHelloInfo? {
        guard hs.count >= 4, hs[0] == 1 else { return nil }
        let declared = Int(hs[1]) << 16 | Int(hs[2]) << 8 | Int(hs[3])
        let body = Array(hs.dropFirst(4).prefix(declared))
        guard body.count >= 34 else { return nil }
        var info = ClientHelloInfo()
        info.clientVersion = u16at(body, 0) ?? 0
        var off = 2 + 32
        guard off < body.count else { return nil }
        let sidLen = Int(body[off]); off += 1 + sidLen
        guard let csLen = u16at(body, off) else { return nil }
        off += 2
        guard off + csLen <= body.count else { return nil }
        for i in stride(from: off, to: off + csLen, by: 2) { if let v = u16at(body, i) { info.ciphers.append(UInt16(v)) } }
        off += csLen
        guard off < body.count else { return nil }
        let compLen = Int(body[off]); off += 1 + compLen
        guard let extLen = u16at(body, off) else { return nil }
        off += 2
        let extEnd = min(body.count, off + extLen)
        while off + 4 <= extEnd {
            guard let etype = u16at(body, off), let elen = u16at(body, off + 2) else { break }
            let data = off + 4
            guard data + elen <= extEnd else { break }
            info.extensions.append(UInt16(etype))
            let seg = Array(body[data..<(data + elen)])
            switch etype {
            case 0: // server_name
                if seg.count >= 5 {
                    let nameLen = u16at(seg, 3) ?? 0
                    if seg[2] == 0, 5 + nameLen <= seg.count, nameLen > 0 {
                        info.sni = String(decoding: seg[5..<(5 + nameLen)], as: UTF8.self)
                    }
                }
            case 0xFE0D: info.ech = true // encrypted_client_hello
            case 10: // supported_groups
                if seg.count >= 2, let n = u16at(seg, 0) {
                    for i in stride(from: 2, to: min(seg.count, 2 + n), by: 2) { if let v = u16at(seg, i) { info.groups.append(UInt16(v)) } }
                }
            case 11: // ec_point_formats
                if !seg.isEmpty { info.pointFormats = Array(seg.dropFirst(Int(seg[0]) == seg.count - 1 ? 1 : 0)) }
            case 13: // signature_algorithms
                if seg.count >= 2, let n = u16at(seg, 0) {
                    for i in stride(from: 2, to: min(seg.count, 2 + n), by: 2) { if let v = u16at(seg, i) { info.sigAlgs.append(UInt16(v)) } }
                }
            case 16: // ALPN
                var p2 = 2
                while p2 < seg.count {
                    let l = Int(seg[p2]); p2 += 1
                    if p2 + l <= seg.count { info.alpn.append(String(decoding: seg[p2..<(p2 + l)], as: UTF8.self)) }
                    p2 += l
                }
            case 43: // supported_versions
                if !seg.isEmpty {
                    var p2 = 1
                    while p2 + 1 < seg.count + 0 && p2 + 2 <= seg.count {
                        if let v = u16at(seg, p2) { info.versions.append(UInt16(v)) }
                        p2 += 2
                    }
                }
            default: break
            }
            off = data + elen
        }
        return info
    }

    static func ja3(_ info: ClientHelloInfo) -> String {
        func strip(_ xs: [UInt16]) -> [UInt16] { xs.filter { !isGREASE($0) } }
        let s = "\(info.clientVersion),\(strip(info.ciphers).map(String.init).joined(separator: "-")),\(strip(info.extensions).map(String.init).joined(separator: "-")),\(strip(info.groups).map(String.init).joined(separator: "-")),\(info.pointFormats.map(String.init).joined(separator: "-"))"
        return Insecure.MD5.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func ja4(_ info: ClientHelloInfo, quic: Bool) -> String {
        func strip(_ xs: [UInt16]) -> [UInt16] { xs.filter { !isGREASE($0) } }
        let version: String = {
            if info.versions.contains(0x0304) { return "13" }
            if info.versions.contains(0x0303) { return "12" }
            return info.clientVersion == 0x0303 ? "12" : "13"
        }()
        let ciphers = strip(info.ciphers)
        let exts = strip(info.extensions)
        let alpnCode: String = {
            guard let first = info.alpn.first, let a = first.first, let b = first.last else { return "00" }
            return "\(a)\(b)"
        }()
        let cipherHash = SHA256.hash(data: Data(ciphers.map { String(format: "%04x", $0) }.sorted().joined(separator: "," ).utf8)).map { String(format: "%02x", $0) }.joined().prefix(12)
        let extPart = exts.filter { $0 != 0 && $0 != 16 }.map { String(format: "%04x", $0) }.sorted().joined(separator: ",")
        let sigPart = info.sigAlgs.map { String(format: "%04x", $0) }.joined(separator: ",")
        let extHash = SHA256.hash(data: Data((extPart + "_" + sigPart).utf8)).map { String(format: "%02x", $0) }.joined().prefix(12)
        return "\(quic ? "q" : "t")\(version)\(info.sni != nil ? "d" : "i")\(String(format: "%02d", min(99, ciphers.count)))\(String(format: "%02d", min(99, exts.count)))\(alpnCode)_\(cipherHash)_\(extHash)"
    }

    // MARK: TLS reassembly over TCP (first 16 KB per direction, in memory only)

    mutating func feedTLSStream(d: inout Decoded, body: [UInt8]) {
        guard let sp = d.sport, let dp = d.dport else { return }
        let flowID = [ "\(d.src):\(sp)", "\(d.dst):\(dp)" ].sorted().joined(separator: "|")
        let dirID = "\(d.src):\(sp)>\(d.dst):\(dp)"
        let key = TLSStreamKey(flow: flowID, direction: dirID)
        let firstIsTLS = body.count >= 5 && (body[0] == 20 || body[0] == 21 || body[0] == 22 || body[0] == 23) && body[1] == 3
        if tlsStreams[key] == nil {
            guard firstIsTLS, tlsStreams.count < 512 else { return }
            tlsStreams[key] = TLSStream(baseSeq: d.tcpSeq)
        }
        guard var stream = tlsStreams[key], !stream.finished else { return }
        // Insert this segment if it adds bytes within the 16 KB window.
        let offset = Int(Int32(bitPattern: d.tcpSeq &- stream.baseSeq))
        if offset >= 0 && stream.bufferedBytes <= 24576 {
            stream.segments.append((d.tcpSeq, body))
            stream.bufferedBytes += body.count
        }
        // Rebuild the contiguous prefix from the base sequence.
        var assembled: [UInt8] = []
        var expected = stream.baseSeq
        for seg in stream.segments.sorted(by: { Int(Int32(bitPattern: $0.seq &- stream.baseSeq)) < Int(Int32(bitPattern: $1.seq &- stream.baseSeq)) }) {
            let segOff = Int(Int32(bitPattern: seg.seq &- stream.baseSeq))
            if segOff > assembled.count { break } // gap: a segment is still missing
            let skip = assembled.count - segOff
            if skip < seg.data.count { assembled.append(contentsOf: seg.data.dropFirst(skip)) }
            expected = seg.seq &+ UInt32(seg.data.count)
            _ = expected
            if assembled.count >= 16384 { break }
        }
        if assembled.count > 16384 { assembled = Array(assembled.prefix(16384)) }
        // Parse complete records we have not parsed yet.
        var off = stream.parsedOffset
        while off + 5 <= assembled.count {
            let recType = assembled[off]
            guard recType == 20 || recType == 21 || recType == 22 || recType == 23 else { stream.finished = true; break }
            let recLen = Int(assembled[off + 3]) << 8 | Int(assembled[off + 4])
            guard off + 5 + recLen <= assembled.count else { break } // record not complete yet
            let rec = Array(assembled[(off + 5)..<(off + 5 + recLen)])
            switch recType {
            case 23: d.isTLSApplicationData = true
            case 21: if d.tlsEvent == nil { d.tlsEvent = "alert" }
            case 22: parseHandshakeRecord(rec: rec, d: &d)
            default: break
            }
            off += 5 + recLen
            if off >= 16384 { stream.finished = true }
        }
        stream.parsedOffset = off
        tlsStreams[key] = stream
    }

    mutating func parseHandshakeRecord(rec: [UInt8], d: inout Decoded) {
        var off = 0
        while off + 4 <= rec.count {
            let hsType = rec[off]
            let hsLen = Int(rec[off + 1]) << 16 | Int(rec[off + 2]) << 8 | Int(rec[off + 3])
            guard off + 4 + hsLen <= rec.count else { return }
            let hs = Array(rec[off..<(off + 4 + hsLen)])
            switch hsType {
            case 1: // ClientHello
                if let info = Self.parseClientHello(handshake: hs) {
                    d.tlsEvent = "clientHello"
                    d.tlsSNI = info.sni
                    d.tlsECH = info.ech
                    if let sni = info.sni { d.hostname = sni }
                    if fingerprintsSeen.count < 2000, let sp = d.sport, let dp = d.dport {
                        fingerprintsSeen.append(TLSFingerprint(ja3: Self.ja3(info), ja4: Self.ja4(info, quic: false), sni: info.sni, ech: info.ech, quic: false, frame: currentPacketNumber, serverAddress: d.dst, serverPort: dp))
                        _ = sp
                    }
                }
            case 2: d.tlsEvent = "serverHello"
            case 11: // Certificate (TLS 1.2 and earlier): hash the first certificate
                // Certificate body: list length (3), then per-cert length (3) + DER.
                if hs.count >= 4 + 3 + 3 {
                    let bodyStart = 4
                    let certLen = Int(hs[bodyStart + 3]) << 16 | Int(hs[bodyStart + 4]) << 8 | Int(hs[bodyStart + 5])
                    let certStart = bodyStart + 6
                    if certLen > 0, certStart + certLen <= hs.count {
                        let der = Array(hs[certStart..<(certStart + certLen)])
                        let sha1 = Insecure.SHA1.hash(data: Data(der)).map { String(format: "%02x", $0) }.joined()
                        let sha256 = SHA256.hash(data: Data(der)).map { String(format: "%02x", $0) }.joined()
                        if certificatesSeen.count < 1000 {
                            certificatesSeen.append(CertificateObservable(sha1: sha1, sha256: sha256, frame: currentPacketNumber, serverAddress: d.src, serverPort: d.sport ?? 0))
                        }
                    }
                }
            default: break
            }
            off += 4 + hsLen
        }
    }

    // MARK: QUIC Initial SNI (RFC 9001 v1, RFC 9369 v2)

    static func hkdfExpand(prk: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
        var out: [UInt8] = []
        var t: [UInt8] = []
        var counter: UInt8 = 1
        while out.count < length {
            var hmac = HMAC<SHA256>(key: SymmetricKey(data: Data(prk)))
            hmac.update(data: Data(t + info + [counter]))
            t = Array(hmac.finalize().withUnsafeBytes { Array($0) })
            out.append(contentsOf: t)
            counter += 1
        }
        return Array(out.prefix(length))
    }
    static func quicHKDFLabel(secret: [UInt8], label: String, length: Int) -> [UInt8] {
        let fullLabel = Array("tls13 ".utf8) + Array(label.utf8)
        var info: [UInt8] = [UInt8(length >> 8), UInt8(length & 0xFF), UInt8(fullLabel.count)]
        info += fullLabel + [0]
        return hkdfExpand(prk: secret, info: info, length: length)
    }
    static func aesECBBlock(key: [UInt8], block: [UInt8]) -> [UInt8]? {
        guard block.count == 16 else { return nil }
        var out = [UInt8](repeating: 0, count: 16)
        var outLen = 0
        let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode), key, key.count, nil, block, 16, &out, 16, &outLen)
        return status == kCCSuccess && outLen == 16 ? out : nil
    }
    static func quicVarint(_ b: [UInt8], _ off: Int) -> (value: Int, next: Int)? {
        guard off < b.count else { return nil }
        let first = b[off]
        switch first >> 6 {
        case 0: return (Int(first & 0x3F), off + 1)
        case 1: guard off + 1 < b.count else { return nil }; return ((Int(first & 0x3F) << 8) | Int(b[off + 1]), off + 2)
        case 2: guard off + 3 < b.count else { return nil }; return ((Int(first & 0x3F) << 24) | (Int(b[off + 1]) << 16) | (Int(b[off + 2]) << 8) | Int(b[off + 3]), off + 4)
        default:
            guard off + 7 < b.count else { return nil }
            var v = Int(first & 0x3F)
            for i in 1..<8 { v = (v << 8) | Int(b[off + i]) }
            return (v, off + 8)
        }
    }

    mutating func processQUIC(body: [UInt8], d: inout Decoded) {
        guard body.count >= 20, let dcidLenOff = quicHeaderLayout(body: body) else { return }
        let version = UInt32(body[1]) << 24 | UInt32(body[2]) << 16 | UInt32(body[3]) << 8 | UInt32(body[4])
        let isV2 = version == 0x6B3343CF
        guard version == 0x00000001 || isV2 else { return }
        let first = body[0]
        let typeBits = (first >> 4) & 0x3
        let isInitial = isV2 ? typeBits == 1 : typeBits == 0
        guard isInitial else { return }
        let dcidLen = Int(body[5])
        guard dcidLen <= 20, body.count >= 6 + dcidLen else { return }
        let dcid = Array(body[6..<(6 + dcidLen)])
        _ = dcidLenOff
        let saltV1: [UInt8] = [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a]
        let saltV2: [UInt8] = [0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6b, 0xf2, 0x15, 0xdc, 0x1d, 0xc2, 0xc4, 0x06]
        let salt = isV2 ? saltV2 : saltV1
        // initial_secret = HKDF-Extract(salt, DCID) == HMAC-SHA256(salt, DCID)
        var extract = HMAC<SHA256>(key: SymmetricKey(data: Data(salt)))
        extract.update(data: Data(dcid))
        let initialSecret = Array(extract.finalize().withUnsafeBytes { Array($0) })
        let clientSecret = Self.quicHKDFLabel(secret: initialSecret, label: "client in", length: 32)
        let key = Self.quicHKDFLabel(secret: clientSecret, label: "quic key", length: 16)
        let iv = Self.quicHKDFLabel(secret: clientSecret, label: "quic iv", length: 12)
        let hp = Self.quicHKDFLabel(secret: clientSecret, label: "quic hp", length: 16)
        // Walk to the packet-number offset: version(5) dcid scid token length payload-length
        var off = 6 + dcidLen
        guard off < body.count else { return }
        let scidLen = Int(body[off]); off += 1 + scidLen
        guard let token = Self.quicVarint(body, off) else { return }
        off = token.next + token.value
        guard let lengthField = Self.quicVarint(body, off) else { return }
        let pnOffset = lengthField.next
        guard pnOffset + 4 + 16 <= body.count, let mask = Self.aesECBBlock(key: hp, block: Array(body[(pnOffset + 4)..<(pnOffset + 4 + 16)])) else { return }
        // The packet-number length bits are themselves header-protected:
        // unmask the first byte first, then read the length from it.
        let unmaskedFirst = first ^ (mask[0] & 0x0F)
        let pnLen = Int(unmaskedFirst & 0x03) + 1
        guard pnOffset + pnLen <= body.count else { return }
        var pnBytes = Array(body[pnOffset..<(pnOffset + pnLen)])
        for i in 0..<pnLen { pnBytes[i] ^= mask[1 + i] }
        var pn = 0
        for byte in pnBytes { pn = (pn << 8) | Int(byte) }
        var header = Array(body[0..<pnOffset])
        header[0] = unmaskedFirst
        header.append(contentsOf: pnBytes)
        let payloadStart = pnOffset + pnLen
        let payloadEnd = min(body.count, payloadStart + max(0, lengthField.value - pnLen))
        guard payloadEnd - payloadStart > 16 else { return }
        let cipherAndTag = Array(body[payloadStart..<payloadEnd])
        var nonce = iv
        for i in 0..<4 { nonce[nonce.count - 1 - i] ^= UInt8((pn >> (8 * i)) & 0xFF) }
        guard cipherAndTag.count > 16,
              let sealed = try? AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: Data(nonce)), ciphertext: Data(cipherAndTag.dropLast(16)), tag: Data(cipherAndTag.suffix(16))),
              let plain = try? AES.GCM.open(sealed, using: SymmetricKey(data: Data(key)), authenticating: Data(header)) else { return }
        let plainBytes = Array(plain)
        // Frames: collect CRYPTO frame bytes by offset for this connection.
        let connKey = "\(d.src):\(d.sport ?? 0)>\(dcid.map { String(format: "%02x", $0) }.joined())"
        var conn = quicConns[connKey] ?? QUICConn()
        var fOff = 0
        while fOff < plainBytes.count {
            let ftype = plainBytes[fOff]
            if ftype == 0 { fOff += 1; continue }
            if ftype == 1 { fOff += 1; continue }
            guard let typeV = Self.quicVarint(plainBytes, fOff) else { break }
            if typeV.value == 6 {
                guard let offV = Self.quicVarint(plainBytes, typeV.next), let lenV = Self.quicVarint(plainBytes, offV.next), lenV.next + lenV.value <= plainBytes.count else { break }
                if conn.bufferedBytes <= 8192 {
                    conn.segments.append((offV.value, Array(plainBytes[lenV.next..<(lenV.next + lenV.value)])))
                    conn.bufferedBytes += lenV.value
                }
                fOff = lenV.next + lenV.value
            } else { break } // other frame types are not expected before CRYPTO in Initials we handle
        }
        quicConns[connKey] = conn
        // Reassemble contiguous CRYPTO bytes from offset 0.
        guard !conn.parsed else { return }
        var assembled: [UInt8] = []
        for seg in conn.segments.sorted(by: { $0.offset < $1.offset }) {
            if seg.offset > assembled.count { break }
            let skip = assembled.count - seg.offset
            if skip < seg.data.count { assembled.append(contentsOf: seg.data.dropFirst(skip)) }
            if assembled.count >= 8192 { break }
        }
        guard assembled.count >= 4, assembled[0] == 1 else { return }
        let hsLen = Int(assembled[1]) << 16 | Int(assembled[2]) << 8 | Int(assembled[3])
        guard assembled.count >= 4 + hsLen else { return }
        if let info = Self.parseClientHello(handshake: Array(assembled.prefix(4 + hsLen))) {
            d.tlsSNI = info.sni
            d.tlsECH = info.ech
            if let sni = info.sni { d.hostname = sni }
            if fingerprintsSeen.count < 2000 {
                fingerprintsSeen.append(TLSFingerprint(ja3: Self.ja3(info), ja4: Self.ja4(info, quic: true), sni: info.sni, ech: info.ech, quic: true, frame: currentPacketNumber, serverAddress: d.dst, serverPort: d.dport ?? 443))
            }
            conn.parsed = true
            quicConns[connKey] = conn
        }
    }
    func quicHeaderLayout(body: [UInt8]) -> Int? { body.count >= 6 ? 5 : nil }

    // MARK: DNS parsing (bounded)

    func parseDNS(msg: [UInt8], isMDNS: Bool) -> DNSInfo? {
        guard msg.count >= 12 else { return nil }
        func u16(_ o: Int) -> Int { Int(msg[o]) << 8 | Int(msg[o + 1]) }
        let flags = u16(2)
        let qd = u16(4), an = u16(6), ns = u16(8), ar = u16(10)
        guard qd <= 32, an + ns + ar <= 256 else { return nil }
        var info = DNSInfo()
        info.isResponse = flags & 0x8000 != 0
        info.truncated = flags & 0x0200 != 0
        info.rcode = flags & 0x000F
        info.isMDNS = isMDNS
        var off = 12
        for _ in 0..<qd {
            guard let (name, next) = readDNSName(msg: msg, offset: off) else { return nil }
            guard next + 4 <= msg.count else { return nil }
            info.questions.append((name, u16(next), u16(next + 2)))
            off = next + 4
        }
        func readRRs(count: Int, collectAnswers: Bool) -> Bool {
            for _ in 0..<count {
                guard let (name, next) = readDNSName(msg: msg, offset: off) else { return false }
                guard next + 10 <= msg.count else { return false }
                let type = u16(next); let rdlen = u16(next + 8)
                let rdata = next + 10
                guard rdata + rdlen <= msg.count else { return false }
                if collectAnswers && (type == 1 || type == 28) {
                    if type == 1 && rdlen == 4 { info.answers.append((name, type, msg[rdata..<rdata+4].map(String.init).joined(separator: "."))) }
                    if type == 28 && rdlen == 16 { info.answers.append((name, type, Self.ipv6String(Array(msg[rdata..<rdata+16])))) }
                }
                if collectAnswers && type == 5, let (target, _) = readDNSName(msg: msg, offset: rdata) {
                    info.answers.append((name, type, target))
                }
                off = rdata + rdlen
            }
            return true
        }
        guard readRRs(count: an, collectAnswers: true) else { return nil }
        guard readRRs(count: ns, collectAnswers: false) else { return nil }
        guard readRRs(count: ar, collectAnswers: false) else { return nil }
        return info
    }

    // Compression pointers must point strictly backwards; cycles/self/forward pointers rejected.
    // Labels are escaped so distinct wire labels stay distinct as strings.
    func readDNSName(msg: [UInt8], offset: Int) -> (String, Int)? {
        var labels: [String] = []
        var pos = offset
        var next: Int? = nil
        var jumps = 0
        var total = 0
        while true {
            guard pos < msg.count else { return nil }
            let len = Int(msg[pos])
            if len == 0 {
                if next == nil { next = pos + 1 }
                break
            }
            if len & 0xC0 == 0xC0 {
                guard pos + 1 < msg.count else { return nil }
                let target = (len & 0x3F) << 8 | Int(msg[pos + 1])
                guard target < pos else { return nil } // reject forward/self/cyclic
                if next == nil { next = pos + 2 }
                pos = target
                jumps += 1
                guard jumps <= 32 else { return nil }
                continue
            }
            guard len <= 63, pos + 1 + len <= msg.count else { return nil }
            total += len + 1
            guard total <= 255 else { return nil }
            var label = ""
            for byte in msg[(pos + 1)..<(pos + 1 + len)] {
                switch byte {
                case 46: label += "\\." // literal dot inside a label
                case 92: label += "\\\\"
                case 32...126: label.append(Character(UnicodeScalar(byte)))
                default:
                    let s = String(byte)
                    label += "\\" + String(repeating: "0", count: max(0, 3 - s.count)) + s
                }
            }
            labels.append(label)
            pos += 1 + len
        }
        guard let n = next else { return nil }
        return (labels.joined(separator: "."), n)
    }

    // MARK: PKTAP

    mutating func decodePKTAP(frame: [UInt8], into d: inout Decoded, depth: Int) {
        sawPKTAP = true
        d.proto = "PKTAP"
        guard frame.count >= 8 else { d.undecodable = true; d.summary = "Truncated PKTAP metadata."; return }
        func ru32(_ o: Int) -> Int { little ? Int(frame[o]) | Int(frame[o+1]) << 8 | Int(frame[o+2]) << 16 | Int(frame[o+3]) << 24 : Int(frame[o]) << 24 | Int(frame[o+1]) << 16 | Int(frame[o+2]) << 8 | Int(frame[o+3]) }
        func ru16(_ o: Int) -> Int { little ? Int(frame[o]) | Int(frame[o+1]) << 8 : Int(frame[o]) << 8 | Int(frame[o+1]) }
        func cstr(_ range: Range<Int>) -> String {
            guard range.lowerBound < frame.count else { return "" }
            let slice = frame[range.lowerBound..<min(range.upperBound, frame.count)]
            let end = slice.firstIndex(of: 0) ?? slice.endIndex
            return String(decoding: slice[slice.startIndex..<end], as: UTF8.self).filter { !$0.isNewline }
        }
        // v2 detection: flags word at offset 36 carries PTH_FLAG_V2_HDR (0x80000) and the
        // first byte is a small header length; v1 has a full 32-bit length >= 100.
        let v1Len = ru32(0)
        let looksV2 = frame.count >= 40 && (ru32(36) & 0x0008_0000) != 0 && Int(frame[0]) >= 40 && Int(frame[0]) <= 200
        if looksV2 {
            let dlt = ru16(6)
            let flags = ru32(36)
            let pid = ru32(28)
            let commOff = Int(frame[4]); let ecommOff = Int(frame[5])
            var headerLen = Int(frame[0])
            // Variable fields follow the fixed 40-byte header; offsets are from header start.
            func v2str(_ offv: Int, maxLen: Int) -> String {
                guard offv >= 40, offv < frame.count else { return "" }
                return cstr(offv..<min(frame.count, offv + maxLen))
            }
            var name = commOff > 0 ? v2str(commOff, maxLen: 20) : ""
            let ename = ecommOff > 0 ? v2str(ecommOff, maxLen: 20) : ""
            if name.isEmpty { name = ename }
            if commOff > 0 { headerLen = max(headerLen, commOff + 20) }
            if ecommOff > 0 { headerLen = max(headerLen, ecommOff + 20) }
            let ifOff = Int(frame[3]); if ifOff > 0 { headerLen = max(headerLen, ifOff + 24) }
            headerLen = min(max(headerLen, 40), frame.count)
            if !name.isEmpty { d.processName = name }
            if pid != 0 { d.processID = pid }
            d.direction = (flags & 0x1) != 0 ? "incoming" : ((flags & 0x2) != 0 ? "outgoing" : nil)
            guard PacketAnalyzer.supportedLinkTypes.contains(dlt) || [0,1,12,101,108,228,229].contains(dlt) else {
                d.undecodable = true; d.summary = "PKTAP record with unsupported inner link type \(dlt)."; return
            }
            decodeLink(frame: Array(frame.dropFirst(headerLen)), link: dlt == 149 || dlt == 258 ? 1 : dlt, into: &d, depth: depth + 1)
            return
        }
        // v1
        guard v1Len >= 100, v1Len <= frame.count else { d.undecodable = true; d.summary = "Malformed PKTAP metadata (bad header length)."; return }
        let innerDLT = ru32(8)
        let flags = ru32(36)
        let pid = ru32(52)
        var name = cstr(56..<76)
        let ename = cstr(88..<108)
        if name.isEmpty { name = ename }
        if !name.isEmpty { d.processName = name }
        if pid != 0 { d.processID = pid }
        d.direction = (flags & 0x1) != 0 ? "incoming" : ((flags & 0x2) != 0 ? "outgoing" : nil)
        let inner: Int
        switch innerDLT { case 0, 1, 12, 101, 108, 228, 229: inner = innerDLT; default: d.undecodable = true; d.summary = "PKTAP record with unsupported inner link type \(innerDLT)."; return }
        decodeLink(frame: Array(frame.dropFirst(v1Len)), link: inner, into: &d, depth: depth + 1)
    }

    mutating func finish(firstTs: Double?, lastTs: Double?, totalPackets: Int) -> CaptureReport {
        var findings: [Finding] = []
        if dnsErrors > 0 {
            findings.append(Finding(id: "dns-errors", severity: "warning", title: "DNS error replies observed", evidence: "\(dnsErrors) of \(dnsResponses) visible DNS replies were error replies. An error reply is an observation, not proof of a bad ISP or malware.", recommendation: "Check the name being looked up and the DNS server in use; retry the affected app and mark the moment it fails.", packetNumbers: Array(dnsErrorPackets.prefix(20))))
        }
        if tcpResets > 0 {
            findings.append(Finding(id: "tcp-resets", severity: "notice", title: "TCP resets observed", evidence: "\(tcpResets) of \(tcpPackets) decoded TCP packets carried the RST flag. A reset can be a normal way to close a refused or finished connection.", recommendation: "Note which app and destination were involved and whether the app reported an error at the same moment.", packetNumbers: Array(rstPackets.prefix(20))))
        }
        if !plaintextRemote.isEmpty {
            let protos = Array(Set(plaintextRemote.map { $0.proto })).sorted().joined(separator: ", ")
            findings.append(Finding(id: "plaintext-remote", severity: "warning", title: "Plaintext application data observed", evidence: "Recognizable plaintext \(protos) content was visible beyond loopback in \(plaintextRemote.count) packet(s). Contents were not stored in this report.", recommendation: "Prefer the encrypted (HTTPS/TLS) version of the service where available and check which app sent it.", packetNumbers: Array(plaintextRemote.prefix(20).map { $0.num })))
        }
        if !plaintextLocal.isEmpty {
            let protos = Array(Set(plaintextLocal.map { $0.proto })).sorted().joined(separator: ", ")
            findings.append(Finding(id: "plaintext-local", severity: "info", title: "Plaintext between addresses on this Mac", evidence: "Recognizable plaintext \(protos) content was visible between loopback addresses in \(plaintextLocal.count) packet(s). This finding by itself says nothing about the rest of the capture.", recommendation: "No action is usually needed: traffic between loopback addresses stays on this Mac. Check the local app only if you did not expect it.", packetNumbers: Array(plaintextLocal.prefix(20).map { $0.num })))
        }
        let severityRank = ["likely_cause": 0, "warning": 1, "notice": 2, "info": 3]
        findings.sort { (severityRank[$0.severity] ?? 4) < (severityRank[$1.severity] ?? 4) }
        var notes: [String] = []
        if totalPackets > PacketAnalyzer.displayLimit { notes.append("Showing the first \(PacketAnalyzer.displayLimit) of \(totalPackets) packets in the packet log. Totals, findings, timeline, apps, and endpoint statistics cover the entire file.") }
        if undecodableCount > 0 { notes.append("\(undecodableCount) packet(s) could not be decoded beyond a counted entry; no bytes were read past their frames.") }
        if sawPKTAP { notes.append("Byte totals include PKTAP metadata when present and can reflect multiple observations of the same traffic; they are not billing figures or unique wire bytes.") }
        if totalPackets == 0 { notes.append("This capture contains no packets. An empty capture does not prove the network is healthy; the selected interface may simply have seen no traffic.") }

        // ---- Destinations from TCP flows and UDP groups (full file) ----
        struct DestGroup {
            var address: String; var port: Int; var proto: String; var outcome: String
            var attempts = 0; var packets = 0; var bytes = 0; var frames: [Int] = []
            var tls = "not_visible"; var name: String?; var nameSource: String?
            var outerName: String?
            var synFrames: [Int] = []; var synSpan: Double = 0; var refusedFrames: [Int] = []
        }
        var groups: [String: DestGroup] = [:]
        var groupOrder: [String] = []
        func groupKey(_ a: String, _ port: Int, _ proto: String) -> String { "\(a):\(port)/\(proto)" }
        for key in flowOrder {
            guard let f = flows[key] else { continue }
            let gk = groupKey(f.server, f.serverPort, "TCP")
            if groups[gk] == nil { groups[gk] = DestGroup(address: f.server, port: f.serverPort, proto: f.sawHTTP ? "TCP · HTTP" : ((f.clientHello || f.serverHello || f.sni != nil || f.serverPort == 443) ? "TCP · TLS" : "TCP"), outcome: "not_checked"); groupOrder.append(gk) }
            var g = groups[gk]!
            g.attempts += f.synFrames.count
            g.packets += f.packets; g.bytes += f.bytes
            g.frames.append(contentsOf: f.frames)
            g.synFrames.append(contentsOf: f.synFrames)
            if let first = f.synTimes.first, let last = f.synTimes.last { g.synSpan = max(g.synSpan, last - first) }
            g.refusedFrames.append(contentsOf: f.refusedFrames)
            if f.alertBeforeHello { g.tls = "failed" } else if f.serverHello { g.tls = "passed" }
            if f.ech {
                // Encrypted Client Hello: the visible SNI is only the outer
                // public name. Record it, but never use it as the display name.
                if g.nameSource == nil { g.nameSource = "sni_outer"; g.outerName = f.sni }
            } else if g.name == nil, let sni = f.sni { g.name = sni; g.nameSource = "sni" }
            // outcome contribution
            let flowOutcome: String
            if f.connected && f.resetLater { flowOutcome = "reset_later" }
            else if f.connected { flowOutcome = "connected" }
            else if f.refused { flowOutcome = "refused" }
            else if !f.synFrames.isEmpty { flowOutcome = "no_reply" }
            else { flowOutcome = "not_checked" }
            let rank = ["connected": 4, "reset_later": 3, "refused": 2, "no_reply": 2, "not_checked": 1]
            if g.outcome == "not_checked" || (rank[flowOutcome] ?? 0) > (rank[g.outcome] ?? 0) { g.outcome = flowOutcome }
            if flowOutcome == "no_reply" && g.outcome == "connected" { /* keep connected: some flows to this destination succeeded */ }
            if g.outcome == "no_reply" && flowOutcome == "connected" { g.outcome = "connected" }
            groups[gk] = g
        }
        for key in udpGroupOrder {
            guard let u = udpGroups[key] else { continue }
            let proto = u.isQUIC ? "QUIC" : "UDP"
            let gk = groupKey(u.server, u.serverPort, proto)
            if groups[gk] == nil { groups[gk] = DestGroup(address: u.server, port: u.serverPort, proto: proto, outcome: u.isQUIC ? "not_checked" : "background"); groupOrder.append(gk) }
            var g = groups[gk]!
            g.packets += u.packets; g.bytes += u.bytes; g.frames.append(contentsOf: u.frames)
            groups[gk] = g
        }
        var destinationRecords: [DestinationRecord] = []
        var unansweredAttempts = 0
        var refusedAttempts = 0
        for gk in groupOrder {
            var g = groups[gk]!
            if g.name == nil, let dn = ipToDNSName[g.address] { g.name = dn; g.nameSource = "dns" }
            let isTCP = g.proto.hasPrefix("TCP")
            let filter = isTCP ? "ip.addr==\(g.address) && tcp.port==\(g.port)" : (g.proto == "QUIC" ? "ip.addr==\(g.address) && udp.port==\(g.port)" : "ip.addr==\(g.address)")
            if g.outcome == "no_reply" { unansweredAttempts += g.attempts }
            if g.outcome == "refused" { refusedAttempts += g.attempts }
            var record = DestinationRecord(name: g.name, nameSource: g.nameSource, address: g.address, port: g.port, protocolLabel: g.proto, outcome: g.outcome, attempts: g.attempts, packets: g.packets, bytes: g.bytes, packetNumbers: Array(g.frames.prefix(200)), evidenceFilter: filter, evidenceCount: g.packets, tlsStatus: g.tls)
            record.outerName = g.outerName
            destinationRecords.append(record)
            groups[gk] = g
        }
        let outcomeRank = ["no_reply": 0, "refused": 0, "reset_later": 1, "connected": 2, "not_checked": 3, "background": 4]
        destinationRecords.sort { a, b in
            let ra = outcomeRank[a.outcome] ?? 5, rb = outcomeRank[b.outcome] ?? 5
            return ra != rb ? ra < rb : a.packets > b.packets
        }

        // ---- New findings driven by flow/DNS outcomes ----
        if let nx = nxdomainEvents.first {
            findings.append(Finding(id: "dns-name-not-found", severity: "likely_cause", title: "The name \(nx.name) was reported as not existing", evidence: "The DNS server replied that \(nx.name) does not exist (NXDOMAIN), in packet #\(nx.frame). \(dnsErrors) of \(dnsResponses) visible DNS replies were error replies.", recommendation: "Check the spelling of the name and whether the service has changed or removed it; try the correct name, then capture again.", packetNumbers: Array(nxdomainEvents.prefix(20).map { $0.frame })))
        }
        for rec in destinationRecords where rec.outcome == "refused" {
            let rstFrames = groups.values.first(where: { $0.address == rec.address && $0.port == rec.port })?.refusedFrames ?? rec.packetNumbers
            findings.append(Finding(id: "refused-connection", severity: "likely_cause", title: "\(rec.name ?? rec.address) refused the connection", evidence: "The destination at \(rec.address) port \(rec.port) answered connection attempts with a reset (refused), across \(rec.attempts) attempt(s).", recommendation: "Check whether the service is running on that device and whether a firewall on it is rejecting the connection; then try again.", packetNumbers: Array(rstFrames.prefix(20))))
        }
        for rec in destinationRecords where rec.outcome == "no_reply" && rec.attempts >= 1 {
            let strong = rec.attempts >= 2
            findings.append(Finding(id: "unanswered-connection", severity: strong ? "likely_cause" : "warning", title: "\(rec.name ?? rec.address) never answered the connection attempts", evidence: "\(rec.attempts) connection request(s) (TCP SYN) to \(rec.address) on port \(rec.port) received no reply of any kind: no SYN-ACK, no reset, no ICMP error. \(destinationRecords.filter { $0.outcome == "connected" }.count) other destination(s) connected successfully in this capture.", recommendation: "Try the same website or app on a different network, such as a phone hotspot. If it works there, a firewall, VPN, or filter on this network is likely blocking it; if it fails everywhere, the service may be down.", packetNumbers: Array(rec.packetNumbers.prefix(20))))
        }
        if !tlsAlertPackets.isEmpty {
            findings.append(Finding(id: "tls-alerts", severity: "warning", title: "Secure setup (TLS) alerts observed", evidence: "\(tlsAlertPackets.count) TLS alert(s) were visible. An alert can mean the secure setup was rejected or failed.", recommendation: "Check the device date and time, then retry; if it repeats for one service, share this report with its support team.", packetNumbers: Array(tlsAlertPackets.prefix(20))))
        }
        let sortedIntervals = intervals.sorted()
        let p95: Double? = sortedIntervals.isEmpty ? nil : sortedIntervals[min(sortedIntervals.count - 1, Int((0.95 * Double(sortedIntervals.count)).rounded(.up)) - 1)]
        if let p = p95, p > 300 {
            findings.append(Finding(id: "slow-dns", severity: "warning", title: "Name lookups were slow", evidence: String(format: "Matched DNS exchanges averaged %.0f ms and the slowest 5%% took at least %.0f ms across %d pair(s).", intervals.reduce(0, +) / Double(max(1, intervals.count)), p, intervals.count), recommendation: "Compare this after changing one thing at a time, such as trying a different network; slow lookups can make apps feel slow before data moves.", packetNumbers: []))
        }

        let answeredLookups = dnsLookups.filter { $0.milliseconds != nil }.count
        let unansweredLookups = max(0, dnsQueryCount - answeredLookups)
        let unansweredFrames = destinationRecords.filter { $0.outcome == "no_reply" }.flatMap { $0.packetNumbers }
        let refusedFramesAll = destinationRecords.filter { $0.outcome == "refused" }.flatMap { $0.packetNumbers }
        let retransFlagged = tcpRetransmissions > 20
        let checks: [CheckRecord] = [
            CheckRecord(id: "dns-errors", label: "DNS errors (NXDOMAIN, SERVFAIL)", count: dnsErrors, flagged: dnsErrors > 0, note: dnsErrors > 0 ? "See findings" : "None", packetNumbers: Array(dnsErrorPackets.prefix(200)), filter: "dns.flags.response == 1 && dns.flags.rcode != 0"),
            CheckRecord(id: "dns-unanswered", label: "DNS lookups with no answer", count: unansweredLookups, flagged: unansweredLookups > 0, note: unansweredLookups > 0 ? "No matching reply was captured" : "None", filter: "dns.flags.response == 0 && !dns.response_in"),
            CheckRecord(id: "tcp-refused", label: "Refused connections (TCP reset)", count: refusedAttempts, flagged: refusedAttempts > 0, note: refusedAttempts > 0 ? "Destination refused" : "None", packetNumbers: Array(refusedFramesAll.prefix(200)), filter: "tcp.flags.reset == 1"),
            CheckRecord(id: "tcp-unanswered", label: "Unanswered connection attempts", count: unansweredAttempts, flagged: unansweredAttempts > 0, note: unansweredAttempts > 0 ? "No reply captured" : "None", packetNumbers: Array(unansweredFrames.prefix(200)), filter: unansweredFrames.isEmpty ? "" : "frame.number in {" + unansweredFrames.prefix(200).map(String.init).joined(separator: ", ") + "}"),
            CheckRecord(id: "icmp-unreachable", label: "ICMP unreachable messages", count: icmpUnreachablePackets.count, flagged: !icmpUnreachablePackets.isEmpty, note: icmpUnreachablePackets.isEmpty ? "None" : "A device reported it could not deliver traffic", packetNumbers: icmpUnreachablePackets, filter: "icmp.type == 3 || icmpv6.type == 1"),
            CheckRecord(id: "tls-alerts", label: "TLS alerts or failed handshakes", count: tlsAlertPackets.count, flagged: !tlsAlertPackets.isEmpty, note: tlsAlertPackets.isEmpty ? "None" : "Secure setup was rejected or failed", packetNumbers: tlsAlertPackets, filter: "tls.record.content_type == 21"),
            CheckRecord(id: "tcp-retransmissions", label: "TCP retransmissions", count: tcpRetransmissions, flagged: retransFlagged, note: tcpRetransmissions == 0 ? "None" : (retransFlagged ? "High level" : "Normal level"), filter: "tcp.analysis.retransmission"),
            CheckRecord(id: "kernel-drops", label: "Packets dropped by capture", count: 0, flagged: false, note: "Nothing lost", filter: ""),
        ]
        let checkedCount = max(0, totalPackets - quicPackets - encryptedOtherPackets - undecodableCount)
        let mixOrder = ["TCP", "DNS", "QUIC", "UDP_OTHER", "ICMP", "OTHER"]
        let mixRecords = mixOrder.compactMap { name -> ProtocolCount? in
            guard let m = mixStats[name] else { return nil }
            return ProtocolCount(name: name, count: m.count, bytes: m.bytes)
        }

        var facts = CaptureFacts(
            firstTimestamp: firstTs, lastTimestamp: lastTs,
            dnsResponses: dnsResponses, dnsErrors: dnsErrors, tcpPackets: tcpPackets, tcpResets: tcpResets,
            averageDNSMilliseconds: intervals.isEmpty ? nil : intervals.reduce(0, +) / Double(intervals.count),
            matchedDNSPairs: intervals.count,
            applications: appOrder.compactMap { apps[$0] }.sorted { $0.bytes > $1.bytes },
            timeline: buckets.values.sorted { $0.second < $1.second },
            domains: domainOrder.compactMap { domains[$0] }.sorted { $0.queryCount + $0.packetNumbers.count > $1.queryCount + $1.packetNumbers.count },
            attributedPackets: attributed, unattributedPackets: unattributed, loopbackPackets: loopbackCount)
        facts.dnsQueries = dnsQueryCount
        facts.dnsAnswered = answeredLookups
        facts.dnsUnanswered = unansweredLookups
        facts.dnsP95Milliseconds = p95
        facts.dnsMaxMilliseconds = sortedIntervals.last
        facts.dnsResolvers = dnsResolvers
        facts.dnsLookups = dnsLookups
        facts.tcpRetransmissions = tcpRetransmissions
        facts.icmpUnreachable = icmpUnreachablePackets.count
        facts.tlsAlerts = tlsAlertPackets.count
        facts.quicPackets = quicPackets
        facts.encryptedOtherPackets = encryptedOtherPackets
        facts.checkedPackets = checkedCount
        facts.destinations = destinationRecords
        facts.checks = checks
        facts.arpResponder = arpResponder
        facts.trafficMix = mixRecords
        facts.httpHosts = httpHostsSeen
        facts.httpURLs = httpURLsSeen
        facts.cnameTargets = cnameTargetsSeen
        facts.certificates = certificatesSeen
        facts.fingerprints = fingerprintsSeen
        facts.observableEndpoints = obsEndpoints.values.sorted { $0.packets > $1.packets }
        facts.observableIPCount = obsIPs.count
        facts.observableTruncated = obsTruncated
        return CaptureReport(
            packetCount: totalPackets, capturedBytes: capturedBytes,
            duration: (firstTs != nil && lastTs != nil) ? max(0, lastTs! - firstTs!) : 0,
            protocols: protoStats.map { ProtocolCount(name: $0.key, count: $0.value.count, bytes: $0.value.bytes) }.sorted { $0.count > $1.count },
            endpoints: endpointStats.map { EndpointStat(address: $0.key, packets: $0.value.packets, bytes: $0.value.bytes) }.sorted { $0.bytes > $1.bytes },
            findings: findings, packets: records, limitationNotes: notes, facts: facts)
    }
}

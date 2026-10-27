namespace PacketScope.Windows;

public sealed class PacketRecord
{
    public int Id;
    public double Timestamp;
    public string Source = "Unknown";
    public string Destination = "Unknown";
    public int? SourcePort;
    public int? DestinationPort;
    public string ProtocolName = "Unknown";
    public int Length; // original length from the PCAP record
    public string Summary = "";
    public string? ProcessName;
    public int? ProcessId;
    public string? Hostname;
}

public sealed class ProtocolCount { public string Name = ""; public int Count; public long Bytes; }
public sealed class EndpointStat { public string Address = ""; public int Packets; public long Bytes; }

public sealed class Finding
{
    public string Id = "";
    public string Severity = "info"; // likely_cause | warning | notice | info
    public string Title = "";
    public string Evidence = "";
    public string Recommendation = "";
    public List<int> PacketNumbers = new();
}

public sealed class DnsLookup
{
    public string Name = "";
    public string Type = "";
    public double? Milliseconds;
    public string Rcode = "";
    public int Frame;
}

public sealed class DestinationRecord
{
    public string? Name;
    public string? NameSource; // dns | sni | sni_outer
    public string Address = "";
    public int Port;
    public string ProtocolLabel = "TCP";
    public string Outcome = "not_checked"; // connected | refused | no_reply | reset_later | not_checked | background
    public int Attempts;
    public int Packets;
    public long Bytes;
    public List<int> PacketNumbers = new();
    public string EvidenceFilter = "";
    public int EvidenceCount;
    public string TlsStatus = "not_visible"; // passed | failed | not_visible
    public List<string> IntelMatchIds = new();
    public string? IntelTopSeverity;
}

public sealed class CheckRecord
{
    public string Id = "";
    public string Label = "";
    public int Count;
    public bool Flagged;
    public string Note = "";
    public List<int> PacketNumbers = new();
    public string Filter = "";
}

public sealed class TrafficBucket { public int Second; public int Packets; public long Bytes; public int DnsErrors; public int TcpResets; }

public sealed class CertificateObservable { public string Sha1 = ""; public string Sha256 = ""; public int Frame; public string ServerAddress = ""; public int ServerPort; }
public sealed class TlsFingerprint { public string Ja3 = ""; public string Ja4 = ""; public string? Sni; public bool Ech; public bool Quic; public int Frame; public string ServerAddress = ""; public int ServerPort; }
public sealed class ObservableEndpoint { public string Address = ""; public int Port; public int Packets; public List<int> Frames = new(); }

public sealed class CaptureFacts
{
    public double? FirstTimestamp;
    public double? LastTimestamp;
    public int DnsResponses, DnsErrors, TcpPackets, TcpResets;
    public double? AverageDnsMilliseconds;
    public int MatchedDnsPairs;
    public double? DnsP95Milliseconds, DnsMaxMilliseconds;
    public int DnsQueries, DnsAnswered, DnsUnanswered;
    public List<string> DnsResolvers = new();
    public List<DnsLookup> DnsLookups = new();
    public List<(string Name, List<string> Addresses, int QueryCount, int ErrorCount, List<int> PacketNumbers)> Domains = new();
    public List<DestinationRecord> Destinations = new();
    public List<CheckRecord> Checks = new();
    public List<TrafficBucket> Timeline = new();
    public List<ProtocolCount> TrafficMix = new();
    public int QuicPackets, EncryptedOtherPackets, CheckedPackets, TcpRetransmissions, IcmpUnreachable, TlsAlerts;
    public string? ArpResponder;
    public List<string> HttpHosts = new();
    public List<string> HttpUrls = new();
    public List<string> CnameTargets = new();
    public List<CertificateObservable> Certificates = new();
    public List<TlsFingerprint> Fingerprints = new();
    public List<ObservableEndpoint> ObservableEndpoints = new();
    public int ObservableIpCount;
    public bool ObservableTruncated;
    public int AttributedPackets, UnattributedPackets;
    public List<(string Name, int? Pid, int Packets, long Bytes, long Sent, long Received, List<string> Destinations, List<int> PacketNumbers)> Applications = new();
}

public sealed class CaptureReport
{
    public int PacketCount;
    public long CapturedBytes;
    public double Duration;
    public List<ProtocolCount> Protocols = new();
    public List<EndpointStat> Endpoints = new();
    public List<Finding> Findings = new();
    public List<PacketRecord> Packets = new();
    public List<string> LimitationNotes = new();
    public CaptureFacts? Facts;
}

public enum CaptureGoal { Website, Slow, Calls, Background }

public static class GoalInfo
{
    public static string Title(CaptureGoal g) => g switch
    {
        CaptureGoal.Website => "A website or app won’t connect",
        CaptureGoal.Slow => "My connection feels slow",
        CaptureGoal.Calls => "A call or stream is interrupted",
        _ => "Understand background activity",
    };
    public static string Guidance(CaptureGoal g) => g switch
    {
        CaptureGoal.Website => "Start the capture, retry the affected operation, and press “It happened just now” when the error appears.",
        CaptureGoal.Slow => "Repeat the slow action during the capture. Captured volume shows what was observed here; it is not a measure of your connection’s capacity.",
        CaptureGoal.Calls => "Mark each freeze or dropout. Encrypted call and stream media stays encrypted; this shows timing and volume, not call content.",
        _ => "Let the capture run and observe which processes and destinations are active. Unknown ownership is not automatically suspicious.",
    };
}

public sealed class ProblemMarker { public double Timestamp; public string Note = "Problem noticed"; }

public sealed class SessionContext
{
    public CaptureGoal Goal = CaptureGoal.Website;
    public string Symptom = "";
    public string Interface = "";
    public double? StartedAt, EndedAt;
    public List<ProblemMarker> Markers = new();
    public bool IsImported;
}

public static class Format
{
    public static string Bytes(long n)
    {
        double d = n;
        if (d >= 1073741824) return $"{d / 1073741824:0.0} GB";
        if (d >= 1048576) return $"{d / 1048576:0.0} MB";
        if (d >= 1024) return $"{d / 1024:0.0} KB";
        return $"{n} B";
    }
    public static string Duration(double s) => s < 60 ? $"{s:0.0} s" : $"{(int)s / 60}:{(int)s % 60:00}";
    public static string PacketTime(double s) => $"{(int)s / 60}:{(s - (int)s / 60 * 60):00.00}";
    public static string Count(long n) => n.ToString("N0");
    public static string Ms(double v) => $"{v:0} ms";
}

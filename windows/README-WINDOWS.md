# PacketScope for Windows

A Windows version of PacketScope, based on the same idea as the macOS app:
choose a troubleshooting question → capture (or import) packets → reproduce
the problem and mark the moment → stop → read a plain-language verdict with
evidence, on its own page, next to any security signal from local threat
feeds.

## Download and run

1. Download **PacketScope-Windows.zip** from the
   [windows-v0.1.0 release](../../releases/tag/windows-v0.1.0) and unzip it.
2. For **live capture**, install [Npcap](https://npcap.com) (free) first —
   PacketScope captures through Npcap's `wpcap.dll`. If opening an adapter
   fails, run PacketScope as administrator. **Importing and analyzing
   existing capture files works without Npcap.**
3. Run `PacketScope.exe`. No installation, account, or API key is needed.

## What it does

- **Guided captures** on the Capture page: four goals, optional symptom,
  interface and duration pickers, large Start/Stop buttons, and
  “It happened just now” markers saved immediately with the session.
- **Import your own log file**: choose or drag-and-drop a classic PCAP
  capture log (any filename; contents are checked). It is analyzed exactly
  like a live capture and opens the same Results page. PCAPNG and text logs
  get a specific explanation instead of results. 100 MiB limit.
- **Results page** rendered from a structured results object: a
  code-decided verdict with one next step, quantified coverage, a
  five-step connection path with the first failed step highlighted,
  findings with evidence packet tables and copyable Wireshark filters,
  per-lookup DNS timing (answered, average, slowest, resolver), eight
  built-in checks, a destinations table, and a timeline with marked
  moments.
- **Threat-intel matching, fully local.** Feeds are registry entries
  (Feodo Tracker, SSLBL certificates, Spamhaus DROP on by default; SSLBL
  JA3 off; ThreatFox/URLhaus hidden until a user adds their own abuse.ch
  Auth-Key and the parsers can be verified). Matching covers destination
  IPs/ports, DNS names (parents match subdomains, never the reverse),
  DNS answers, TLS SNI, HTTP hosts/URLs, certificate SHA1/SHA256, and
  JA3/JA4, over the full deduplicated observable set. Severity starts from
  the feed and adjusts with every reason recorded; private/loopback
  addresses never match; allowlisted values are counted, not hidden.
  A security card sits above the goal verdict when a high or medium match
  exists, and findings are grouped as one per destination. Auth-Keys live
  only in the Windows Credential Manager. Matching never sends capture
  data anywhere.
- **Apps page.** Windows has no PKTAP, so process names come from
  connection-table snapshots taken during the capture and matched by
  endpoint. This is approximate (a shared or reused socket can differ)
  and is labeled as such; missing identity is "Unknown".
- **Compare** before/after sessions, **Ask capture** (local rules guide —
  see below), **Packet log** with search and evidence-filter support,
  **Endpoints**, and redacted **support reports** (defanged indicators,
  feed licenses credited; raw PCAP export is separate and unchanged).

## Differences from the macOS version (v0.1 scope)

- AI summary (optional): the verdict is always decided by the built-in
  checks. If you run a local model server on this device (for example
  Ollama), PacketScope can ask it to *word* the Results summary — the
  wording is validated against the measured numbers before it is shown
  (every number/name/feed/date must exist in the structured results) and
  the code-built template is always the fallback. Only loopback endpoints
  are allowed, so summaries never leave this device; there is no cloud
  model. Configure it under Ask capture → “Results summary wording”.
  Ask answers themselves always come from the local rules guide.
- QUIC server names are not yet extracted (QUIC is reported as “names not
  read, contents encrypted” in coverage); TCP TLS SNI/JA3/JA4 and
  certificate extraction match the Mac behavior, including multi-segment
  ClientHello reassembly and ECH outer-name handling.
- Process attribution is endpoint-matched and approximate (above), rather
  than kernel PKTAP metadata.
- The public-suffix guard uses a conservative built-in list on Windows;
  the macOS app bundles the full Public Suffix List.
- File-hash matching reports “Files: not checked” (this app doesn't
  reconstruct transferred files) rather than implying a clean result.

## Building from source

Requires the .NET 8 SDK on Windows:

```powershell
cd windows\PacketScope.Windows
dotnet publish -c Release -r win-x64 --self-contained true
```

Platform-independent logic (analyzer, results builder, threat-intel
parsers/matcher) is covered by the console test harness:

```powershell
cd windows\PacketScope.Tests
dotnet run -c Release
```

The GUI and Npcap capture can only run on Windows itself; the analyzer and
matcher are exercised by the test harness on any platform.

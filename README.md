# PacketScope 0.2.0

A lightweight, native macOS packet capture and explanation tool for everyday
Mac users and network administrators.

**Journey:** choose a troubleshooting question → start a real capture →
reproduce the symptom → mark the relevant moment → stop → understand the
measured evidence → try a change and compare → optionally save a support
report.

## Features

1. **Guided captures** — four goals (a website or app won't connect, a slow
   connection, an interrupted call or stream, background activity), an
   optional symptom note, durations from 30 seconds to "Until I stop"
   (15-minute maximum), and "It happened just now" markers (up to 50 per
   session, saved immediately to `context.json`).
2. **Understandable explanations** — bounded, safe PCAP parsing with
   findings for visible DNS error replies, TCP resets, and recognizable
   plaintext (loopback plaintext is informational and kept separate). Every
   finding says what was observed, why it may matter, what to check next,
   what it cannot establish, and links supporting packet numbers.
3. **Before/after comparisons** — DNS error share, TCP reset share, matched
   DNS response time, captured traffic rate, and observed packet span, all
   with denominators and uncertainty. Missing denominators report "No
   observed sample", never 0%. A baseline is an in-memory choice: use the
   current capture, choose from history, clear it, or "Run the same check
   again" to preserve the baseline and start a real new capture.
4. **Process attribution** — process name, PID, and direction taken only
   from macOS PKTAP metadata actually present in the records. Nothing is
   inferred from addresses, ports, or domains. Missing identity goes to an
   explicit **Unknown** group.
5. **Capture Q&A** — an always-available local rules guide (labelled
   "Local evidence guide · rules, no AI") and, on macOS 26+ with Apple
   Intelligence, optional on-device answers via Apple FoundationModels
   (weak-linked; the rules guide works without it). Factual app, marker,
   and comparison answers always come from measured data directly. No
   cloud model, account, or API key is involved anywhere.
6. **Support reports with privacy controls** — a live plain-text preview
   with independent toggles (IP addresses off by default, domain names off
   by default, app/process names on by default, your notes off by default),
   applied to the whole generated text. The raw PCAP export is separate
   and copies the original file unchanged.
7. **Import your own log file** — choose or drag-and-drop a classic PCAP
   capture log from another tool (any filename; the contents are checked)
   on the Capture page. It is copied into a local session with the original
   preserved, needs no administrator authorization, and is analyzed through
   exactly the same pipeline as a live capture, opening the same Results
   page. PCAPNG and plain-text files get a clear explanation instead.
8. **Packet and endpoint inspection** — timeline (Apple Charts, amber
   markers), packet log with search, and endpoints.

All analysis, session storage, and optional inference stay on the Mac.
There is no telemetry, external reputation lookup, reverse-DNS lookup, or
cloud inference.

## Download

**macOS ( Apple Silicon and Intel ):** download `PacketScope-macOS.zip`
from the [latest release](../../releases/latest), unzip it, and open
`PacketScope.app` inside the "PacketScope Demo" folder. Requires macOS 13.0
or later. The build is ad hoc signed (not notarized), so on first launch
right-click the app and choose **Open**. Capturing asks for administrator
approval via the standard macOS prompt; opening existing capture files
needs no approval.

**Windows:** a Windows version lives in [`windows/`](windows/) (native
C#/.NET WinForms; live capture through Npcap, fully local threat-intel
matching). Download `PacketScope-Windows.zip` from the
[windows-v0.1.0 release](../../releases/tag/windows-v0.1.0), unzip, install
[Npcap](https://npcap.com) for live capture, and run `PacketScope.exe`.
**Windows requirements:** Windows 10/11 64-bit; Npcap for live capture
(administrator rights may be needed if an adapter won't open); no .NET
install needed (self-contained); optional Ollama for the local AI summary.
Importing and analyzing capture files works without Npcap. See
[`windows/README-WINDOWS.md`](windows/README-WINDOWS.md) for its feature
scope and differences from the macOS app (optional local-model AI summary,
validated with template fallback; QUIC names not yet extracted; process
attribution is endpoint-matched and approximate).

## Building from source

## Requirements

- Runtime: macOS 13.0 or later (universal `arm64` + `x86_64`).
- Build: Xcode command-line tools, `clang`, and `swiftc` in Swift 5 language
  mode. No Xcode project, no third-party packages, nothing to install from
  Homebrew. The bundled C helper links the system `libpcap`.
- Capturing asks for administrator approval via the native macOS prompt
  (the GUI never runs as root, and PocketScope never sees your password).
  Opening existing PCAP files needs no approval.

## Build, test, and package

From the project root:

```sh
bash scripts/build.sh    # → dist/PacketScope.app (universal, ad hoc signed)
bash scripts/test.sh     # runs the automated test suites (synthetic traffic only)
bash scripts/package.sh  # → dist/PacketScope-macOS.zip
```

`package.sh` produces a ZIP which, when extracted, contains:

```text
PacketScope Demo/
  PacketScope.app
  START HERE.txt
```

Signing: the helper and app are **ad hoc signed** for the development demo.
`codesign --verify --deep --strict` is verified in `build.sh` and again on the
extracted ZIP in `package.sh`, along with `lipo` checks that both binaries
contain `arm64` and `x86_64` and a check that `FoundationModels` is
weak-linked. No Developer ID signing or notarization is claimed or performed.

## Layout

```text
PacketScope/
  Sources/
    PacketScopeApp.swift   # app lifecycle, menus, quit cleanup
    AppModel.swift         # main-actor state, capture/import/history/export
    Analyzer.swift         # PCAP parsing and full-file measured facts
    Features.swift         # goals/context, explanations, comparisons, redaction
    CaptureAssistant.swift # rules guide, optional on-device model, output checks
    ContentView.swift      # theme, navigation, overview/packet/endpoint UI
    FeatureViews.swift     # guided setup, timeline/apps/compare/Q&A/history/support
  Helper/capture.c         # packetscope-capture (libpcap, PKTAP, privilege drop)
  Resources/Info.plist
  Tests/                   # 80 automated test cases + live_traffic.py (dev only)
  QUICKSTART.txt
scripts/  build.sh  package.sh  test.sh  make_icon.swift
```

Sessions live under `~/Library/Application Support/PacketScope/Sessions/<timestamp_UUID>/`
containing `traffic.pcap`, `report.json`, `report.txt`, `context.json`, and
live-session `status.json` / `capture.log` / `stop.request` as applicable.

## Capture helper contract

```text
packetscope-capture --interfaces
packetscope-capture --interface INTERFACE --directory SESSION_DIRECTORY
  --uid UID --gid GID --duration SECONDS --max-bytes BYTES
  --watch-pid APP_PID --attribution 1
```

The helper captures passively (non-promiscuous, no probes or injection),
prefers PKTAP for process attribution scoped to the selected interface, and
falls back to an ordinary capture (with attribution off and the limitation
disclosed) when PKTAP is unavailable. It opens BPF with privileges, then
uses `initgroups`/`setgid`/`setuid` to become the invoking user before
creating any output files, enforces a 100 MiB capture file cap and the
requested duration, polls for a validated `stop.request`, publishes
`status.json` atomically about once a second, and reports kernel drops from
`pcap_stats`. This is a demo architecture: there is no persistent privileged
service, no setuid binary, and no permanent BPF permission change.

## Results page

The Results tab renders only from a structured `CaptureResults` object
(`PacketScope/Sources/Results.swift`): a code-decided verdict (template
summary always available; optional on-device AI may only reword it after
strict number/name/citation validation), quantified coverage with a traffic
mix bar, a five-step connection path per destination, findings with evidence
packet tables and copyable display filters, per-lookup DNS timings (answered,
average, p95, slowest, resolver), the eight built-in checks, a destinations
table, and a timeline with marked moments. Destination names come from DNS
answers or TLS ClientHello SNI, never from payload contents, and credentials
or payload data are never sent to the summarizer.

## Verification status (October 26, 2026 run)

- All 80 automated test cases pass (`bash scripts/test.sh`): parser bounds,
  both byte orders and timestamp resolutions, supported link types,
  full-file statistics beyond the 2,000 displayed rows, DNS matching with
  retry/duplicate/mDNS exclusions, PKTAP v1/v2 attribution, loopback vs
  non-loopback plaintext, helper argument and session-directory validation,
  context compatibility, explanations, comparisons, redaction, and the
  assistant's evidence/validation behavior.
- `bash scripts/build.sh` and `bash scripts/package.sh` complete here on
  macOS 27.0 (Swift 6.4, Swift 5 language mode): both binaries are verified
  universal (`arm64` + `x86_64`), the app is ad hoc signed with
  `codesign --verify --deep --strict` passing on the extracted ZIP, and
  `FoundationModels` is verified weak-linked.
- A controlled live capture on `lo0` with synthetic localhost HTTP/ping
  traffic, a saved marker, a user-initiated stop, and post-stop analysis
  was exercised against the bundled helper with the native administrator
  prompt (see the completion report delivered with this build for
  measured numbers from that run).
- A real on-device model answer was exercised when the current machine's
  Apple Intelligence model reported available; the rules-only path is
  covered by the automated tests and is always available.

## Not in this version

No whole-LAN visibility claim, packet decryption, TLS interception, PCAPNG
support, full TCP-stream/IP-fragment reassembly, DNS reassembly across TCP
segments, firewall blocking, intrusion prevention, malware verdicts, public
reputation scoring, cloud chatbot, autonomous remediation, automatic sharing,
or background monitoring service.

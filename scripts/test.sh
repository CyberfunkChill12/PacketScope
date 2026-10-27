#!/usr/bin/env bash
# Compiles and runs the automated test suites (synthetic traffic only) plus helper checks.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SDK="$(xcrun --show-sdk-path)"
BUILD="$ROOT/build/tests"
mkdir -p "$BUILD"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: tests require macOS." >&2
  exit 1
fi

echo "== Building test helper =="
clang -O1 -mmacosx-version-min=13.0 -isysroot "$SDK" \
  "$ROOT/PacketScope/Helper/capture.c" -lpcap -o "$BUILD/packetscope-capture"
chmod +x "$BUILD/packetscope-capture"

echo "== Building test runner =="
cat > "$BUILD/main.swift" <<'EOF'
import Foundation
registerAnalyzerTests()
registerEngineTests()
registerFeatureTests()
registerAssistantTests()
registerResultsTests()
registerThreatFeedTests()
registerThreatIntelTests()
exit(TestHarness.finish())
EOF
swiftc -swift-version 5 -O \
  -sdk "$SDK" -target "$(uname -m)-apple-macos13.0" \
  -framework AppKit -Xlinker -weak_framework -Xlinker FoundationModels \
  "$ROOT/PacketScope/Sources/Analyzer.swift" \
  "$ROOT/PacketScope/Sources/Features.swift" \
  "$ROOT/PacketScope/Sources/CaptureAssistant.swift" \
  "$ROOT/PacketScope/Sources/Results.swift" \
  "$ROOT/PacketScope/Sources/ThreatFeeds.swift" \
  "$ROOT/PacketScope/Sources/IntelMatcher.swift" \
  "$ROOT/PacketScope/Sources/AppModel.swift" \
  "$ROOT"/PacketScope/Tests/*.swift \
  "$BUILD/main.swift" \
  -o "$BUILD/packetscope-tests"

echo "== Running tests =="
PACKETSCOPE_HELPER="$BUILD/packetscope-capture" "$BUILD/packetscope-tests"
echo "All test suites passed."

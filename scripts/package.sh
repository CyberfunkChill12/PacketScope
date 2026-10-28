#!/usr/bin/env bash
# Packages dist/PacketScope-macOS.zip containing "PacketScope Demo/" (app + START HERE.txt).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: packaging requires macOS (ditto/codesign)." >&2
  exit 1
fi
[[ -d "$ROOT/dist/PacketScope.app" ]] || bash "$ROOT/scripts/build.sh"

STAGE="$ROOT/build/package"
rm -rf "$STAGE" "$ROOT/dist/PacketScope-macOS.zip"
mkdir -p "$STAGE/PacketScope Demo"
ditto "$ROOT/dist/PacketScope.app" "$STAGE/PacketScope Demo/PacketScope.app"
cp "$ROOT/PacketScope/QUICKSTART.txt" "$STAGE/PacketScope Demo/START HERE.txt"
cp -R "$ROOT/samples" "$STAGE/PacketScope Demo/samples"
# No test captures, session data, caches, credentials, or logs belong in the package.
find "$STAGE" -name "*.pcap" -o -name "status.json" -o -name ".DS_Store" | xargs rm -f 2>/dev/null || true

cd "$STAGE"
ditto -c -k --sequesterRsrc --keepParent "PacketScope Demo" "$ROOT/dist/PacketScope-macOS.zip"
cd "$ROOT"

echo "== Verifying ZIP extraction, permissions, signature, architectures =="
VERIFY="$ROOT/build/verify-unzip"
rm -rf "$VERIFY"; mkdir -p "$VERIFY"
ditto -x -k "$ROOT/dist/PacketScope-macOS.zip" "$VERIFY"
test -x "$VERIFY/PacketScope Demo/PacketScope.app/Contents/MacOS/PacketScope"
test -x "$VERIFY/PacketScope Demo/PacketScope.app/Contents/Helpers/packetscope-capture"
test -f "$VERIFY/PacketScope Demo/START HERE.txt"
codesign --verify --deep --strict "$VERIFY/PacketScope Demo/PacketScope.app"
lipo -info "$VERIFY/PacketScope Demo/PacketScope.app/Contents/MacOS/PacketScope" | grep -q arm64
lipo -info "$VERIFY/PacketScope Demo/PacketScope.app/Contents/MacOS/PacketScope" | grep -q x86_64
lipo -info "$VERIFY/PacketScope Demo/PacketScope.app/Contents/Helpers/packetscope-capture" | grep -q arm64
lipo -info "$VERIFY/PacketScope Demo/PacketScope.app/Contents/Helpers/packetscope-capture" | grep -q x86_64
echo "Packaged $ROOT/dist/PacketScope-macOS.zip"

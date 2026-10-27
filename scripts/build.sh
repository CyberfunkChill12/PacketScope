#!/usr/bin/env bash
# Builds dist/PacketScope.app (universal arm64 + x86_64 UI and helper), ad hoc signed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SDK="$(xcrun --show-sdk-path)"
BUILD="$ROOT/build"
DIST="$ROOT/dist"
APP="$DIST/PacketScope.app"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: PacketScope builds only on macOS (needs SwiftUI, libpcap, and macOS SDKs)." >&2
  exit 1
fi

mkdir -p "$BUILD" "$DIST"
echo "== Compiling capture helper (arm64 + x86_64) =="
for arch in arm64 x86_64; do
  mkdir -p "$BUILD/$arch"
  clang -O2 -arch "$arch" -mmacosx-version-min=13.0 -isysroot "$SDK" \
    "$ROOT/PacketScope/Helper/capture.c" -lpcap -o "$BUILD/$arch/packetscope-capture"
done
lipo -create "$BUILD/arm64/packetscope-capture" "$BUILD/x86_64/packetscope-capture" -output "$BUILD/packetscope-capture"
chmod +x "$BUILD/packetscope-capture"

echo "== Compiling SwiftUI app (arm64 + x86_64, Swift 5 mode) =="
for arch in arm64 x86_64; do
  swiftc -swift-version 5 -O \
    -sdk "$SDK" -target "$arch-apple-macos13.0" \
    -framework SwiftUI -framework AppKit -framework Charts \
    -Xlinker -weak_framework -Xlinker FoundationModels \
    "$ROOT"/PacketScope/Sources/*.swift \
    -o "$BUILD/$arch/PacketScope"
done
lipo -create "$BUILD/arm64/PacketScope" "$BUILD/x86_64/PacketScope" -output "$BUILD/PacketScope"

echo "== App icon =="
mkdir -p "$BUILD/Resources"
swift "$ROOT/scripts/make_icon.swift" "$BUILD/Resources"

echo "== Assembling app bundle =="
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Helpers" "$APP/Contents/Resources"
cp "$BUILD/PacketScope" "$APP/Contents/MacOS/PacketScope"
cp "$BUILD/packetscope-capture" "$APP/Contents/Helpers/packetscope-capture"
cp "$ROOT/PacketScope/Resources/Info.plist" "$APP/Contents/Info.plist"
cp "$ROOT/PacketScope/Resources/public_suffix_list.dat" "$APP/Contents/Resources/public_suffix_list.dat"
cp "$BUILD/Resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
chmod +x "$APP/Contents/MacOS/PacketScope" "$APP/Contents/Helpers/packetscope-capture"

echo "== Ad hoc signing (development demo only; not Developer ID / notarization) =="
codesign --force --sign - "$APP/Contents/Helpers/packetscope-capture"
codesign --force --sign - --entitlements /dev/null "$APP" 2>/dev/null || codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"

echo "== Verifying architectures and weak linking =="
lipo -info "$APP/Contents/MacOS/PacketScope"
lipo -info "$APP/Contents/Helpers/packetscope-capture"
if otool -l "$APP/Contents/MacOS/PacketScope" | grep -A2 LC_LOAD_WEAK_DYLIB | grep -q FoundationModels; then
  echo "FoundationModels: weak-linked"
else
  echo "warning: could not confirm FoundationModels weak load command" >&2
fi
echo "Built $APP"

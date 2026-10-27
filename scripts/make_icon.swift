import AppKit

// Generates AppIcon.icns: dark navy rounded square with a teal waveform.
// Usage: swift scripts/make_icon.swift <output-dir>
let outDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."
let sizes: [(String, Int)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32), ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256), ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]
let iconset = NSTemporaryDirectory() + "PacketScope.iconset"
try? FileManager.default.removeItem(atPath: iconset)
try FileManager.default.createDirectory(atPath: iconset, withIntermediateDirectories: true)

func drawIcon(pixels: Int) -> NSImage {
    let size = NSSize(width: pixels, height: pixels)
    let img = NSImage(size: size)
    img.lockFocus()
    let s = CGFloat(pixels)
    let rect = NSRect(x: s * 0.06, y: s * 0.06, width: s * 0.88, height: s * 0.88)
    let path = NSBezierPath(roundedRect: rect, xRadius: s * 0.2, yRadius: s * 0.2)
    NSColor(srgbRed: 0.055, green: 0.078, blue: 0.115, alpha: 1).setFill()
    path.fill()
    // waveform
    let wave = NSBezierPath()
    let midY = s * 0.5
    let points: [(CGFloat, CGFloat)] = [(0.18, 0.5), (0.30, 0.5), (0.36, 0.68), (0.44, 0.30), (0.52, 0.62), (0.58, 0.5), (0.84, 0.5)]
    for (i, p) in points.enumerated() {
        let pt = NSPoint(x: s * p.0, y: s * (1 - p.1) == midY ? midY : s * p.1)
        if i == 0 { wave.move(to: pt) } else { wave.line(to: pt) }
    }
    wave.lineWidth = s * 0.045
    wave.lineCapStyle = .round
    wave.lineJoinStyle = .round
    NSColor(srgbRed: 0.280, green: 0.880, blue: 0.770, alpha: 1).setStroke()
    wave.stroke()
    img.unlockFocus()
    return img
}

for (name, px) in sizes {
    let img = drawIcon(pixels: px)
    guard let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
          let png = rep.representation(using: .png, properties: [:]) else { continue }
    try png.write(to: URL(fileURLWithPath: iconset + "/\(name).png"))
}
let task = Process()
task.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
task.arguments = ["-c", "icns", iconset, "-o", outDir + "/AppIcon.icns"]
try task.run(); task.waitUntilExit()
if task.terminationStatus != 0 { fputs("iconutil failed\n", stderr); exit(1) }
print("wrote \(outDir)/AppIcon.icns")

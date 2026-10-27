#!/usr/bin/env python3
"""Development-only localhost traffic generator for manual PacketScope tests.

Starts a throwaway HTTP server on 127.0.0.1, fetches two pages (plaintext HTTP
on loopback, which PacketScope should report as informational), and sends a
few ICMP pings. Synthetic test traffic only; never used by the app itself.
"""
import http.server
import subprocess
import threading
import urllib.request

PORT = 18099


def main() -> None:
    server = http.server.HTTPServer(("127.0.0.1", PORT), http.server.SimpleHTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for _ in range(2):
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=5) as r:
                print("HTTP", r.status, len(r.read()), "bytes")
        subprocess.run(["ping", "-c", "3", "127.0.0.1"], check=False)
    finally:
        server.shutdown()
    print("live_traffic done")


if __name__ == "__main__":
    main()

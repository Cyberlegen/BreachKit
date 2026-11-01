#!/usr/bin/env python3
"""
Minimal stand-in for the HexStrike HTTP API, used by CI and local smoke tests.

Serves GET /health with a JSON body shaped like the real server's response so
`breachkit init --check` can be exercised without cloning/installing upstream.

Usage: python tests/stub_hexstrike.py [port]   (default 8888)
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class HealthHandler(BaseHTTPRequestHandler):
    server_version = "StubHexStrike/0.0.0"

    def do_GET(self) -> None:
        if self.path.rstrip("/") not in {"", "/health"}:
            self.send_error(404, "not found")
            return
        payload = {
            "status": "healthy",
            "message": "Stub HexStrike AI Tools API Server is operational",
            "version": "6.0.0-stub",
            "tools_status": {"curl": True},
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main(argv: list[str]) -> int:
    port = int(argv[1]) if len(argv) > 1 else 8888
    server = HTTPServer(("127.0.0.1", port), HealthHandler)
    print(f"[*] stub HexStrike listening on http://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

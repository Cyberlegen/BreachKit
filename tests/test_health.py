"""
Tests for the backend health probe (BK-009 health check).
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from breachkit.health import check_local_api, collect_checks


class _Handler(BaseHTTPRequestHandler):
    status: ClassVar[int] = 200
    payload: ClassVar[dict] = {"status": "healthy", "message": "stub"}

    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        body = json.dumps(self.payload).encode()
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence test output
        return


@pytest.fixture
def stub_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_health_probe_ok(stub_server):
    check = check_local_api(stub_server)
    assert check.ok, check.detail
    assert "healthy" in check.detail


def test_health_probe_reports_http_error(stub_server):
    _Handler.status = 500
    try:
        check = check_local_api(stub_server)
    finally:
        _Handler.status = 200
    assert not check.ok
    assert "HTTP 500" in check.detail


def test_health_probe_reports_unreachable():
    # Port 9 (discard) is normally closed; point at a reserved TEST-NET address
    # instead so the probe fails fast without depending on local services.
    check = check_local_api("http://127.0.0.1:1", timeout=0.5)
    assert not check.ok
    assert "unreachable" in check.detail


def test_collect_checks_shape(stub_server):
    checks = collect_checks(stub_server)
    names = [c.name for c in checks]
    assert names == ["python", "manifest", "hexstrike-health"]
    assert all(c.ok for c in checks), [c.render() for c in checks]

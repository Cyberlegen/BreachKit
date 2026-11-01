"""
Environment and backend health checks (stdlib only).

Used by ``breachkit init --check`` and by CI, so a fresh runner can prove that
the CLI, the pinned manifest and the HexStrike backend are all usable without
downloading the 100+ MB upstream server.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from breachkit.config import ConfigError, Manifest, load_manifest

MIN_PYTHON = (3, 10)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""

    def render(self) -> str:
        mark = "ok  " if self.ok else "FAIL"
        return f"[{mark}] {self.name}: {self.detail}" if self.detail else f"[{mark}] {self.name}"


def check_python() -> Check:
    version = sys.version_info
    ok = version[:2] >= MIN_PYTHON
    return Check("python", ok, f"{version.major}.{version.minor}.{version.micro} (need >= 3.10)")


def check_manifest(path: str | Path | None = None) -> Check:
    try:
        manifest = load_manifest(path)
    except ConfigError as exc:
        return Check("manifest", False, str(exc))
    hs: Manifest = manifest
    return Check(
        "manifest",
        True,
        f"pinned {hs.hexstrike.pinned_commit[:12]}, bind {hs.hexstrike.bind_host}"
        f":{hs.hexstrike.default_port}, {len(hs.hexstrike.allowed_tools)} tools",
    )


def check_local_api(url: str, timeout: float = 3.0) -> Check:
    """Probe the HexStrike /health endpoint."""

    endpoint = url.rstrip("/") + "/health"
    request = urllib.request.Request(endpoint, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(4096).decode("utf-8", "replace")
            status = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        return Check("hexstrike-health", False, f"{endpoint} returned HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return Check("hexstrike-health", False, f"{endpoint} unreachable: {exc}")

    if status >= 400:
        return Check("hexstrike-health", False, f"{endpoint} returned HTTP {status}")

    detail = "answered"
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        state = payload.get("status") or payload.get("message")
        if state:
            detail = f"answered ({state})"
    return Check("hexstrike-health", True, f"{endpoint} {detail}")


def collect_checks(server_url: str, manifest_path: str | Path | None = None) -> list[Check]:
    return [
        check_python(),
        check_manifest(manifest_path),
        check_local_api(server_url),
    ]

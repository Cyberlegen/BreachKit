"""
Configuration loading and validation.

The HexStrike manifest is the single source of truth for which upstream commit
BreachKit talks to, where it binds, and which tools are exposed. It is validated
on load so a typo (or a floating branch instead of a pinned commit) fails the
build instead of silently changing the attack surface of a run.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "manifest.yaml"

# Loopback only: the server must never be reachable from another host (BK-201).
ALLOWED_BIND_HOSTS = {"127.0.0.1", "::1", "localhost"}

COMMIT_RE = r"^[0-9a-f]{40}$"
TOOL_RE = r"^[a-z0-9][a-z0-9._+-]*$"


class ConfigError(ValueError):
    """Raised when a configuration file is missing, malformed or unsafe."""


class HexStrikeConfig(BaseModel):
    """Validated ``hexstrike:`` section of manifest.yaml."""

    pinned_commit: str = Field(pattern=COMMIT_RE)
    repo_url: str
    bind_host: str = "127.0.0.1"
    default_port: int = Field(ge=1, le=65535)
    allowed_tools: list[str]

    @field_validator("repo_url")
    @classmethod
    def _repo_url_is_https(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("repo_url must use https://")
        if re.search(r"\s", value):
            raise ValueError("repo_url must not contain whitespace")
        return value

    @field_validator("bind_host")
    @classmethod
    def _bind_host_is_loopback(cls, value: str) -> str:
        if value not in ALLOWED_BIND_HOSTS:
            raise ValueError(
                f"bind_host must be loopback ({', '.join(sorted(ALLOWED_BIND_HOSTS))}), got {value!r}"
            )
        if value not in {"localhost", "::1"}:
            ipaddress.ip_address(value)
        return value

    @field_validator("allowed_tools")
    @classmethod
    def _tools_are_slugs(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("allowed_tools must not be empty")
        if len(set(value)) != len(value):
            raise ValueError("allowed_tools contains duplicates")
        for tool in value:
            if not re.match(TOOL_RE, tool):
                raise ValueError(f"invalid tool name: {tool!r}")
        return value


class Manifest(BaseModel):
    """Top-level manifest.yaml document."""

    hexstrike: HexStrikeConfig


def load_manifest(path: str | Path | None = None) -> Manifest:
    """Load and validate a manifest file, raising ConfigError on any problem."""

    target = Path(path) if path is not None else DEFAULT_MANIFEST
    if not target.is_file():
        raise ConfigError(f"manifest not found: {target}")

    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover - exercised via CLI message
        raise ConfigError(f"manifest is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict) or "hexstrike" not in raw:
        raise ConfigError(f"manifest is missing the required 'hexstrike' section: {target}")

    try:
        return Manifest(**raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise ConfigError(f"invalid manifest {target}: {problems}") from exc


def describe_manifest(manifest: Manifest) -> list[str]:
    """Human readable summary used by the CLI and CI logs."""

    hs = manifest.hexstrike
    return [
        f"pinned_commit: {hs.pinned_commit}",
        f"repo_url: {hs.repo_url}",
        f"bind_host: {hs.bind_host}",
        f"default_port: {hs.default_port}",
        f"allowed_tools ({len(hs.allowed_tools)}): {', '.join(hs.allowed_tools)}",
    ]

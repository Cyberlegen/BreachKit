"""
Tests for manifest validation (BK-009 config validation).
"""

import textwrap

import pytest

from breachkit.config import ConfigError, load_manifest
from breachkit.health import check_manifest, check_python

VALID = """
hexstrike:
  pinned_commit: "d689933ff579d839c676c82b231f8e98326c5f04"
  repo_url: "https://github.com/0x4m4/hexstrike-ai.git"
  bind_host: "127.0.0.1"
  default_port: 8888
  allowed_tools:
    - httpx
    - sqlmap
"""


def write_manifest(tmp_path, body: str):
    path = tmp_path / "manifest.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def test_repo_manifest_is_valid():
    manifest = load_manifest()
    assert len(manifest.hexstrike.pinned_commit) == 40
    assert manifest.hexstrike.bind_host in {"127.0.0.1", "::1", "localhost"}
    assert manifest.hexstrike.allowed_tools


def test_valid_manifest_loads(tmp_path):
    manifest = load_manifest(write_manifest(tmp_path, VALID))
    assert manifest.hexstrike.default_port == 8888
    assert manifest.hexstrike.allowed_tools == ["httpx", "sqlmap"]


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_manifest(tmp_path / "nope.yaml")


def test_unpinned_commit_is_rejected(tmp_path):
    body = VALID.replace("d689933ff579d839c676c82b231f8e98326c5f04", "master")
    with pytest.raises(ConfigError, match="pinned_commit"):
        load_manifest(write_manifest(tmp_path, body))


def test_short_commit_is_rejected(tmp_path):
    body = VALID.replace("d689933ff579d839c676c82b231f8e98326c5f04", "4a2b9f3e1892a01d")
    with pytest.raises(ConfigError, match="pinned_commit"):
        load_manifest(write_manifest(tmp_path, body))


def test_public_bind_host_is_rejected(tmp_path):
    body = VALID.replace('bind_host: "127.0.0.1"', 'bind_host: "0.0.0.0"')
    with pytest.raises(ConfigError, match="bind_host"):
        load_manifest(write_manifest(tmp_path, body))


def test_plain_http_repo_is_rejected(tmp_path):
    body = VALID.replace("repo_url: \"https://", "repo_url: \"http://")
    with pytest.raises(ConfigError, match="repo_url"):
        load_manifest(write_manifest(tmp_path, body))


def test_empty_tool_list_is_rejected(tmp_path):
    body = """
    hexstrike:
      pinned_commit: "d689933ff579d839c676c82b231f8e98326c5f04"
      repo_url: "https://github.com/0x4m4/hexstrike-ai.git"
      bind_host: "127.0.0.1"
      default_port: 8888
      allowed_tools: []
    """
    with pytest.raises(ConfigError, match="allowed_tools"):
        load_manifest(write_manifest(tmp_path, body))


def test_missing_hexstrike_section_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="hexstrike"):
        load_manifest(write_manifest(tmp_path, "other: 1\n"))


def test_health_checks_report_manifest_and_python(tmp_path):
    assert check_python().ok
    assert check_manifest(write_manifest(tmp_path, VALID)).ok
    bad = write_manifest(tmp_path, VALID.replace("8888", "99999"))
    assert not check_manifest(bad).ok

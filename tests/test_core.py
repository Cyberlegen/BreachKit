"""
Unit tests for BreachKit Policy Engine, State Machine, and Evidence Store.
"""

import pytest
import os
import shutil
from breachkit.policy.engine import EngagementScope, ScopeTarget, PolicyEngine, ApprovalRecord
from breachkit.orchestrator.state import Job, JobManager
from breachkit.evidence.store import EvidenceStore, redact_text


def test_scope_enforcement():
    target = ScopeTarget(host="0a1b00ff.web-security-academy.net")
    scope = EngagementScope(
        engagement="test-lab",
        authorisation_ref="ref-123",
        targets=[target],
        exclude=["*.amazonaws.com"]
    )
    engine = PolicyEngine(scope)

    # In scope
    assert engine.assert_in_scope("https://0a1b00ff.web-security-academy.net/filter?category=Gifts") == True

    # Out of scope (not in target)
    with pytest.raises(ValueError):
        engine.assert_in_scope("https://evil.com/path")

    # Out of scope (matches exclusion)
    with pytest.raises(ValueError):
        engine.assert_in_scope("https://s3.amazonaws.com/bucket")


def test_kill_switch():
    target = ScopeTarget(host="example.com")
    scope = EngagementScope(engagement="test", authorisation_ref="ref", targets=[target])
    engine = PolicyEngine(scope, kill_switch_active=True)

    with pytest.raises(PermissionError):
        engine.assert_in_scope("https://example.com")


def test_approval_matrix():
    target = ScopeTarget(host="example.com")
    scope = EngagementScope(engagement="test", authorisation_ref="ref", targets=[target])
    engine = PolicyEngine(scope)

    # Passive needs no approval
    assert engine.assert_approved("passive", "https://example.com", "httpx") == True

    # Intrusive without approval should raise error
    with pytest.raises(PermissionError):
        engine.assert_approved("intrusive", "https://example.com", "sqlmap")

    # Record approval and test again
    app = ApprovalRecord(
        id="apr-01",
        job_id="job-1",
        action_class="intrusive",
        target="https://example.com",
        tool="sqlmap",
        argument_summary="test",
        risk="intrusive"
    )
    engine.record_approval(app)
    assert engine.assert_approved("intrusive", "https://example.com", "sqlmap") == True


def test_state_machine():
    job = Job(id="job-2026-10-25-001", engagement="lab", target_host="example.com", state="init")
    assert job.state == "init"

    job.transition_to("scoped")
    assert job.state == "scoped"

    job.transition_to("recon")
    assert job.state == "recon"

    # Invalid transition
    with pytest.raises(ValueError):
        job.transition_to("reporting")


def test_write_time_redaction():
    raw_text = "GET / HTTP/1.1\r\nAuthorization: Bearer secret_token_123\r\nX-Api-Key: my_api_key_abc\r\nCookie: session=secret_cookie_val\r\n"
    redacted = redact_text(raw_text)

    assert "secret_token_123" not in redacted
    assert "REDACTED_AUTH" in redacted
    assert "my_api_key_abc" not in redacted
    assert "REDACTED_KEY" in redacted
    assert "secret_cookie_val" not in redacted
    assert "REDACTED_VALUE" in redacted

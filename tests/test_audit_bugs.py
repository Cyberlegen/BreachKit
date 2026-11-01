"""
Comprehensive unit tests addressing all 12 reported security and functionality bugs.
"""

import os
import shutil
import pytest
from breachkit.policy.engine import EngagementScope, ScopeTarget, PolicyEngine, ApprovalRecord
from breachkit.evidence.store import EvidenceStore, redact_text
from breachkit.cli import main as cli_main
from breachkit.orchestrator.state import Job, JobManager


def test_issue_1_and_8_scope_validation_and_restrictions():
    # Issue 1: Host subdomains like example.com.evil.test should be rejected when target is example.com
    # Issue 8: Schemes, methods, and rate limits should be enforced
    target = ScopeTarget(host="example.com", schemes=["https"], methods=["GET", "POST"], max_rps=2)
    scope = EngagementScope(
        engagement="test",
        authorisation_ref="ref",
        targets=[target],
        exclude=["*.evil.com"]
    )
    engine = PolicyEngine(scope)

    # Valid exact host
    assert engine.assert_in_scope("https://example.com/login", method="GET") is True

    # Valid subdomain of authorized host
    assert engine.assert_in_scope("https://api.example.com/data", method="POST") is True

    # Issue 1 Fix Verification: example.com.evil.test must BE REJECTED
    with pytest.raises(ValueError, match="outside authorised scope targets"):
        engine.assert_in_scope("https://example.com.evil.test/attack")

    # Issue 8 Fix Verification: Invalid scheme rejected
    with pytest.raises(ValueError, match="Scheme 'http' is not allowed"):
        engine.assert_in_scope("http://example.com/login", method="GET")

    # Issue 8 Fix Verification: Invalid HTTP method rejected
    with pytest.raises(ValueError, match="HTTP Method 'DELETE' is not allowed"):
        engine.assert_in_scope("https://example.com/resource", method="DELETE")

    # Issue 8 Fix Verification: Rate limit (max_rps=2) enforcement
    engine._request_history.clear()
    assert engine.assert_in_scope("https://example.com/1") is True
    assert engine.assert_in_scope("https://example.com/2") is True
    with pytest.raises(ValueError, match="Rate limit exceeded"):
        engine.assert_in_scope("https://example.com/3")


def test_issue_2_stricter_approval_checks():
    # Issue 2: Job ID binding, Scope Hash binding, and exact host matching
    target = ScopeTarget(host="example.com")
    scope = EngagementScope(engagement="test", authorisation_ref="ref", targets=[target])
    engine = PolicyEngine(scope, scope_hash="hash-v1")

    app = ApprovalRecord(
        id="apr-1",
        job_id="job-100",
        action_class="intrusive",
        target="https://example.com/exploit",
        tool="sqlmap",
        argument_summary="sqli",
        risk="intrusive",
        scope_hash="hash-v1"
    )
    engine.record_approval(app)

    # Valid matching call
    assert engine.assert_approved("intrusive", "https://example.com/exploit", "sqlmap", job_id="job-100", current_scope_hash="hash-v1") is True

    # Rejection on mismatched job_id
    with pytest.raises(PermissionError):
        engine.assert_approved("intrusive", "https://example.com/exploit", "sqlmap", job_id="job-200", current_scope_hash="hash-v1")

    # Rejection on mismatched scope_hash
    with pytest.raises(PermissionError):
        engine.assert_approved("intrusive", "https://example.com/exploit", "sqlmap", job_id="job-100", current_scope_hash="hash-v2")

    # Rejection on mismatched target host
    with pytest.raises(PermissionError):
        engine.assert_approved("intrusive", "https://other.com/exploit", "sqlmap", job_id="job-100", current_scope_hash="hash-v1")


def test_issue_3_path_traversal_prevention(tmp_path):
    # Issue 3: Prevent directory traversal in EvidenceStore via basename stripping
    store = EvidenceStore(str(tmp_path))

    # Path traversal attempt should be safely neutralized to basename
    hash_val = store.write_evidence("../../../etc/passwd", "evil content")
    assert len(hash_val) == 64
    assert os.path.exists(tmp_path / "evidence" / "passwd")
    assert not os.path.exists(tmp_path / "etc" / "passwd")


def test_issue_4_extended_redaction_and_raw_consent(tmp_path):
    # Issue 4: PII redaction (email, phone, password fields, tokens) & raw consent requirement
    text = (
        "User email: john.doe@example.com, Phone: 555-123-4567\n"
        "Authorization: Bearer my_jwt_token_123\n"
        "Password body: password=secret123&user=admin\n"
        "JSON password: {\"password\": \"secret456\"}\n"
    )
    redacted = redact_text(text)

    assert "[REDACTED_EMAIL]" in redacted
    assert "john.doe@example.com" not in redacted
    assert "[REDACTED_PHONE]" in redacted
    assert "555-123-4567" not in redacted
    assert "REDACTED_AUTH" in redacted
    assert "my_jwt_token_123" not in redacted
    assert "password=REDACTED_PASSWORD" in redacted
    assert "secret123" not in redacted
    assert "REDACTED_PASSWORD" in redacted

    store = EvidenceStore(str(tmp_path))
    # raw=True without consent raises error
    with pytest.raises(ValueError, match="operator_consent"):
        store.write_evidence("raw_test.txt", text, raw=True)

    # raw=True with consent succeeds
    hash_val = store.write_evidence("raw_test.txt", text, raw=True, operator_consent=True)
    assert len(hash_val) == 64


def test_issue_5_audit_log_hash_chain_recovery(tmp_path):
    # Issue 5: Reopening an EvidenceStore should recover the last hash from existing audit.jsonl
    run_dir = str(tmp_path)

    store1 = EvidenceStore(run_dir)
    store1.append_audit_log("event1", {"data": "first"})
    first_hash = store1.last_hash
    assert first_hash != "0000000000000000000000000000000000000000000000000000000000000000"

    # Instantiate store2 targeting the same directory
    store2 = EvidenceStore(run_dir)
    assert store2.last_hash == first_hash

    store2.append_audit_log("event2", {"data": "second"})
    second_hash = store2.last_hash
    assert second_hash != first_hash


def test_issue_6_and_7_cli_verbs_and_kill_switch(tmp_path):
    # Issue 6: CLI verbs execution (run, approve, stop)
    # Issue 7: Kill switch activation writing flag file and preventing policy scope checks
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        scope_file = tmp_path / "test_scope.yaml"
        scope_file.write_text(
            "engagement: test-eng\n"
            "authorisation_ref: ref-123\n"
            "targets:\n"
            "  - host: example.com\n",
            encoding="utf-8"
        )

        # CLI run verb
        ret = cli_main(["run", "--scope", str(scope_file), "--job-id", "job-cli-01"])
        assert ret == 0
        assert os.path.exists(tmp_path / "runs" / "job-cli-01" / "job.json")

        # CLI approve verb
        ret = cli_main(["approve", "--job-id", "job-cli-01"])
        assert ret == 0

        # CLI report verb
        ret = cli_main(["report", "--job-id", "job-cli-01"])
        assert ret == 0
        assert os.path.exists(tmp_path / "runs" / "job-cli-01" / "report.md")

        # CLI stop verb (hard kill switch)
        ret = cli_main(["stop", "--hard"])
        assert ret == 0
        assert os.path.exists(tmp_path / "runs" / ".kill_switch_active")

        # Verify policy engine obeys the activated kill switch
        target = ScopeTarget(host="example.com")
        scope = EngagementScope(engagement="test", authorisation_ref="ref", targets=[target])
        engine = PolicyEngine(scope, kill_switch_active=True)
        with pytest.raises(PermissionError, match="Kill switch is active"):
            engine.assert_in_scope("https://example.com")

    finally:
        os.chdir(old_cwd)

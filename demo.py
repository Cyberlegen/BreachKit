#!/usr/bin/env python3
"""
BreachKit Interactive Demo
Demonstrates scope enforcement, HITL approval gates, secure execution, and evidence redaction.
"""

import sys
import time
from breachkit.policy.engine import EngagementScope, ScopeTarget, PolicyEngine, ApprovalRecord
from breachkit.orchestrator.state import Job, JobManager
from breachkit.evidence.store import EvidenceStore, redact_text

def print_banner():
    print("=" * 60)
    print("         BREACHKIT INTERACTIVE DEMO PIPELINE          ")
    print("=" * 60)
    print()

def simulate_step(title, delay=0.8):
    print(f"[*] {title}...")
    time.sleep(delay)

def main():
    print_banner()

    # 1. Scope Setup
    simulate_step("Initializing Engagement Scope for PortSwigger Lab")
    target = ScopeTarget(host="0a1b00ff.web-security-academy.net", schemes=["https"], methods=["GET", "POST"], max_rps=5)
    scope = EngagementScope(
        engagement="lab-sqli-001",
        authorisation_ref="PS-academy-2026-10-25",
        targets=[target],
        exclude=["*.amazonaws.com"]
    )
    engine = PolicyEngine(scope)
    print(f" [+] Target locked: {target.host}")
    print(f" [+] Authorisation Ref: {scope.authorisation_ref}")
    print()

    # 2. State Machine & Job Initialization
    simulate_step("Spinning up Orchestrator State Machine")
    manager = JobManager(runs_dir="runs")
    job = Job(id="job-demo-001", engagement="lab-sqli-001", target_host=target.host, state="init")
    manager.save_job(job)
    print(f" [+] Job {job.id} created in state: [{job.state}]")

    job.transition_to("scoped")
    manager.save_job(job)
    print(f" [+] State transitioned to: [{job.state}]")
    print()

    # 3. Policy Enforcement Demonstration (In-scope vs Out-of-scope)
    simulate_step("Testing Scope Policy Enforcement")
    in_scope_url = "https://0a1b00ff.web-security-academy.net/filter?category=Gifts"
    out_of_scope_url = "https://evil-unauthorized-target.com/admin"

    print(f" > Testing in-scope URL: {in_scope_url}")
    try:
        engine.assert_in_scope(in_scope_url)
        print("   [+] ALLOWED by Policy Engine.")
    except Exception as e:
        print(f"   [x] BLOCKED: {e}")

    print(f" > Testing out-of-scope URL: {out_of_scope_url}")
    try:
        engine.assert_in_scope(out_of_scope_url)
        print("   [+] ALLOWED")
    except Exception as e:
        print(f"   [x] BLOCKED correctly by Policy Engine: {e}")
    print()

    # 4. Human-in-the-Loop (HITL) Approval Gate Demonstration
    simulate_step("Demonstrating HITL Approval Gate for Intrusive Action")
    print(" > Attempting intrusive tool 'sqlmap' without approval...")
    try:
        engine.assert_approved("intrusive", in_scope_url, "sqlmap")
    except PermissionError as pe:
        print(f"   [x] REJECTED: {pe}")

    print(" > Granting HITL Approval record for intrusive action...")
    approval = ApprovalRecord(
        id="apr-demo-01",
        job_id=job.id,
        action_class="intrusive",
        target=in_scope_url,
        tool="sqlmap",
        argument_summary="boolean-blind on category",
        risk="intrusive",
        approved_by="operator"
    )
    engine.record_approval(approval)
    print(f"   [+] Approval recorded: {approval.id} (Class: {approval.action_class}, Tool: {approval.tool})")

    if engine.assert_approved("intrusive", in_scope_url, "sqlmap"):
        print("   [+] Action now APPROVED and cleared for dispatch.")
    print()

    # 5. Evidence Store & Write-Time Redaction Demonstration
    simulate_step("Capturing Evidence & Applying Write-Time Redaction")
    store = EvidenceStore(run_dir=f"runs/{job.id}")
    
    raw_response = (
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: session=super_secret_session_token_xyz999; Secure\r\n"
        "Authorization: Bearer secret_jwt_token_abcdef123456\r\n"
        "X-Api-Key: sample_key_placeholder\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html><body>Product catalog loaded successfully.</html></body>"
    )

    print(" > Raw response captured containing sensitive tokens & cookies.")
    redacted_response = redact_text(raw_response)
    print(" > Redacted response (written to disk):")
    for line in redacted_response.split("\r\n"):
        print(f"   {line}")

    art_hash = store.write_evidence("0001-response.http", raw_response)
    print(f" [+] Evidence stored securely. SHA-256 Hash: {art_hash}")
    print(f" [+] Audit log updated with hash chain entry.")
    print()

    # 6. Finalizing
    job.transition_to("recon")
    job.transition_to("discovery")
    job.transition_to("triage")
    manager.save_job(job)
    print("=" * 60)
    print(f" [+] Demo completed successfully! Job state: [{job.state}]")
    print(f" [+] Run artifact bundle preserved under: runs/{job.id}/")
    print("=" * 60)

if __name__ == "__main__":
    main()

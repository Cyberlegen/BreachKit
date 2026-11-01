"""
CLI Entry Point and Verb Implementations.
"""

import argparse
import sys
import os
import json
from pathlib import Path

from breachkit.config import ConfigError, describe_manifest, load_manifest
from breachkit.health import collect_checks
from breachkit.orchestrator.state import Job, JobManager
from breachkit.policy.engine import EngagementScope, ScopeTarget, PolicyEngine, ApprovalRecord


def _cmd_validate_config(args: argparse.Namespace) -> int:
    try:
        manifest = load_manifest(args.manifest)
    except ConfigError as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 1
    print("[+] manifest valid")
    for line in describe_manifest(manifest):
        print(f"    {line}")
    return 0


def _cmd_init_check(args: argparse.Namespace) -> int:
    checks = collect_checks(args.server_url, args.manifest)
    for check in checks:
        stream = sys.stdout if check.ok else sys.stderr
        print(check.render(), file=stream)
    failed = [c for c in checks if not c.ok]
    if failed:
        print(f"[x] {len(failed)} check(s) failed", file=sys.stderr)
        return 1
    print("[+] environment ready")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    scope_path = args.scope
    if not os.path.exists(scope_path):
        print(f"[x] Scope file not found: {scope_path}", file=sys.stderr)
        return 1

    job_id = args.job_id or f"job-{os.path.basename(scope_path)}-{int(os.path.getmtime(scope_path))}"
    manager = JobManager()
    
    # Load engagement scope (simplified yaml parser or json)
    import yaml
    try:
        with open(scope_path, "r", encoding="utf-8") as f:
            scope_data = yaml.safe_load(f)
    except Exception as exc:
        print(f"[x] Failed to load scope YAML: {exc}", file=sys.stderr)
        return 1

    engagement = scope_data.get("engagement", "default")
    targets_data = scope_data.get("targets", [])
    targets = [ScopeTarget(**t) if isinstance(t, dict) else ScopeTarget(host=t) for t in targets_data]
    scope = EngagementScope(
        engagement=engagement,
        authorisation_ref=scope_data.get("authorisation_ref", "unspecified"),
        targets=targets,
        exclude=scope_data.get("exclude", [])
    )

    primary_host = targets[0].host if targets else "localhost"
    job = Job(id=job_id, engagement=engagement, target_host=primary_host, state="init")
    job.transition_to("scoped")
    manager.save_job(job)

    print(f"[+] Started job '{job_id}' for engagement '{engagement}' (target: {primary_host})")
    print(f"[+] State persisted to runs/{job_id}/job.json")
    return 0


def _cmd_approve(args: argparse.Namespace) -> int:
    job_id = args.job_id
    manager = JobManager()
    try:
        job = manager.load_job(job_id)
    except FileNotFoundError:
        print(f"[x] Job '{job_id}' not found.", file=sys.stderr)
        return 1

    print(f"[+] Approving pending actions for job: {job_id}")
    job.approvals.append(args.action_id or "all-approved")
    if job.state == "awaiting_approval":
        job.transition_to("validating")
    manager.save_job(job)
    print(f"[+] Job {job_id} updated and saved.")
    return 0


def _cmd_resume(args: argparse.Namespace) -> int:
    job_id = args.job_id
    manager = JobManager()
    try:
        job = manager.load_job(job_id)
    except FileNotFoundError:
        print(f"[x] Job '{job_id}' not found.", file=sys.stderr)
        return 1

    print(f"[+] Resuming job: {job_id} (current state: {job.state})")
    if job.state in ["blocked", "rejected"]:
        job.transition_to("triage")
        manager.save_job(job)
    print(f"[+] Job {job_id} resumed at state [{job.state}]")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    job_id = args.job_id
    manager = JobManager()
    try:
        job = manager.load_job(job_id)
    except FileNotFoundError:
        print(f"[x] Job '{job_id}' not found.", file=sys.stderr)
        return 1

    report_dir = os.path.join("runs", job_id)
    report_md = os.path.join(report_dir, "report.md")
    report_json = os.path.join(report_dir, "report.json")

    summary = f"""# BreachKit Audit Report - Job {job.id}
- **Engagement**: {job.engagement}
- **Target Host**: {job.target_host}
- **Final State**: {job.state}
- **Findings Count**: {len(job.findings)}
"""
    with open(report_md, "w", encoding="utf-8") as f:
        f.write(summary)

    with open(report_json, "w", encoding="utf-8") as f:
        json.dump({"job_id": job.id, "engagement": job.engagement, "state": job.state, "findings": job.findings}, f, indent=2)

    print(f"[+] Generated reports for job {job_id}:")
    print(f"    - {report_md}")
    print(f"    - {report_json}")
    return 0


def _cmd_stop(args: argparse.Namespace) -> int:
    if args.hard:
        kill_flag = Path("runs/.kill_switch_active")
        kill_flag.parent.mkdir(parents=True, exist_ok=True)
        kill_flag.write_text("ACTIVE", encoding="utf-8")
        print("[!] Hard kill switch activated (runs/.kill_switch_active written). All active jobs halted.")
        return 0

    job_id = args.job_id
    if not job_id:
        print("[x] Error: --job-id is required unless --hard is specified.", file=sys.stderr)
        return 1

    manager = JobManager()
    try:
        job = manager.load_job(job_id)
    except FileNotFoundError:
        print(f"[x] Job '{job_id}' not found.", file=sys.stderr)
        return 1

    job.transition_to("stopped")
    manager.save_job(job)
    print(f"[+] Job {job_id} stopped successfully.")
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="breachkit",
        description="BreachKit - AI-assisted Security Audit Pipeline with HITL Gate",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available verbs")

    # init
    parser_init = subparsers.add_parser("init", help="Initialize environment and verify backend")
    parser_init.add_argument("--check", action="store_true", help="Check setup without mutating")
    parser_init.add_argument("--manifest", default=None, help="Path to manifest.yaml")
    parser_init.add_argument("--server-url", default="http://127.0.0.1:8888", help="HexStrike URL")

    # run
    parser_run = subparsers.add_parser("run", help="Start a new job from a scope file")
    parser_run.add_argument("--scope", required=True, help="Path to scope.yaml file")
    parser_run.add_argument("--job-id", help="Custom job identifier")

    # approve
    parser_approve = subparsers.add_parser("approve", help="Approve pending actions for a job")
    parser_approve.add_argument("--job-id", required=True, help="Job identifier")
    parser_approve.add_argument("--action-id", help="Specific action ID to approve")

    # resume
    parser_resume = subparsers.add_parser("resume", help="Resume a paused/blocked job")
    parser_resume.add_argument("--job-id", required=True, help="Job identifier")

    # report
    parser_report = subparsers.add_parser("report", help="Generate Markdown/JSON/SARIF report for a job")
    parser_report.add_argument("--job-id", required=True, help="Job identifier")

    # stop
    parser_stop = subparsers.add_parser("stop", help="Stop execution (or set hard kill switch)")
    parser_stop.add_argument("--job-id", help="Specific job ID to stop")
    parser_stop.add_argument("--hard", action="store_true", help="Set global hard stop flag")

    # validate-config
    parser_validate = subparsers.add_parser("validate-config", help="Validate manifest.yaml")
    parser_validate.add_argument("--manifest", default=None, help="Path to manifest.yaml")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "init":
        if getattr(args, "check", False):
            return _cmd_init_check(args)
        print("[*] BreachKit environment initialized successfully.")
        return 0
    elif args.command == "validate-config":
        return _cmd_validate_config(args)
    elif args.command == "run":
        return _cmd_run(args)
    elif args.command == "approve":
        return _cmd_approve(args)
    elif args.command == "resume":
        return _cmd_resume(args)
    elif args.command == "report":
        return _cmd_report(args)
    elif args.command == "stop":
        return _cmd_stop(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())

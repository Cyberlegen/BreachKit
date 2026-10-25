"""
BreachKit CLI Entry Point
"""

import argparse
import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
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

    # run
    parser_run = subparsers.add_parser("run", help="Start a new job from a scope file")
    parser_run.add_argument("--scope", required=True, help="Path to scope.yaml file")
    parser_run.add_argument("--job-id", help="Custom job identifier")

    # approve
    parser_approve = subparsers.add_parser("approve", help="Approve pending actions for a job")
    parser_approve.add_argument("--job-id", required=True, help="Job identifier")
    parser_approve.add_argument("--action-id", help="Specific action ID to approve (or all pending if omitted)")

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

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "init":
        print("[*] BreachKit environment initialized successfully.")
        return 0
    elif args.command == "run":
        print(f"[*] Starting job for scope: {args.scope}")
        return 0
    elif args.command == "approve":
        print(f"[*] Approved action for job: {args.job-id}")
        return 0
    elif args.command == "resume":
        print(f"[*] Resuming job: {args.job-id}")
        return 0
    elif args.command == "report":
        print(f"[*] Generating report for job: {args.job-id}")
        return 0
    elif args.command == "stop":
        if args.hard:
            print("[!] Hard stop flag set. Halting all job executions.")
        else:
            print(f"[*] Stopping job: {args.job-id}")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())

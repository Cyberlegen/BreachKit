"""
State machine and crash-safe job persistence.
"""

import os
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Literal

JobState = Literal[
    "init", "scoped", "recon", "discovery", "triage",
    "awaiting_approval", "validating", "validated", "reporting", "done",
    "rejected", "blocked", "failed", "stopped"
]

VALID_TRANSITIONS = {
    "init": ["scoped", "failed", "stopped"],
    "scoped": ["recon", "failed", "stopped"],
    "recon": ["discovery", "failed", "stopped"],
    "discovery": ["triage", "failed", "stopped"],
    "triage": ["awaiting_approval", "validating", "failed", "stopped"],
    "awaiting_approval": ["validating", "rejected", "blocked", "stopped"],
    "validating": ["validated", "triage", "failed", "stopped"],
    "validated": ["reporting", "failed", "stopped"],
    "reporting": ["done", "failed", "stopped"],
    "blocked": ["triage", "awaiting_approval", "stopped"],
    "rejected": ["triage", "stopped"],
}


@dataclass
class Job:
    id: str
    engagement: str
    target_host: str
    state: JobState = "init"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: List[str] = field(default_factory=list)
    approvals: List[str] = field(default_factory=list)

    def transition_to(self, new_state: JobState) -> None:
        if new_state in ["failed", "stopped"]:
            self.state = new_state
            self.updated_at = datetime.now(timezone.utc).isoformat()
            return

        allowed = VALID_TRANSITIONS.get(self.state, [])
        if new_state not in allowed:
            raise ValueError(f"Invalid state transition from '{self.state}' to '{new_state}'")
        self.state = new_state
        self.updated_at = datetime.now(timezone.utc).isoformat()


class JobManager:
    def __init__(self, runs_dir: str = "runs"):
        self.runs_dir = runs_dir
        os.makedirs(self.runs_dir, exist_ok=True)

    def save_job(self, job: Job) -> str:
        job_dir = os.path.join(self.runs_dir, job.id)
        os.makedirs(job_dir, exist_ok=True)
        job_file = os.path.join(job_dir, "job.json")
        with open(job_file, "w", encoding="utf-8") as f:
            json.dump(asdict(job), f, indent=2)
        return job_file

    def load_job(self, job_id: str) -> Job:
        job_file = os.path.join(self.runs_dir, job_id, "job.json")
        if not os.path.exists(job_file):
            raise FileNotFoundError(f"Job file for '{job_id}' not found.")
        with open(job_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return Job(**data)

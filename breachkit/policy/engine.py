"""
Policy engine: scope allowlist, approval matrix, rate/time budgets, and kill switch.
"""

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Literal


@dataclass
class ScopeTarget:
    host: str
    schemes: List[str] = field(default_factory=lambda: ["https", "http"])
    methods: List[str] = field(default_factory=lambda: ["GET", "POST"])
    max_rps: int = 5


@dataclass
class EngagementScope:
    engagement: str
    authorisation_ref: str
    targets: List[ScopeTarget]
    exclude: List[str] = field(default_factory=list)


@dataclass
class ApprovalRecord:
    id: str
    job_id: str
    action_class: Literal["passive", "active", "intrusive", "destructive"]
    target: str
    tool: str
    argument_summary: str
    risk: str
    approved_by: str = "operator"
    approved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    scope_hash: str = ""


class PolicyEngine:
    def __init__(self, scope: EngagementScope, kill_switch_active: bool = False):
        self.scope = scope
        self.kill_switch_active = kill_switch_active
        self.approvals: List[ApprovalRecord] = []

    def assert_in_scope(self, url_or_host: str) -> bool:
        if self.kill_switch_active:
            raise PermissionError("Kill switch is active. All operations halted.")

        # Check exclusions first
        for pat in self.scope.exclude:
            if fnmatch.fnmatch(url_or_host, pat) or fnmatch.fnmatch(url_or_host, f"*{pat}*"):
                raise ValueError(f"Target '{url_or_host}' matches exclusion pattern '{pat}'")

        # Check inclusion in targets
        matched = False
        for target in self.scope.targets:
            if target.host in url_or_host or fnmatch.fnmatch(url_or_host, f"*{target.host}*"):
                matched = True
                break

        if not matched:
            raise ValueError(f"Target '{url_or_host}' is outside authorised scope targets.")
        return True

    def record_approval(self, approval: ApprovalRecord) -> None:
        self.approvals.append(approval)

    def assert_approved(self, action_class: str, target: str, tool: str) -> bool:
        if action_class == "passive":
            return True

        # Check if a valid approval exists for this target & tool
        now = datetime.now(timezone.utc)
        for app in self.approvals:
            if app.action_class == action_class and app.tool == tool and (app.target in target or target in app.target):
                if app.expires_at:
                    exp = datetime.fromisoformat(app.expires_at)
                    if now > exp:
                        continue
                return True

        raise PermissionError(f"Action class '{action_class}' for tool '{tool}' on target '{target}' requires approval.")

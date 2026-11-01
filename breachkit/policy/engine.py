"""
Policy engine: scope allowlist, approval matrix, rate/time budgets, and kill switch.
"""

import fnmatch
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal, Optional
from urllib.parse import urlparse


@dataclass
class ScopeTarget:
    host: str
    schemes: list[str] = field(default_factory=lambda: ["https", "http"])
    methods: list[str] = field(default_factory=lambda: ["GET", "POST"])
    max_rps: int = 5


@dataclass
class EngagementScope:
    engagement: str
    authorisation_ref: str
    targets: list[ScopeTarget]
    exclude: list[str] = field(default_factory=list)


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
    def __init__(self, scope: EngagementScope, kill_switch_active: bool = False, scope_hash: str = ""):
        self.scope = scope
        self.kill_switch_active = kill_switch_active
        self.scope_hash = scope_hash
        self.approvals: list[ApprovalRecord] = []
        self._request_history: dict[str, list[float]] = {}

    def _parse_url_or_host(self, target_str: str) -> tuple[str, str, str]:
        """Extract scheme, hostname, and path from URL or host string."""
        if "://" not in target_str:
            # Bare hostname or host:port
            target_url = "https://" + target_str
        else:
            target_url = target_str

        parsed = urlparse(target_url)
        scheme = parsed.scheme.lower() if parsed.scheme else "https"
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        path = parsed.path or "/"
        return scheme, hostname, path

    def assert_in_scope(self, url_or_host: str, method: str = "GET") -> bool:
        if self.kill_switch_active:
            raise PermissionError("Kill switch is active. All operations halted.")

        scheme, hostname, _ = self._parse_url_or_host(url_or_host)
        if not hostname:
            raise ValueError(f"Invalid target URL or host string: '{url_or_host}'")

        # 1. Check exclusions (exact domain match or subdomain match)
        for pat in self.scope.exclude:
            pat_clean = pat.lower()
            if fnmatch.fnmatch(hostname, pat_clean) or fnmatch.fnmatch(url_or_host.lower(), pat_clean):
                raise ValueError(f"Target '{url_or_host}' matches exclusion pattern '{pat}'")

        # 2. Check targets
        matched_target: Optional[ScopeTarget] = None
        for t in self.scope.targets:
            thost = t.host.lower()
            # Exact hostname match or valid subdomain match (e.g. sub.example.com matching target example.com)
            if hostname == thost or hostname.endswith("." + thost):
                matched_target = t
                break

        if not matched_target:
            raise ValueError(f"Host '{hostname}' is outside authorised scope targets.")

        # 3. Check scheme restriction
        if scheme not in [s.lower() for s in matched_target.schemes]:
            raise ValueError(f"Scheme '{scheme}' is not allowed for target '{hostname}' (allowed: {matched_target.schemes}).")

        # 4. Check method restriction
        if method.upper() not in [m.upper() for m in matched_target.methods]:
            raise ValueError(f"HTTP Method '{method}' is not allowed for target '{hostname}' (allowed: {matched_target.methods}).")

        # 5. Check Rate Limit (max_rps)
        now = time.time()
        window_start = now - 1.0
        history = self._request_history.get(hostname, [])
        history = [ts for ts in history if ts >= window_start]
        if len(history) >= matched_target.max_rps:
            raise ValueError(f"Rate limit exceeded for host '{hostname}': max {matched_target.max_rps} RPS.")

        history.append(now)
        self._request_history[hostname] = history

        return True

    def record_approval(self, approval: ApprovalRecord) -> None:
        self.approvals.append(approval)

    def assert_approved(
        self,
        action_class: str,
        target: str,
        tool: str,
        job_id: Optional[str] = None,
        current_scope_hash: Optional[str] = None
    ) -> bool:
        if action_class == "passive":
            return True

        if self.kill_switch_active:
            raise PermissionError("Kill switch is active. Approval check rejected.")

        _, target_host, _ = self._parse_url_or_host(target)

        now = datetime.now(timezone.utc)
        for app in self.approvals:
            if app.action_class != action_class or app.tool != tool:
                continue

            # Target matching: exact host or target path match
            _, app_host, _ = self._parse_url_or_host(app.target)
            if target_host != app_host and app.target not in target and target not in app.target:
                continue

            # Validate job_id binding if provided
            if job_id and app.job_id and app.job_id != job_id:
                continue

            # Validate scope_hash binding if provided
            if current_scope_hash and app.scope_hash and app.scope_hash != current_scope_hash:
                continue

            # Expiration check
            if app.expires_at:
                exp = datetime.fromisoformat(app.expires_at)
                if now > exp:
                    continue

            return True

        raise PermissionError(
            f"Action class '{action_class}' for tool '{tool}' on target '{target}' "
            f"(job: {job_id or 'any'}) requires valid, non-expired approval."
        )

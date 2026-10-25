"""
Dispatcher choke point: enforcement of policy and evidence recording.
"""

import subprocess
import json
import hashlib
from typing import Dict, Any, List, Literal
from breachkit.policy.engine import PolicyEngine

@dataclass
class Action:
    id: str
    tool: str
    arguments: Dict[str, Any]
    target: str
    intent: str
    risk: Literal["passive", "active", "intrusive", "destructive"]
    requires_approval: bool


class Dispatcher:
    def __init__(self, policy: PolicyEngine):
        self.policy = policy
        self.registry = {
            "httpx": "/usr/bin/httpx",
            "ffuf": "/usr/bin/ffuf",
            "sqlmap": "/usr/bin/sqlmap",
        }

    def dispatch(self, action: Action) -> Dict[str, Any]:
        # 1. Policy check (enforce at the dispatcher level)
        self.policy.assert_in_scope(action.target)
        if action.requires_approval:
            self.policy.assert_approved(action.risk, action.target, action.tool)

        # 2. Execution (subprocess array only - NO SHELL)
        cmd = [self.registry.get(action.tool, action.tool)]
        for k, v in action.arguments.items():
            cmd.extend([f"--{k}", str(v)])

        try:
            result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=300)
            output = {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
        except Exception as e:
            output = {"error": str(e), "returncode": -1}

        # 3. Evidence/Audit Recording
        self._record_evidence(action, output)
        return output

    def _record_evidence(self, action: Action, output: Dict[str, Any]) -> None:
        # Placeholder for writing JSONL audit and evidence files
        print(f"[*] Audit: Recorded {action.id} result")

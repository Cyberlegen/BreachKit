"""
Dispatcher choke point: enforcement of policy and evidence recording.
"""

import subprocess
import json
import hashlib
import shutil
import os
from dataclasses import dataclass
from typing import Dict, Any, List, Literal, Union
from breachkit.policy.engine import PolicyEngine

@dataclass
class Action:
    id: str
    tool: str
    arguments: List[Union[str, Dict[str, Any]]] # Supports flags, key-values, and positionals
    target: str
    intent: str
    risk: Literal["passive", "active", "intrusive", "destructive"]
    requires_approval: bool


class Dispatcher:
    def __init__(self, policy: PolicyEngine):
        self.policy = policy
        # Preference registry for known locations, but fallback to PATH
        self.registry = {
            "httpx": ["httpx", "/usr/bin/httpx", os.path.expanduser("~/go/bin/httpx")],
            "ffuf": ["ffuf", "/usr/bin/ffuf", os.path.expanduser("~/go/bin/ffuf")],
            "sqlmap": ["sqlmap", "/usr/bin/sqlmap"],
        }

    def _resolve_tool(self, tool: str) -> str:
        candidates = self.registry.get(tool, [tool])
        for cand in candidates:
            path = shutil.which(cand)
            if path:
                return path
        return tool # Fallback to bare name and let subprocess try

    def dispatch(self, action: Action) -> Dict[str, Any]:
        # 1. Policy check (enforce at the dispatcher level)
        self.policy.assert_in_scope(action.target)
        if action.requires_approval:
            self.policy.assert_approved(action.risk, action.target, action.tool)

        # 2. Execution (subprocess array only - NO SHELL)
        executable = self._resolve_tool(action.tool)
        cmd = [executable]
        
        for arg in action.arguments:
            if isinstance(arg, str):
                # Positional or value-less flag (e.g., "-sV", "https://...")
                cmd.append(arg)
            elif isinstance(arg, dict):
                # Key-value pair (e.g., {"key": "header", "value": "X-Foo: bar"})
                # Or repeated flags if value is a list
                k = arg.get("key")
                v = arg.get("value")
                if k and v is not None:
                    if isinstance(v, list):
                        for item in v:
                            cmd.extend([k, str(item)])
                    else:
                        cmd.extend([k, str(v)])

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

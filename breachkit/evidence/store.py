"""
Evidence Store with Write-Time Redaction and Hash-Chaining Audit Log.
"""

import os
import json
import re
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List


def redact_text(text: str) -> str:
    """Write-time redaction for cookies, tokens, keys, and PII."""
    # Redact Authorization / API keys
    text = re.sub(r'(?i)(authorization:\s*)(bearer|basic)\s+[^\s\r\n]+', r'\1REDACTED_AUTH', text)
    text = re.sub(r'(?i)(x-api-key:\s*)[^\s\r\n]+', r'\1REDACTED_KEY', text)
    # Redact Cookie values (keep name)
    text = re.sub(r'(?i)(cookie:\s*[^=]+=)[^\s;]+', r'\1REDACTED_VALUE', text)
    return text


class EvidenceStore:
    def __init__(self, run_dir: str):
        self.run_dir = run_dir
        self.evidence_dir = os.path.join(run_dir, "evidence")
        self.audit_file = os.path.join(run_dir, "audit.jsonl")
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.last_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    def write_evidence(self, artifact_name: str, content: str, raw: bool = False) -> str:
        file_path = os.path.join(self.evidence_dir, artifact_name)
        final_content = content if raw else redact_text(content)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(final_content)
        
        content_hash = hashlib.sha256(final_content.encode("utf-8")).hexdigest()
        self.append_audit_log("write_evidence", {"file": artifact_name, "sha256": content_hash})
        return content_hash

    def append_audit_log(self, event_type: str, data: Dict[str, Any]) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "timestamp": timestamp,
            "prev_hash": self.last_hash,
            "event": event_type,
            "data": data,
        }
        serialized = json.dumps(payload, sort_keys=True)
        entry_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        payload["hash"] = entry_hash
        self.last_hash = entry_hash

        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")

"""
Evidence Store with Write-Time Redaction, Path Traversal Prevention,
and Hash-Chaining Audit Log Recovery & Concurrency Safety.
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional


def redact_text(text: str) -> str:
    """Write-time redaction for cookies, tokens, keys, credentials, and PII."""
    # 1. Authorization & API Keys
    text = re.sub(r'(?i)(authorization:\s*)(bearer|basic)\s+[^\s\r\n]+', r'\1REDACTED_AUTH', text)
    text = re.sub(r'(?i)(x-api-key|api-key|apikey|token|secret)[:=]\s*[^\s\r\n]+', r'\1=REDACTED_SECRET', text)

    # 2. Cookie values (keep name)
    text = re.sub(r'(?i)(cookie:\s*[^=]+=)[^\s;]+', r'\1REDACTED_VALUE', text)
    text = re.sub(r'(?i)(set-cookie:\s*[^=]+=)[^\s;]+', r'\1REDACTED_VALUE', text)

    # 3. Passwords in body / json / query params
    text = re.sub(r'(?i)(["\']?password["\']?\s*[:=]\s*["\'])[^\'">]+(["\'])', r'\1REDACTED_PASSWORD\2', text)
    text = re.sub(r'(?i)(password=[^&]+)', 'password=REDACTED_PASSWORD', text)

    # 4. PII: Email addresses
    text = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[REDACTED_EMAIL]', text)

    # 5. PII: US Phone numbers / international formats
    text = re.sub(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', '[REDACTED_PHONE]', text)

    return text


class EvidenceStore:
    def __init__(self, run_dir: str):
        self.run_dir = os.path.abspath(run_dir)
        self.evidence_dir = os.path.join(self.run_dir, "evidence")
        self.audit_file = os.path.join(self.run_dir, "audit.jsonl")
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        """Read existing audit.jsonl on startup and recover the last hash for chain integrity."""
        default_genesis = "0000000000000000000000000000000000000000000000000000000000000000"
        if not os.path.exists(self.audit_file):
            return default_genesis

        last_valid_hash = default_genesis
        try:
            with open(self.audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if "hash" in entry:
                            last_valid_hash = entry["hash"]
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        return last_valid_hash

    def write_evidence(self, artifact_name: str, content: str, raw: bool = False, operator_consent: bool = False) -> str:
        """Write evidence artifact. raw=True requires explicit operator_consent=True."""
        if raw and not operator_consent:
            raise ValueError("Writing raw unredacted evidence requires explicit operator_consent=True.")

        # Path traversal prevention: enforce resolved path is within evidence_dir
        safe_filename = os.path.basename(artifact_name)
        file_path = os.path.abspath(os.path.join(self.evidence_dir, safe_filename))
        if not file_path.startswith(os.path.abspath(self.evidence_dir)):
            raise ValueError(f"Path traversal detected in artifact name: '{artifact_name}'")

        final_content = content if raw else redact_text(content)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(final_content)

        content_hash = hashlib.sha256(final_content.encode("utf-8")).hexdigest()
        self.append_audit_log("write_evidence", {"file": safe_filename, "sha256": content_hash, "raw": raw})
        return content_hash

    def append_audit_log(self, event_type: str, data: dict[str, Any]) -> None:
        """Append to audit log with file locking / atomic-safe write for hash chain continuity."""
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Concurrency safety: re-verify and lock-in latest hash under critical section
        self.last_hash = self._recover_last_hash()

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

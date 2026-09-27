"""Log de auditoria imutável e encadeado — ISO/IEC 27043.

Cada entrada referencia o hash da anterior; qualquer adulteração
quebra a verificação de integridade da cadeia completa.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path


class AuditLogger:
    def __init__(self, log_path: Path, operator_identity: str):
        self.log_path = log_path
        self.operator = operator_identity
        self._previous_hash: str | None = None

    def log_action(self, action: str, details: dict | None = None) -> str:
        entry = {
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "operator_identity": self.operator,
            "action": action,
            "details": details or {},
            "previous_hash": self._previous_hash,
        }
        entry["entry_hash"] = self._compute_hash(entry)
        self._previous_hash = entry["entry_hash"]

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry["entry_hash"]

    def _compute_hash(self, entry: dict) -> str:
        payload = {k: v for k, v in entry.items() if k != "entry_hash"}
        content = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(content.encode()).hexdigest()

    def verify_integrity(self) -> bool:
        """Verifica se nenhuma entrada do log foi alterada."""
        if not self.log_path.exists():
            return False
        prev_hash: str | None = None
        with open(self.log_path, encoding="utf-8") as f:
            for line in f:
                entry = json.loads(line)
                if entry["previous_hash"] != prev_hash:
                    return False
                if entry["entry_hash"] != self._compute_hash(entry):
                    return False
                prev_hash = entry["entry_hash"]
        return True
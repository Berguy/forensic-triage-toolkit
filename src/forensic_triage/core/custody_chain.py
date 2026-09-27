"""Cadeia de custódia — eventos do ciclo de vida da evidência (ISO 27037).

Registra eventos de custódia (coleta, transferência, análise, descarte)
em um ledger encadeado criptograficamente: cada entrada contém o hash
da anterior, tornando qualquer adulteração detectável.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path


class CustodyEventType(str, Enum):
    COLLECTED = "collected"
    TRANSFERRED = "transferred"
    ANALYZED = "analyzed"
    STORED = "stored"
    DISPOSED = "disposed"


@dataclass
class CustodyEntry:
    event_type: CustodyEventType
    evidence_id: str
    description: str
    operator_identity: str
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    previous_hash: str | None = None
    entry_hash: str | None = None

    def compute_hash(self) -> str:
        content = json.dumps(
            {
                "event_type": self.event_type.value,
                "evidence_id": self.evidence_id,
                "description": self.description,
                "operator_identity": self.operator_identity,
                "timestamp_utc": self.timestamp_utc,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(content.encode()).hexdigest()


class CustodyChain:
    """Ledger de eventos de custódia com integridade verificável."""

    def __init__(self, operator_identity: str):
        self.operator_identity = operator_identity
        self.entries: list[CustodyEntry] = []
        self._last_hash: str | None = None

    def append(
        self, event_type: CustodyEventType, evidence_id: str, description: str
    ) -> CustodyEntry:
        entry = CustodyEntry(
            event_type=event_type,
            evidence_id=evidence_id,
            description=description,
            operator_identity=self.operator_identity,
            previous_hash=self._last_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self._last_hash = entry.entry_hash
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        prev: str | None = None
        for entry in self.entries:
            if entry.previous_hash != prev:
                return False
            if entry.entry_hash != entry.compute_hash():
                return False
            prev = entry.entry_hash
        return True

    def export_json(self, path: Path) -> None:
        payload = [asdict(e) for e in self.entries]
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
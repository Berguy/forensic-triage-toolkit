"""Manifesto de evidências — ISO/IEC 27037.

Registra cada artefato coletado com hash, timestamp UTC, método de
coleta e identidade do operador. A cadeia de hashes encadeados torna
qualquer adulteração detectável.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class CollectionMethod(str, Enum):
    LIVE = "live_acquisition"
    IMAGE = "disk_image"
    REMOTE = "remote_acquisition"


class HashAlgorithm(str, Enum):
    SHA256 = "sha256"
    SHA3_256 = "sha3_256"
    BLAKE2B = "blake2b"


@dataclass
class EvidenceItem:
    description: str
    source_path: str
    collection_method: CollectionMethod
    hash_value: str
    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256
    case_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    collector_identity: str = "not_set"
    collection_timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tool_version: str = "0.1.0"
    previous_chain_hash: str | None = None
    chain_hash: str | None = None

    def compute_chain_hash(self, previous_hash: str | None) -> str:
        """Hash encadeado: SHA-256(prev + current) — detecta qualquer alteração."""
        combined = (previous_hash or "") + self.hash_value
        self.previous_chain_hash = previous_hash
        self.chain_hash = hashlib.sha256(combined.encode()).hexdigest()
        return self.chain_hash

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


class EvidenceManifest:
    """Gerencia a coleção de evidências mantendo a cadeia de hashes encadeados."""

    def __init__(self, case_id: str, operator_identity: str, tool_version: str = "0.1.0"):
        self.case_id = case_id
        self.operator_identity = operator_identity
        self.tool_version = tool_version
        self.items: list[EvidenceItem] = []
        self._last_chain_hash: str | None = None

    def add_item(
        self,
        description: str,
        source_path: str,
        collection_method: CollectionMethod,
        hash_value: str,
        hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    ) -> EvidenceItem:
        item = EvidenceItem(
            description=description,
            source_path=source_path,
            collection_method=collection_method,
            hash_value=hash_value,
            hash_algorithm=hash_algorithm,
            case_id=self.case_id,
            collector_identity=self.operator_identity,
            tool_version=self.tool_version,
        )
        item.compute_chain_hash(self._last_chain_hash)
        self._last_chain_hash = item.chain_hash
        self.items.append(item)
        return item

    def verify_integrity(self) -> bool:
        """Verifica a cadeia: qualquer alteração em qualquer item quebra a cadeia."""
        expected_prev: str | None = None
        for item in self.items:
            if item.previous_chain_hash != expected_prev:
                return False
            combined = (item.previous_chain_hash or "") + item.hash_value
            expected = hashlib.sha256(combined.encode()).hexdigest()
            if item.chain_hash != expected:
                return False
            expected_prev = item.chain_hash
        return True

    def export_json(self, path: Path) -> None:
        payload = {
            "case_id": self.case_id,
            "operator_identity": self.operator_identity,
            "tool_version": self.tool_version,
            "items": [item.to_dict() for item in self.items],
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def import_json(cls, path: Path) -> "EvidenceManifest":
        payload = json.loads(path.read_text(encoding="utf-8"))
        manifest = cls(
            case_id=payload["case_id"],
            operator_identity=payload["operator_identity"],
            tool_version=payload.get("tool_version", "0.1.0"),
        )
        for raw in payload["items"]:
            manifest.items.append(EvidenceItem(**raw))
        manifest._last_chain_hash = manifest.items[-1].chain_hash if manifest.items else None
        return manifest
"""Modelo do relatório de triagem — ISO/IEC 27037 (rastreabilidade)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from forensic_triage.analyzers.base_analyzer import AnalyzerFinding


@dataclass(frozen=True)
class TriageReport:
    """Relatório consolidado de triagem forense.

    Imutável por construção. O integrity_hash cobre todos os campos exceto
    ele mesmo, incluindo o findings_hash que amarra o relatório ao arquivo
    de achados de origem (ISO/IEC 27037).
    """

    case_id: str
    operator_identity: str
    generated_at_utc: str
    findings: tuple[AnalyzerFinding, ...]
    evidence_chain_hash: str
    evidence_count: int
    evidence_hashes: dict[str, str]
    summary: dict[str, int]
    risk_score: int
    risk_level: str
    executive_summary: str
    findings_hash: str = ""
    integrity_hash: str = ""

    def to_dict(self) -> dict:
        """Serializa para dicionário, convertendo o enum de severidade."""
        data = asdict(self)
        data["findings"] = [
            {**asdict(finding), "severity": finding.severity.value}
            for finding in self.findings
        ]
        return data

    def compute_integrity_hash(self) -> str:
        """Hash SHA-256 do payload canônico, excluindo o próprio hash."""
        payload = {k: v for k, v in self.to_dict().items() if k != "integrity_hash"}
        canonical = json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Recalcula o hash e compara com o armazenado."""
        return self.compute_integrity_hash() == self.integrity_hash

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
"""Persistência de achados com hash de integridade — ISO/IEC 27037."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from forensic_triage.analyzers.base_analyzer import AnalyzerFinding


def compute_findings_hash(findings: list[AnalyzerFinding]) -> str:
    """SHA-256 do array canônico de achados, na ordem em que serão gravados."""
    canonical = json.dumps(
        [f.to_dict() for f in findings],
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def save_findings(findings: list[AnalyzerFinding], path: Path) -> str:
    """Grava o envelope {findings, findings_hash} e devolve o hash calculado."""
    findings_hash = compute_findings_hash(findings)
    payload = {
        "findings": [f.to_dict() for f in findings],
        "findings_hash": findings_hash,
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return findings_hash


def load_findings(path: Path) -> tuple[list[AnalyzerFinding], str]:
    """Lê o envelope e valida o hash. Aborta se o arquivo foi adulterado."""
    payload = json.loads(path.read_text(encoding="utf-8"))

    if "findings" not in payload or "findings_hash" not in payload:
        raise ValueError(
            f"Envelope inválido em {path}: esperado 'findings' e 'findings_hash'."
        )

    findings = [AnalyzerFinding.from_dict(item) for item in payload["findings"]]
    expected = payload["findings_hash"]
    actual = compute_findings_hash(findings)

    if actual != expected:
        raise ValueError(
            f"ALERTA: achados adulterados em {path}. "
            f"Hash esperado {expected[:16]}..., calculado {actual[:16]}..."
        )

    return findings, expected
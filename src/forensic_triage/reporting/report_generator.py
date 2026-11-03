"""Geração do relatório de triagem consolidado — ISO/IEC 27042."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, datetime

from forensic_triage.analyzers.base_analyzer import AnalyzerFinding, Severity
from forensic_triage.core.evidence_manifest import EvidenceManifest
from forensic_triage.reporting.report_model import TriageReport
from forensic_triage.scoring.risk_scorer import calculate_risk_score, classify_risk

# Ordem de exibição: mais grave primeiro.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ReportGenerator:
    """Consolida achados e evidências em um relatório verificável."""

    def __init__(self, manifest: EvidenceManifest) -> None:
        self.manifest = manifest

    def generate(
        self,
        findings: Iterable[AnalyzerFinding],
        generated_at_utc: str | None = None,
    ) -> TriageReport:
        """Gera o relatório ordenado, com score, sumário e hash de integridade.

        O parâmetro generated_at_utc permite congelar o timestamp em testes
        de determinismo — sem ele, o hash varia entre execuções.
        """
        ordered = tuple(
            sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        )

        summary = {level.value: 0 for level in Severity}
        for finding in ordered:
            summary[finding.severity.value] += 1

        risk_score = calculate_risk_score(ordered)
        risk_level = classify_risk(risk_score)

        evidence_hashes = {
            item.evidence_id: item.hash_value for item in self.manifest.items
        }
        chain_hash = self.manifest.items[-1].chain_hash if self.manifest.items else ""

        report = TriageReport(
            case_id=self.manifest.case_id,
            operator_identity=self.manifest.operator_identity,
            generated_at_utc=generated_at_utc or datetime.now(UTC).isoformat(),
            findings=ordered,
            evidence_chain_hash=chain_hash or "",
            evidence_count=len(self.manifest.items),
            evidence_hashes=evidence_hashes,
            summary=summary,
            risk_score=risk_score,
            risk_level=risk_level,
            executive_summary=self._build_executive_summary(
                ordered, summary, risk_score, risk_level
            ),
        )
        return replace(report, integrity_hash=report.compute_integrity_hash())

    def _build_executive_summary(
        self,
        findings: tuple[AnalyzerFinding, ...],
        summary: dict[str, int],
        risk_score: int,
        risk_level: str,
    ) -> str:
        """Monta o texto do sumário executivo."""
        if not findings:
            return (
                f"Nenhum achado relevante identificado no caso {self.manifest.case_id}. "
                f"{len(self.manifest.items)} artefato(s) analisado(s). "
                f"Risco agregado: {risk_score}/100 ({risk_level})."
            )

        parts = [
            (
                f"Foram identificados {len(findings)} achado(s) no caso "
                f"{self.manifest.case_id}, distribuídos em "
                f"{len(self.manifest.items)} artefato(s) coletado(s)."
            )
        ]

        critical = summary.get(Severity.CRITICAL.value, 0)
        high = summary.get(Severity.HIGH.value, 0)
        if critical or high:
            parts.append(
                f"Atenção imediata: {critical} achado(s) crítico(s) e "
                f"{high} de severidade alta."
            )

        parts.append(
            f"Risco agregado do caso: {risk_score}/100, classificado como {risk_level}."
        )
        return " ".join(parts)
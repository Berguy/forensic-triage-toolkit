"""Cálculo de risco agregado a partir dos achados — ISO/IEC 27042."""

from __future__ import annotations

from collections.abc import Iterable

from forensic_triage.analyzers.base_analyzer import AnalyzerFinding, Severity

# Peso de cada severidade na composição do score (0-100).
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 1,
}

MAX_SCORE = 100


def calculate_risk_score(findings: Iterable[AnalyzerFinding]) -> int:
    """Calcula o score de risco agregado do caso (0-100).

    Soma os pesos das severidades e aplica teto em 100. Um único achado
    crítico já leva o caso a 40; dois achados críticos saturam o score.
    A fórmula é linear e auditável — requisito de relatório pericial.
    """
    total = sum(SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)
    return min(total, MAX_SCORE)


def classify_risk(score: int) -> str:
    """Traduz o score numérico em rótulo textual para o sumário executivo."""
    if score >= 70:
        return "CRÍTICO"
    if score >= 40:
        return "ALTO"
    if score >= 15:
        return "MÉDIO"
    if score > 0:
        return "BAIXO"
    return "NENHUM"
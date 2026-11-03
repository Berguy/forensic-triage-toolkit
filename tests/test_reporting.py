"""Testes do relatório de triagem e do score de risco (ISO/IEC 27042)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forensic_triage.analyzers.base_analyzer import AnalyzerFinding, Severity
from forensic_triage.core.evidence_manifest import CollectionMethod, EvidenceManifest
from forensic_triage.reporting.exporters import export_json, export_markdown
from forensic_triage.reporting.report_generator import ReportGenerator
from forensic_triage.scoring.risk_scorer import calculate_risk_score, classify_risk

FIXED_TIMESTAMP = "2026-11-03T12:00:00+00:00"


@pytest.fixture
def manifest() -> EvidenceManifest:
    m = EvidenceManifest(case_id="TEST-005", operator_identity="perito_teste")
    m.add_item(
        description="Hive SYSTEM",
        source_path="C:/evidencias/SYSTEM.hive",
        collection_method=CollectionMethod.LIVE,
        hash_value="a" * 64,
    )
    m.add_item(
        description="Prefetch",
        source_path="C:/evidencias/CMD.EXE.pf",
        collection_method=CollectionMethod.LIVE,
        hash_value="b" * 64,
    )
    return m


def _finding(severity: Severity, title: str = "Achado") -> AnalyzerFinding:
    return AnalyzerFinding(
        analyzer="persistence",
        artifact_id="SYSTEM.hive",
        title=title,
        description="Descrição do achado",
        severity=severity,
        mitre_technique="T1547.001",
    )


def test_risk_score_sums_weights():
    findings = [_finding(Severity.CRITICAL), _finding(Severity.HIGH)]
    assert calculate_risk_score(findings) == 65


def test_risk_score_caps_at_100():
    findings = [_finding(Severity.CRITICAL) for _ in range(5)]
    assert calculate_risk_score(findings) == 100


def test_risk_score_empty_is_zero():
    assert calculate_risk_score([]) == 0


def test_classify_risk_thresholds():
    assert classify_risk(0) == "NENHUM"
    assert classify_risk(10) == "BAIXO"
    assert classify_risk(20) == "MÉDIO"
    assert classify_risk(50) == "ALTO"
    assert classify_risk(80) == "CRÍTICO"


def test_generator_orders_by_severity(manifest):
    findings = [
        _finding(Severity.LOW, "baixo"),
        _finding(Severity.CRITICAL, "critico"),
        _finding(Severity.MEDIUM, "medio"),
    ]
    report = ReportGenerator(manifest).generate(findings, FIXED_TIMESTAMP)
    assert [f.title for f in report.findings] == ["critico", "medio", "baixo"]


def test_generator_counts_summary(manifest):
    findings = [_finding(Severity.CRITICAL), _finding(Severity.CRITICAL), _finding(Severity.LOW)]
    report = ReportGenerator(manifest).generate(findings, FIXED_TIMESTAMP)
    assert report.summary["critical"] == 2
    assert report.summary["low"] == 1
    assert report.summary["high"] == 0


def test_generator_carries_evidence_chain(manifest):
    report = ReportGenerator(manifest).generate([], FIXED_TIMESTAMP)
    assert report.evidence_count == 2
    assert report.evidence_chain_hash == manifest.items[-1].chain_hash
    assert len(report.evidence_hashes) == 2


def test_generator_integrity_hash_is_stable(manifest):
    findings = [_finding(Severity.HIGH)]
    first = ReportGenerator(manifest).generate(findings, FIXED_TIMESTAMP)
    second = ReportGenerator(manifest).generate(findings, FIXED_TIMESTAMP)
    assert first.integrity_hash == second.integrity_hash
    assert first.verify_integrity()


def test_generator_detects_tampered_finding(manifest):
    report = ReportGenerator(manifest).generate([_finding(Severity.HIGH)], FIXED_TIMESTAMP)
    tampered = AnalyzerFinding(
        analyzer="persistence",
        artifact_id="SYSTEM.hive",
        title="Título alterado",
        description="Descrição do achado",
        severity=Severity.HIGH,
        mitre_technique="T1547.001",
    )
    from dataclasses import replace

    forged = replace(report, findings=(tampered,))
    assert forged.verify_integrity() is False


def test_generator_detects_tampered_evidence_hash(manifest):
    report = ReportGenerator(manifest).generate([], FIXED_TIMESTAMP)
    from dataclasses import replace

    forged = replace(report, evidence_chain_hash="0" * 64)
    assert forged.verify_integrity() is False


def test_executive_summary_without_findings(manifest):
    report = ReportGenerator(manifest).generate([], FIXED_TIMESTAMP)
    assert "Nenhum achado" in report.executive_summary
    assert report.risk_level == "NENHUM"


def test_executive_summary_with_critical(manifest):
    report = ReportGenerator(manifest).generate([_finding(Severity.CRITICAL)], FIXED_TIMESTAMP)
    assert "Atenção imediata" in report.executive_summary
    assert report.risk_level == "ALTO"


def test_export_json_roundtrip(manifest, tmp_path: Path):
    report = ReportGenerator(manifest).generate([_finding(Severity.HIGH)], FIXED_TIMESTAMP)
    target = tmp_path / "relatorio.json"
    export_json(report, target)

    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["case_id"] == "TEST-005"
    assert payload["integrity_hash"] == report.integrity_hash
    assert payload["findings"][0]["severity"] == "high"


def test_export_markdown_contains_sections(manifest, tmp_path: Path):
    report = ReportGenerator(manifest).generate([_finding(Severity.CRITICAL)], FIXED_TIMESTAMP)
    target = tmp_path / "relatorio.md"
    export_markdown(report, target)

    content = target.read_text(encoding="utf-8")
    assert "# Relatório de Triagem — TEST-005" in content
    assert "## Sumário executivo" in content
    assert "| Severidade | Título |" in content
    assert report.integrity_hash in content
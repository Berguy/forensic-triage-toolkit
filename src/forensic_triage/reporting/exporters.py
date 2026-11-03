"""Exportação do relatório de triagem em JSON e Markdown."""

from __future__ import annotations

from pathlib import Path

from forensic_triage.reporting.report_model import TriageReport


def export_json(report: TriageReport, path: Path) -> None:
    """Grava o relatório em JSON com formatação estável."""
    path.write_text(report.to_json(), encoding="utf-8")


def export_markdown(report: TriageReport, path: Path) -> None:
    """Grava o relatório em Markdown legível, com tabela de achados."""
    lines = [
        f"# Relatório de Triagem — {report.case_id}",
        "",
        f"**Operador:** {report.operator_identity}  ",
        f"**Gerado em (UTC):** {report.generated_at_utc}  ",
        f"**Risco agregado:** {report.risk_score}/100 ({report.risk_level})  ",
        f"**Artefatos analisados:** {report.evidence_count}  ",
        f"**Cadeia de evidências (chain_hash):** `{report.evidence_chain_hash}`  ",
        f"**Hash de integridade do relatório:** `{report.integrity_hash}`",
        "",
        "## Sumário executivo",
        "",
        report.executive_summary,
        "",
        "## Achados por severidade",
        "",
        "| Severidade | Quantidade |",
        "|---|---|",
    ]

    for level, count in report.summary.items():
        lines.append(f"| {level} | {count} |")

    lines.extend(
        [
            "",
            "## Achados",
            "",
            "| Severidade | Título | Artefato | MITRE | Analyzer |",
            "|---|---|---|---|---|",
        ]
    )

    for finding in report.findings:
        lines.append(
            f"| {finding.severity.value} | {finding.title} | "
            f"{finding.artifact_id} | {finding.mitre_technique or '—'} | "
            f"{finding.analyzer} |"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
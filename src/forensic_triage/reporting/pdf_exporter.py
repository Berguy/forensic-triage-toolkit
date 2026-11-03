"""Exportação do relatório de triagem em PDF — artefato de apresentação.

O PDF NÃO entra no integrity_hash: metadados de criação variam a cada
geração, tornando o hash instável. O documento verificável é o JSON.
"""

from __future__ import annotations

from pathlib import Path

from forensic_triage.reporting.report_model import TriageReport

SEVERITY_COLORS = {
    "critical": "#B71C1C",
    "high": "#E65100",
    "medium": "#F9A825",
    "low": "#2E7D32",
    "info": "#546E7A",
}


def export_pdf(report: TriageReport, path: Path) -> None:
    """Grava o relatório em PDF. Requer reportlab instalado."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise ImportError(
            "reportlab não está instalado. Rode: pip install -e '.[pdf]'"
        ) from exc

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title=f"Relatório de Triagem — {report.case_id}",
        author=report.operator_identity,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Heading1"], fontSize=18, spaceAfter=12
    )
    section_style = ParagraphStyle(
        "SectionTitle", parent=styles["Heading2"], fontSize=13,
        spaceBefore=16, spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["BodyText"], fontSize=9.5, leading=14
    )
    mono_style = ParagraphStyle(
        "Mono", parent=styles["BodyText"], fontName="Courier",
        fontSize=7.5, leading=10, textColor=colors.HexColor("#37474F"),
    )

    story = [
        Paragraph(f"Relatório de Triagem — {report.case_id}", title_style),
        Paragraph(
            f"<b>Operador:</b> {report.operator_identity}<br/>"
            f"<b>Gerado em (UTC):</b> {report.generated_at_utc}<br/>"
            f"<b>Risco agregado:</b> {report.risk_score}/100 ({report.risk_level})<br/>"
            f"<b>Artefatos analisados:</b> {report.evidence_count}",
            body_style,
        ),
        Spacer(1, 8),
        Paragraph("Sumário executivo", section_style),
        Paragraph(report.executive_summary, body_style),
        Paragraph("Achados por severidade", section_style),
    ]

    summary_rows = [["Severidade", "Quantidade"]]
    summary_rows += [[level, str(count)] for level, count in report.summary.items()]
    summary_table = Table(summary_rows, colWidths=[60 * mm, 40 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B0BEC5")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#F5F5F5")],
                ),
            ]
        )
    )
    story.append(summary_table)

    if report.findings:
        story.append(Paragraph("Achados", section_style))
        finding_rows = [["Severidade", "Título", "Artefato", "MITRE", "Analyzer"]]
        for finding in report.findings:
            finding_rows.append(
                [
                    finding.severity.value,
                    Paragraph(finding.title, body_style),
                    Paragraph(finding.artifact_id, body_style),
                    finding.mitre_technique or "—",
                    finding.analyzer,
                ]
            )
        findings_table = Table(
            finding_rows,
            colWidths=[22 * mm, 52 * mm, 38 * mm, 24 * mm, 28 * mm],
            repeatRows=1,
        )
        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B0BEC5")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for index, finding in enumerate(report.findings, start=1):
            hex_color = SEVERITY_COLORS.get(finding.severity.value)
            if hex_color:
                table_style.append(
                    ("TEXTCOLOR", (0, index), (0, index), colors.HexColor(hex_color))
                )
                table_style.append(
                    ("FONTNAME", (0, index), (0, index), "Helvetica-Bold")
                )
        findings_table.setStyle(TableStyle(table_style))
        story.append(findings_table)

    story.extend(
        [
            Paragraph("Integridade", section_style),
            Paragraph(
                f"<b>Cadeia de evidências (chain_hash):</b><br/>"
                f"{report.evidence_chain_hash}",
                body_style,
            ),
            Spacer(1, 4),
            Paragraph(
                f"<b>Hash dos achados (findings_hash):</b><br/>{report.findings_hash}",
                mono_style,
            ),
            Spacer(1, 4),
            Paragraph(
                f"<b>Hash de integridade do relatório:</b><br/>{report.integrity_hash}",
                mono_style,
            ),
        ]
    )

    doc.build(story)
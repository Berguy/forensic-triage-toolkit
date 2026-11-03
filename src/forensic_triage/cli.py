"""Interface de linha de comando — ISO/IEC 27037 (coleta e preservação)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from forensic_triage.analyzers.base_analyzer import AnalyzerFinding
from forensic_triage.core.evidence_manifest import EvidenceManifest
from forensic_triage.reporting.exporters import export_json, export_markdown
from forensic_triage.reporting.findings_store import load_findings, save_findings
from forensic_triage.reporting.report_generator import ReportGenerator

app = typer.Typer(
    name="forensic-triage",
    help="Triagem forense de sistemas Windows com cadeia de custódia auditável.",
    no_args_is_help=True,
)


@app.command()
def collect(
    case_id: Annotated[
        str, typer.Option("--case-id", "-c", help="Identificador do caso.")
    ],
    operator: Annotated[
        str, typer.Option("--operator", "-o", help="Identidade do perito.")
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-O", help="Caminho do manifesto."),
    ] = Path("manifesto.json"),
) -> None:
    """Cria um manifesto de evidências vazio, pronto para receber artefatos."""
    manifest = EvidenceManifest(case_id=case_id, operator_identity=operator)
    manifest.export_json(output)
    typer.echo(f"Manifesto criado: {output}")
    typer.echo(f"Caso: {case_id} | Operador: {operator}")


@app.command()
def analyze(
    findings_json: Annotated[
        Path,
        typer.Option("--input", "-i", help="JSON com os achados brutos dos analyzers."),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-O", help="Envelope de saída com hash."),
    ] = Path("achados.json"),
) -> None:
    """Valida os achados e grava o envelope com findings_hash."""
    if not findings_json.exists():
        typer.echo(f"Arquivo não encontrado: {findings_json}", err=True)
        raise typer.Exit(code=1)

    raw = json.loads(findings_json.read_text(encoding="utf-8"))
    items = raw["findings"] if isinstance(raw, dict) else raw
    findings = [AnalyzerFinding.from_dict(item) for item in items]

    findings_hash = save_findings(findings, output)
    typer.echo(f"{len(findings)} achado(s) gravado(s) em {output}")
    typer.echo(f"findings_hash: {findings_hash}")


@app.command()
def report(
    manifest_path: Annotated[
        Path,
        typer.Option("--manifest", "-m", help="Manifesto de evidências do caso."),
    ],
    findings_json: Annotated[
        Path,
        typer.Option("--findings", "-f", help="Envelope de achados com findings_hash."),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-O", help="Caminho base do relatório."),
    ] = Path("relatorio.json"),
    pdf: Annotated[
        bool, typer.Option("--pdf", help="Gera também a versão em PDF.")
    ] = False,
) -> None:
    """Consolida manifesto e achados em relatório verificável."""
    if not manifest_path.exists():
        typer.echo(f"Manifesto não encontrado: {manifest_path}", err=True)
        raise typer.Exit(code=1)
    if not findings_json.exists():
        typer.echo(f"Achados não encontrados: {findings_json}", err=True)
        raise typer.Exit(code=1)

    manifest = EvidenceManifest.import_json(manifest_path)

    try:
        findings, findings_hash = load_findings(findings_json)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    triage = ReportGenerator(manifest).generate(
        findings, findings_hash=findings_hash
    )

    json_path = output.with_suffix(".json")
    md_path = output.with_suffix(".md")
    export_json(triage, json_path)
    export_markdown(triage, md_path)

    typer.echo(f"Relatório JSON: {json_path}")
    typer.echo(f"Relatório Markdown: {md_path}")

    if pdf:
        from forensic_triage.reporting.pdf_exporter import export_pdf

        pdf_path = output.with_suffix(".pdf")
        export_pdf(triage, pdf_path)
        typer.echo(f"Relatório PDF: {pdf_path}")

    typer.echo(f"Risco: {triage.risk_score}/100 ({triage.risk_level})")
    typer.echo(f"Hash: {triage.integrity_hash}")


@app.command()
def verify(
    manifest_path: Annotated[
        Path | None,
        typer.Option("--manifest", "-m", help="Manifesto de evidências a verificar."),
    ] = None,
    findings_json: Annotated[
        Path | None,
        typer.Option("--findings", "-f", help="Envelope de achados a verificar."),
    ] = None,
    report_path: Annotated[
        Path | None,
        typer.Option("--report", "-r", help="Relatório JSON a verificar."),
    ] = None,
) -> None:
    """Verifica a integridade da cadeia: manifesto, achados e relatório."""
    if not any([manifest_path, findings_json, report_path]):
        typer.echo(
            "Informe ao menos um: --manifest, --findings ou --report.", err=True
        )
        raise typer.Exit(code=1)

    failed = False
    chain_manifest_hash = ""
    chain_findings_hash = ""

    if manifest_path:
        if not manifest_path.exists():
            typer.echo(f"Manifesto não encontrado: {manifest_path}", err=True)
            raise typer.Exit(code=1)
        manifest = EvidenceManifest.import_json(manifest_path)
        if manifest.verify_integrity():
            typer.echo(f"Manifesto íntegro: {manifest_path}")
            chain_manifest_hash = (
                manifest.items[-1].chain_hash if manifest.items else ""
            )
        else:
            typer.echo(f"ALERTA: manifesto adulterado: {manifest_path}", err=True)
            failed = True

    if findings_json:
        if not findings_json.exists():
            typer.echo(f"Achados não encontrados: {findings_json}", err=True)
            raise typer.Exit(code=1)
        try:
            _, chain_findings_hash = load_findings(findings_json)
            typer.echo(f"Achados íntegros: {findings_json}")
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            failed = True

    if report_path:
        if not report_path.exists():
            typer.echo(f"Relatório não encontrado: {report_path}", err=True)
            raise typer.Exit(code=1)
        from forensic_triage.reporting.report_model import TriageReport

        payload = json.loads(report_path.read_text(encoding="utf-8"))
        payload["findings"] = tuple(
            AnalyzerFinding.from_dict(item) for item in payload["findings"]
        )
        triage = TriageReport(**payload)

        if not triage.verify_integrity():
            typer.echo(f"ALERTA: relatório adulterado: {report_path}", err=True)
            failed = True
        else:
            typer.echo(f"Relatório íntegro: {report_path}")

            if chain_manifest_hash and triage.evidence_chain_hash != chain_manifest_hash:
                typer.echo(
                    "ALERTA: relatório não corresponde ao manifesto informado.",
                    err=True,
                )
                failed = True
            elif chain_manifest_hash:
                typer.echo("Cadeia manifesto → relatório: consistente")

            if chain_findings_hash and triage.findings_hash != chain_findings_hash:
                typer.echo(
                    "ALERTA: relatório não corresponde aos achados informados.",
                    err=True,
                )
                failed = True
            elif chain_findings_hash:
                typer.echo("Cadeia achados → relatório: consistente")

    if failed:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
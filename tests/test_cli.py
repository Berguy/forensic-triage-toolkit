"""Testes da CLI unificada — ISO/IEC 27037."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from forensic_triage.analyzers.base_analyzer import AnalyzerFinding, Severity
from forensic_triage.cli import app
from forensic_triage.core.evidence_manifest import CollectionMethod, EvidenceManifest
from forensic_triage.reporting.findings_store import compute_findings_hash

runner = CliRunner()


@pytest.fixture
def manifest_file(tmp_path: Path) -> Path:
    manifest = EvidenceManifest(case_id="CLI-001", operator_identity="perito_cli")
    manifest.add_item(
        description="Hive SYSTEM",
        source_path="C:/evidencias/SYSTEM.hive",
        collection_method=CollectionMethod.LIVE,
        hash_value="a" * 64,
    )
    target = tmp_path / "manifesto.json"
    manifest.export_json(target)
    return target


@pytest.fixture
def raw_findings_file(tmp_path: Path) -> Path:
    findings = [
        AnalyzerFinding(
            analyzer="persistence",
            artifact_id="SYSTEM.hive",
            title="Autostart suspeito",
            description="Chave Run aponta para AppData",
            severity=Severity.CRITICAL,
            mitre_technique="T1547.001",
        ).to_dict()
    ]
    target = tmp_path / "brutos.json"
    target.write_text(json.dumps(findings), encoding="utf-8")
    return target


@pytest.fixture
def findings_file(raw_findings_file: Path, tmp_path: Path) -> Path:
    target = tmp_path / "achados.json"
    runner.invoke(app, ["analyze", "-i", str(raw_findings_file), "-O", str(target)])
    return target


def test_collect_creates_manifest(tmp_path: Path):
    target = tmp_path / "manifesto.json"
    result = runner.invoke(
        app, ["collect", "-c", "CLI-002", "-o", "perito", "-O", str(target)]
    )
    assert result.exit_code == 0
    assert target.exists()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["case_id"] == "CLI-002"


def test_analyze_writes_envelope_with_hash(raw_findings_file: Path, tmp_path: Path):
    target = tmp_path / "achados.json"
    result = runner.invoke(
        app, ["analyze", "-i", str(raw_findings_file), "-O", str(target)]
    )
    assert result.exit_code == 0
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert "findings" in payload
    assert "findings_hash" in payload
    assert len(payload["findings_hash"]) == 64


def test_analyze_missing_file_exits_with_error(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "analyze",
            "-i",
            str(tmp_path / "nao_existe.json"),
            "-O",
            str(tmp_path / "x.json"),
        ],
    )
    assert result.exit_code == 1


def test_report_generates_json_and_markdown(
    manifest_file: Path, findings_file: Path, tmp_path: Path
):
    base = tmp_path / "relatorio"
    result = runner.invoke(
        app,
        ["report", "-m", str(manifest_file), "-f", str(findings_file), "-O", str(base)],
    )
    assert result.exit_code == 0
    assert (tmp_path / "relatorio.json").exists()
    assert (tmp_path / "relatorio.md").exists()


def test_report_records_findings_hash(
    manifest_file: Path, findings_file: Path, tmp_path: Path
):
    base = tmp_path / "relatorio"
    runner.invoke(
        app,
        ["report", "-m", str(manifest_file), "-f", str(findings_file), "-O", str(base)],
    )
    payload = json.loads((tmp_path / "relatorio.json").read_text(encoding="utf-8"))
    assert payload["findings_hash"] != ""
    assert len(payload["findings_hash"]) == 64


def test_report_aborts_on_tampered_findings(
    manifest_file: Path, findings_file: Path, tmp_path: Path
):
    payload = json.loads(findings_file.read_text(encoding="utf-8"))
    payload["findings"][0]["severity"] = "low"
    findings_file.write_text(json.dumps(payload), encoding="utf-8")

    base = tmp_path / "relatorio"
    result = runner.invoke(
        app,
        ["report", "-m", str(manifest_file), "-f", str(findings_file), "-O", str(base)],
    )
    assert result.exit_code == 1
    assert not (tmp_path / "relatorio.json").exists()


def test_report_missing_manifest_exits_with_error(
    findings_file: Path, tmp_path: Path
):
    result = runner.invoke(
        app,
        [
            "report",
            "-m",
            str(tmp_path / "nao_existe.json"),
            "-f",
            str(findings_file),
            "-O",
            str(tmp_path / "r"),
        ],
    )
    assert result.exit_code == 1


def test_verify_valid_manifest(manifest_file: Path):
    result = runner.invoke(app, ["verify", "-m", str(manifest_file)])
    assert result.exit_code == 0
    assert "íntegro" in result.output


def test_verify_tampered_manifest(manifest_file: Path):
    payload = json.loads(manifest_file.read_text(encoding="utf-8"))
    payload["items"][0]["hash_value"] = "b" * 64
    manifest_file.write_text(json.dumps(payload), encoding="utf-8")

    result = runner.invoke(app, ["verify", "-m", str(manifest_file)])
    assert result.exit_code == 1
    assert "adulterado" in result.output


def test_verify_tampered_findings(findings_file: Path):
    payload = json.loads(findings_file.read_text(encoding="utf-8"))
    payload["findings"][0]["title"] = "Título forjado"
    findings_file.write_text(json.dumps(payload), encoding="utf-8")

    result = runner.invoke(app, ["verify", "-f", str(findings_file)])
    assert result.exit_code == 1


def test_verify_full_chain_consistent(
    manifest_file: Path, findings_file: Path, tmp_path: Path
):
    base = tmp_path / "relatorio"
    runner.invoke(
        app,
        ["report", "-m", str(manifest_file), "-f", str(findings_file), "-O", str(base)],
    )
    result = runner.invoke(
        app,
        [
            "verify",
            "-m",
            str(manifest_file),
            "-f",
            str(findings_file),
            "-r",
            str(tmp_path / "relatorio.json"),
        ],
    )
    assert result.exit_code == 0
    assert "Cadeia manifesto → relatório: consistente" in result.output
    assert "Cadeia achados → relatório: consistente" in result.output


def test_verify_detects_report_from_other_findings(
    manifest_file: Path, findings_file: Path, tmp_path: Path
):
    base = tmp_path / "relatorio"
    runner.invoke(
        app,
        ["report", "-m", str(manifest_file), "-f", str(findings_file), "-O", str(base)],
    )

    other = tmp_path / "outros_achados.json"
    other.write_text(
        json.dumps({"findings": [], "findings_hash": compute_findings_hash([])}),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "verify",
            "-f",
            str(other),
            "-r",
            str(tmp_path / "relatorio.json"),
        ],
    )
    assert result.exit_code == 1
    assert "não corresponde aos achados" in result.output


def test_verify_without_arguments_exits_with_error():
    result = runner.invoke(app, ["verify"])
    assert result.exit_code == 1
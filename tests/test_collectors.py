"""Testes da camada de coletores (ISO/IEC 27041: validação de método)."""

from __future__ import annotations

from pathlib import Path

import pytest

from forensic_triage.collectors.base_collector import BaseCollector
from forensic_triage.collectors.live_collector import LiveCollector
from forensic_triage.core.audit_logger import AuditLogger
from forensic_triage.core.custody_chain import CustodyChain
from forensic_triage.core.evidence_manifest import EvidenceManifest


@pytest.fixture
def harness(tmp_path: Path):
    manifest = EvidenceManifest(case_id="TEST-002", operator_identity="perito_teste")
    custody = CustodyChain(operator_identity="perito_teste")
    audit = AuditLogger(tmp_path / "audit.log", operator_identity="perito_teste")
    return {
        "manifest": manifest,
        "custody": custody,
        "audit": audit,
        "output": tmp_path / "evidence",
    }


def test_live_collector_preserves_artifact(harness, tmp_path: Path):
    # Cria um artefato de exemplo para o coletor processar.
    fake_artifact = tmp_path / "sample.pf"
    fake_artifact.write_bytes(b"FAKE_PREFETCH_DATA")

    # Coletor "ao vivo" apontando para um único arquivo de teste.
    collector = LiveCollector(
        output_dir=harness["output"],
        manifest=harness["manifest"],
        custody=harness["custody"],
        audit=harness["audit"],
        operator_identity="perito_teste",
    )
    # Substitui o mapa de artefatos para apontar para o arquivo de teste.
    collector.ARTIFACT_PATHS = {"sample": str(fake_artifact)}

    collected = collector.collect()
    assert len(collected) == 1
    assert collected[0].sha256
    assert (harness["output"] / "live" / "sample" / "sample.pf").exists()


def test_collector_rejects_missing_artifact(harness, tmp_path: Path):
    collector = LiveCollector(
        output_dir=harness["output"],
        manifest=harness["manifest"],
        custody=harness["custody"],
        audit=harness["audit"],
        operator_identity="perito_teste",
    )
    collector.ARTIFACT_PATHS = {"missing": str(tmp_path / "nao_existe.bin")}
    with pytest.raises(FileNotFoundError):
        collector.collect()
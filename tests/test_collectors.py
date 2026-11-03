"""Testes da camada de coletores (ISO/IEC 27041: validação de método)."""

from __future__ import annotations

from pathlib import Path

import pytest

from forensic_triage.collectors.image_collector import ImageCollector
from forensic_triage.collectors.live_collector import LiveCollector
from forensic_triage.core.audit_logger import AuditLogger
from forensic_triage.core.custody_chain import CustodyChain
from forensic_triage.core.evidence_manifest import EvidenceManifest
from forensic_triage.integrity.hashing import hash_file


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


# --- Testes do LiveCollector ---


def test_live_collector_preserves_artifact(harness, tmp_path: Path):
    """Artefato existente é preservado, hasheado e registrado no manifesto."""
    artifact_file = tmp_path / "sample.bin"
    artifact_file.write_bytes(b"conteudo-forense")

    collector = LiveCollector(
        output_dir=harness["output"],
        manifest=harness["manifest"],
        custody=harness["custody"],
        audit=harness["audit"],
        operator_identity="perito_teste",
    )
    collector.ARTIFACT_PATHS = {"sample": str(artifact_file)}

    collected = collector.collect()

    assert len(collected) == 1
    assert collected[0].sha256 == hash_file(artifact_file)
    assert len(harness["manifest"].items) == 1
    assert harness["manifest"].verify_integrity()


def test_collector_skips_missing_artifact(harness, tmp_path: Path):
    collector = LiveCollector(
        output_dir=harness["output"],
        manifest=harness["manifest"],
        custody=harness["custody"],
        audit=harness["audit"],
        operator_identity="perito_teste",
    )
    collector.ARTIFACT_PATHS = {"missing": str(tmp_path / "nao_existe.bin")}

    collected = collector.collect()
    # ISO 27037: artefato ausente é ignorado e auditado, sem exceção.
    assert collected == []
    assert len(harness["manifest"].items) == 0


# --- Testes do ImageCollector ---


def test_image_collector_requires_existing_image(harness, tmp_path: Path):
    """Imagem inexistente levanta FileNotFoundError antes de qualquer coleta."""
    missing = tmp_path / "disco.E01"

    with pytest.raises(FileNotFoundError):
        ImageCollector(
            image_path=missing,
            output_dir=harness["output"],
            manifest=harness["manifest"],
            custody=harness["custody"],
            audit=harness["audit"],
            operator_identity="perito_teste",
        )


def test_image_collector_preserves_image(harness, tmp_path: Path):
    """A imagem é copiada, hasheada e registrada no manifesto."""
    image = tmp_path / "disco.E01"
    image.write_bytes(b"E01" + b"\x00" * 1024)

    collector = ImageCollector(
        image_path=image,
        output_dir=harness["output"],
        manifest=harness["manifest"],
        custody=harness["custody"],
        audit=harness["audit"],
        operator_identity="perito_teste",
    )
    collected = collector.collect()

    assert len(collected) == 1
    assert collected[0].sha256 == hash_file(image)
    assert len(collected[0].sha256) == 64
    assert collected[0].size_bytes == 1027
    assert Path(collected[0].destination_path).is_file()


def test_image_collector_registers_in_manifest(harness, tmp_path: Path):
    """A imagem entra no manifesto e a integridade é verificável."""
    image = tmp_path / "disco.E01"
    image.write_bytes(b"E01" + b"\x00" * 512)

    collector = ImageCollector(
        image_path=image,
        output_dir=harness["output"],
        manifest=harness["manifest"],
        custody=harness["custody"],
        audit=harness["audit"],
        operator_identity="perito_teste",
    )
    collector.collect()

    assert len(harness["manifest"].items) == 1
    assert harness["manifest"].verify_integrity()


def test_image_collector_audits_mount(harness, tmp_path: Path):
    """A operação de montagem da imagem é registrada no log de auditoria."""
    image = tmp_path / "disco.E01"
    image.write_bytes(b"E01" + b"\x00" * 256)

    collector = ImageCollector(
        image_path=image,
        output_dir=harness["output"],
        manifest=harness["manifest"],
        custody=harness["custody"],
        audit=harness["audit"],
        operator_identity="perito_teste",
    )
    collector.collect()

    assert harness["audit"].verify_integrity()
    log_content = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "image_mount" in log_content
    assert "disco.E01" in log_content


def test_image_collector_is_deterministic(harness, tmp_path: Path):
    """Mesma imagem gera o mesmo hash em coletas independentes (ISO/IEC 27042)."""
    image = tmp_path / "disco.E01"
    image.write_bytes(b"E01" + b"\x00" * 128)

    first = ImageCollector(
        image_path=image,
        output_dir=harness["output"],
        manifest=harness["manifest"],
        custody=harness["custody"],
        audit=harness["audit"],
        operator_identity="perito_teste",
    ).collect()

    second = ImageCollector(
        image_path=image,
        output_dir=harness["output"] / "segunda",
        manifest=harness["manifest"],
        custody=harness["custody"],
        audit=harness["audit"],
        operator_identity="perito_teste",
    ).collect()

    assert first[0].sha256 == second[0].sha256
"""Testes do núcleo de integridade — ISO/IEC 27041 (garantia de adequação)."""
import json
from pathlib import Path

from forensic_triage.core.audit_logger import AuditLogger
from forensic_triage.core.custody_chain import CustodyChain, CustodyEventType
from forensic_triage.core.evidence_manifest import CollectionMethod, EvidenceManifest
from forensic_triage.integrity.hashing import hash_bytes, hash_file


def test_hash_bytes_deterministic():
    assert hash_bytes(b"evidencia") == hash_bytes(b"evidencia")
    assert hash_bytes(b"evidencia") != hash_bytes(b"evidencia2")


def test_hash_file_chunks(tmp_path: Path):
    f = tmp_path / "artefato.bin"
    f.write_bytes(b"A" * (2 * 1024 * 1024))  # 2 MiB
    assert hash_file(f) == hash_file(f)
    assert len(hash_file(f)) == 64  # SHA-256 hex = 64 caracteres


def test_unsupported_algorithm_raises():
    try:
        hash_bytes(b"x", algorithm="md5")
        assert False, "deveria ter levantado ValueError"
    except ValueError:
        pass


def test_manifest_chain_and_tamper_detection():
    manifest = EvidenceManifest(case_id="CASO-001", operator_identity="perito_teste")
    manifest.add_item("ad1", "C:\\a.bin", CollectionMethod.LIVE, "hashA")
    manifest.add_item("ad2", "C:\\b.bin", CollectionMethod.LIVE, "hashB")

    assert len(manifest.items) == 2
    assert manifest.verify_integrity()

    # Adultera o hash do primeiro item
    manifest.items[0].hash_value = "hashADULTERADO"
    assert not manifest.verify_integrity()


def test_manifest_export_import_roundtrip(tmp_path: Path):
    manifest = EvidenceManifest(case_id="CASO-002", operator_identity="perito_teste")
    manifest.add_item("ad1", "C:\\a.bin", CollectionMethod.IMAGE, "hashA")

    path = tmp_path / "manifest.json"
    manifest.export_json(path)
    loaded = EvidenceManifest.import_json(path)

    assert loaded.case_id == "CASO-002"
    assert len(loaded.items) == 1
    assert loaded.verify_integrity()


def test_custody_chain_events():
    chain = CustodyChain(operator_identity="perito_teste")
    chain.append(CustodyEventType.COLLECTED, "ev-1", "coleta de imagem")
    chain.append(CustodyEventType.TRANSFERRED, "ev-1", "transferência para laboratório")
    chain.append(CustodyEventType.ANALYZED, "ev-1", "análise de artefatos")

    assert len(chain.entries) == 3
    assert chain.verify()

    # Adultera a descrição de um evento
    chain.entries[1].description = "ALTERADO"
    assert not chain.verify()


def test_audit_log_immutable(tmp_path: Path):
    log = AuditLogger(tmp_path / "audit.log", operator_identity="perito_teste")
    log.log_action("collect", {"file": "a.bin"})
    log.log_action("analyze", {"file": "a.bin"})
    assert log.verify_integrity()

    # Adultera o log manualmente
    path = tmp_path / "audit.log"
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["details"]["file"] = "ALTERADO.bin"
    lines[0] = json.dumps(entry)
    path.write_text("\n".join(lines), encoding="utf-8")

    assert not log.verify_integrity()
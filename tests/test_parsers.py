"""Testes dos parsers com dados sintéticos (ISO/IEC 27041: validação de método)."""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath

import pytest

from forensic_triage.parsers.base_parser import MalformedArtifactError
from forensic_triage.parsers.evtx_parser import EvtxParser
from forensic_triage.parsers.prefetch_parser import PrefetchParser
from forensic_triage.parsers.registry_parser import RegistryParser

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
SAMPLE_TICKS = 133_600_000_000_000_000  # ~2024-05-01 em FILETIME


def _build_prefetch(
    version: int = 30,
    run_count: int = 3,
    ticks: int = SAMPLE_TICKS,
) -> bytes:
    """Monta um arquivo .pf sintético mínimo, alinhado ao formato oficial."""
    buf = bytearray(0x98)
    buf[:4] = b"MAM\x04"
    struct.pack_into("<I", buf, 4, version)
    struct.pack_into("<Q", buf, 0x78, ticks)
    run_count_offset = 0x94 if version == 30 else 0x90
    struct.pack_into("<I", buf, run_count_offset, run_count)
    return bytes(buf)


def _build_hive(run_command: str = "", hive_type: int = 2) -> bytes:
    """Monta um hive REGF sintético mínimo com uma RunKey opcional."""
    header = bytearray(80)
    header[:4] = b"regf"
    struct.pack_into("<I", header, 4, 1)   # sequência primária
    struct.pack_into("<I", header, 8, 1)   # sequência secundária
    struct.pack_into("<Q", header, 12, SAMPLE_TICKS)  # última escrita
    struct.pack_into("<H", header, 20, 1)  # major version
    struct.pack_into("<H", header, 22, 3)  # minor version
    struct.pack_into("<I", header, 32, 1)  # tipo de arquivo
    struct.pack_into("<I", header, 36, hive_type)
    payload = bytearray(header)
    if run_command:
        payload += b"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        payload += run_command.encode("utf-16-le")
        payload += b"\x00\x00"
        payload += b"\x00" * 64
    return bytes(payload)


def _build_evtx(events: list[tuple[int, int]]) -> bytes:
    """Monta um arquivo .evtx sintético: header ElfFile + registros.

    events: lista de (event_id, filetime_ticks).
    """
    header = bytearray(4096)
    header[:8] = b"ElfFile\x00"
    payload = bytearray(header)
    for event_id, ticks in events:
        record = bytearray(0x40)
        record[:4] = b"\x2a\x2a\x00\x00"
        struct.pack_into("<I", record, 4, len(record))
        struct.pack_into("<Q", record, 0x10, ticks)
        struct.pack_into("<H", record, 0x30, event_id)
        payload += record
    return bytes(payload)


# --- Testes do Prefetch ---

def test_prefetch_parses_valid_file(tmp_path: Path):
    path = tmp_path / "NOTEPAD.EXE-3D4D1A1F.pf"
    path.write_bytes(_build_prefetch())

    result = PrefetchParser(path).parse()

    assert result.parser == "prefetch"
    assert result.artifact_id == path.name
    assert result.data["version"] == 30
    assert result.data["run_count"] == 3
    expected = (FILETIME_EPOCH + timedelta(microseconds=SAMPLE_TICKS // 10)).isoformat()
    assert result.data["last_run_utc"] == expected


def test_prefetch_deterministic(tmp_path: Path):
    """Mesma entrada gera rigorosamente a mesma saída (ISO/IEC 27042)."""
    path = tmp_path / "APP.EXE-1.pf"
    path.write_bytes(_build_prefetch())

    first = PrefetchParser(path).parse()
    second = PrefetchParser(path).parse()

    assert first.data == second.data


def test_prefetch_rejects_bad_magic(tmp_path: Path):
    path = tmp_path / "BAD.pf"
    path.write_bytes(b"NOPE\x04" + b"\x00" * 16)

    with pytest.raises(MalformedArtifactError):
        PrefetchParser(path).parse()


def test_prefetch_rejects_unsupported_version(tmp_path: Path):
    path = tmp_path / "FUTURE.pf"
    path.write_bytes(b"MAM\x04" + struct.pack("<I", 99) + b"\x00" * 16)

    with pytest.raises(MalformedArtifactError):
        PrefetchParser(path).parse()


def test_prefetch_rejects_truncated(tmp_path: Path):
    path = tmp_path / "TRUNC.pf"
    path.write_bytes(b"MAM\x04")

    with pytest.raises(MalformedArtifactError):
        PrefetchParser(path).parse()


def test_base_parser_rejects_missing_file(tmp_path: Path):
    missing = tmp_path / "ghost.pf"

    with pytest.raises(MalformedArtifactError):
        PrefetchParser(missing).parse()


# --- Testes do Registry ---

def test_registry_parses_run_key(tmp_path: Path):
    path = tmp_path / "SOFTWARE"
    path.write_bytes(_build_hive(run_command="C:\\Windows\\temp\\evil.exe"))

    result = RegistryParser(path).parse()

    assert result.parser == "registry"
    assert result.data["hive_type"] == "software"
    assert result.data["format_version"] == "1.3"
    assert len(result.data["run_keys"]) == 1
    command = result.data["run_keys"][0]["command"]
    # PureWindowsPath interpreta caminhos Windows em QUALQUER SO (Linux/Windows/macOS).
    assert PureWindowsPath(command).name.lower() == "evil.exe"


def test_registry_reports_last_written(tmp_path: Path):
    path = tmp_path / "NTUSER.DAT"
    path.write_bytes(_build_hive(hive_type=5))

    result = RegistryParser(path).parse()

    assert result.data["hive_type"] == "ntuser"
    expected = (FILETIME_EPOCH + timedelta(microseconds=SAMPLE_TICKS // 10)).isoformat()
    assert result.data["last_written_utc"] == expected


def test_registry_rejects_bad_magic(tmp_path: Path):
    path = tmp_path / "BAD"
    path.write_bytes(b"XXXX" + b"\x00" * 80)

    with pytest.raises(MalformedArtifactError):
        RegistryParser(path).parse()


def test_registry_rejects_truncated(tmp_path: Path):
    path = tmp_path / "TRUNC"
    path.write_bytes(b"regf")

    with pytest.raises(MalformedArtifactError):
        RegistryParser(path).parse()


# --- Testes do EVTX ---

def test_evtx_parses_security_events(tmp_path: Path):
    path = tmp_path / "Security.evtx"
    path.write_bytes(
        _build_evtx(
            [
                (4624, SAMPLE_TICKS),
                (4625, SAMPLE_TICKS),
                (1102, SAMPLE_TICKS),
            ]
        )
    )

    result = EvtxParser(path).parse()

    assert result.parser == "evtx"
    assert result.artifact_id == path.name
    assert result.data["event_count"] == 3
    ids = {e["event_id"] for e in result.data["events"]}
    assert ids == {4624, 4625, 1102}


def test_evtx_reports_written_time(tmp_path: Path):
    path = tmp_path / "Security.evtx"
    path.write_bytes(_build_evtx([(4624, SAMPLE_TICKS)]))

    result = EvtxParser(path).parse()

    expected = (FILETIME_EPOCH + timedelta(microseconds=SAMPLE_TICKS // 10)).isoformat()
    assert result.data["events"][0]["written_utc"] == expected


def test_evtx_rejects_bad_magic(tmp_path: Path):
    path = tmp_path / "BAD.evtx"
    path.write_bytes(b"NOTEVTX\x00" + b"\x00" * 4096)

    with pytest.raises(MalformedArtifactError):
        EvtxParser(path).parse()


def test_evtx_rejects_truncated(tmp_path: Path):
    path = tmp_path / "TRUNC.evtx"
    path.write_bytes(b"ElfFile\x00" + b"\x00" * 100)

    with pytest.raises(MalformedArtifactError):
        EvtxParser(path).parse()
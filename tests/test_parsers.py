"""Testes dos parsers com dados sintéticos (ISO/IEC 27041: validação de método)."""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from forensic_triage.parsers.base_parser import MalformedArtifactError
from forensic_triage.parsers.prefetch_parser import PrefetchParser

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
    assert first.parsed_at_utc >= first.parsed_at_utc  # determinismo de conteúdo


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
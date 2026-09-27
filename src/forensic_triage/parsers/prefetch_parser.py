"""Decodificação de arquivos .pf do Windows Prefetch (ISO/IEC 27042).

Extrai: versão do formato, última execução (UTC) e contagem de execuções.
O formato é versionado (17/23/26/30); offsets seguem a documentação pública
do formato (libyal/Windows-Prefetch).
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from forensic_triage.parsers.base_parser import (
    BaseParser,
    MalformedArtifactError,
    ParsedArtifact,
)

MAGIC = b"MAM\x04"
SUPPORTED_VERSIONS = {17, 23, 26, 30}
LAST_RUN_OFFSET = 0x78
RUN_COUNT_OFFSETS: dict[int, int] = {17: 0x90, 23: 0x90, 26: 0x90, 30: 0x94}
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _filetime_to_iso(ticks: int) -> str:
    """Converte FILETIME (intervalos de 100 ns desde 1601-01-01) para ISO 8601 UTC."""
    if ticks <= 0:
        return ""
    return (FILETIME_EPOCH + timedelta(microseconds=ticks // 10)).isoformat()


class PrefetchParser(BaseParser):
    """Interpreta um arquivo .pf e devolve o achado estruturado."""

    name: ClassVar[str] = "prefetch"

    def parse(self) -> ParsedArtifact:
        self._require_min_size(8)
        raw = self._raw

        if raw[:4] != MAGIC:
            raise MalformedArtifactError(
                f"Assinatura MAM inválida no Prefetch: {raw[:4]!r}"
            )

        version = struct.unpack_from("<I", raw, 4)[0]
        if version not in SUPPORTED_VERSIONS:
            raise MalformedArtifactError(
                f"Versão de Prefetch não suportada: {version}"
            )

        data: dict = {"version": version}

        if len(raw) >= LAST_RUN_OFFSET + 8:
            ticks = struct.unpack_from("<Q", raw, LAST_RUN_OFFSET)[0]
            if ticks:
                data["last_run_utc"] = _filetime_to_iso(ticks)

        run_count_offset = RUN_COUNT_OFFSETS[version]
        if len(raw) >= run_count_offset + 4:
            data["run_count"] = struct.unpack_from("<I", raw, run_count_offset)[0]

        return ParsedArtifact(
            artifact_id=self.source.name,
            parser=self.name,
            source_path=str(self.source),
            data=data,
        )
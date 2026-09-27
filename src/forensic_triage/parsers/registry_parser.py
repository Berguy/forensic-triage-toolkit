"""Extração de hives do registro do Windows (ISO/IEC 27042).

Valida o cabeçalho REGF e extrai candidatos de RunKeys/autorun por
varredura determinística dos caminhos-chave no conteúdo binário.
Nunca modifica o arquivo; aponta o achado para o artefato de origem.
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

HIVE_MAGIC = b"regf"
HIVE_TYPES: dict[int, str] = {
    0: "unknown",
    1: "system",
    2: "software",
    3: "security",
    4: "sam",
    5: "ntuser",
}
RUNKEY_MARKERS = (
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
)
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
MAX_COMMAND_LEN = 512


def _filetime_to_iso(ticks: int) -> str:
    """Converte FILETIME (100ns desde 1601-01-01) para ISO 8601 UTC."""
    if ticks <= 0:
        return ""
    return (FILETIME_EPOCH + timedelta(microseconds=ticks // 10)).isoformat()


def _decode_utf16le_value(raw: bytes) -> str:
    """Decodifica um valor UTF-16-LE de forma robusta.

    Decodifica o bloco inteiro como UTF-16-LE e remove os caracteres nulos
    terminais DEPOIS da decodificação. Isso garante que nenhum caractere
    válido seja cortado, independentemente de padding ou terminador.
    """
    if not raw:
        return ""
    text = raw.decode("utf-16-le", errors="replace")
    return text.rstrip("\x00")


class RegistryParser(BaseParser):
    """Lê um hive do registro e produz os achados estruturados de autorun."""

    name: ClassVar[str] = "registry"

    def parse(self) -> ParsedArtifact:
        self._require_min_size(80)
        raw = self._raw

        if raw[:4] != HIVE_MAGIC:
            raise MalformedArtifactError(
                f"Assinatura do hive inválida: {raw[:4]!r}"
            )

        major = struct.unpack_from("<H", raw, 20)[0]
        minor = struct.unpack_from("<H", raw, 22)[0]
        hive_type = HIVE_TYPES.get(
            struct.unpack_from("<I", raw, 36)[0], "unknown"
        )
        ticks = struct.unpack_from("<Q", raw, 12)[0]

        data: dict = {
            "hive_type": hive_type,
            "format_version": f"{major}.{minor}",
            "last_written_utc": _filetime_to_iso(ticks),
        }

        run_keys: list[dict] = []
        for marker in RUNKEY_MARKERS:
            start = 0
            while True:
                idx = raw.find(marker, start)
                if idx == -1:
                    break
                candidate = raw[
                    idx + len(marker) : idx + len(marker) + MAX_COMMAND_LEN
                ]
                value = _decode_utf16le_value(candidate)
                if value and value not in {k["command"] for k in run_keys}:
                    run_keys.append(
                        {
                            "path": marker.decode("ascii"),
                            "command": value,
                        }
                    )
                start = idx + 1

        data["run_keys"] = run_keys
        return ParsedArtifact(
            artifact_id=self.source.name,
            parser=self.name,
            source_path=str(self.source),
            data=data,
        )
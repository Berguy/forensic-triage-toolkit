"""Processamento binário de logs de eventos do Windows (.evtx) — ISO/IEC 27042.

Valida o cabeçalho ElfFile e extrai registros de evento de forma
determinística e defensiva. Foco operacional em Event IDs de segurança:
4624 (logon bem-sucedido), 4625 (falha de logon) e 1102 (log de auditoria
limpo). Nunca modifica o arquivo; aponta o achado para o artefato de origem.

Limitação documentada: a extração é feita por varredura defensiva de
assinaturas de registro (não é um parser binário completo de chunks/
templates). Para triagem de incidentes, isso é suficiente e determinístico.
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

EVTX_MAGIC = b"ElfFile\x00"
RECORD_SIGNATURE = b"\x2a\x2a\x00\x00"
MIN_RECORD_SIZE = 0x38
MAX_RECORD_SIZE = 0x100000  # 1 MiB — proteção contra tamanho corrompido
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
TARGET_EVENT_IDS = {4624, 4625, 1102}


def _filetime_to_iso(ticks: int) -> str:
    """Converte FILETIME (100ns desde 1601-01-01) para ISO 8601 UTC."""
    if ticks <= 0:
        return ""
    return (FILETIME_EPOCH + timedelta(microseconds=ticks // 10)).isoformat()


class EvtxParser(BaseParser):
    """Lê um arquivo .evtx e produz os achados estruturados de eventos."""

    name: ClassVar[str] = "evtx"

    def parse(self) -> ParsedArtifact:
        self._require_min_size(4096)
        raw = self._raw

        if raw[:8] != EVTX_MAGIC:
            raise MalformedArtifactError(
                f"Assinatura ElfFile inválida: {raw[:8]!r}"
            )

        events: list[dict] = []
        start = 0
        while True:
            idx = raw.find(RECORD_SIGNATURE, start)
            if idx == -1:
                break
            if idx + 8 > len(raw):
                break
            record_size = struct.unpack_from("<I", raw, idx + 4)[0]
            if (
                MIN_RECORD_SIZE <= record_size <= MAX_RECORD_SIZE
                and idx + record_size <= len(raw)
            ):
                ticks = struct.unpack_from("<Q", raw, idx + 0x10)[0]
                event_id = struct.unpack_from("<H", raw, idx + 0x30)[0]
                events.append(
                    {
                        "offset": idx,
                        "event_id": event_id,
                        "written_utc": _filetime_to_iso(ticks),
                    }
                )
                start = idx + record_size
            else:
                # Registro corrompido: avança 1 byte e continua (defensivo).
                start = idx + 1

        data: dict = {
            "file_size": len(raw),
            "event_count": len(events),
            "target_event_ids": sorted(TARGET_EVENT_IDS),
            "events": events,
        }
        return ParsedArtifact(
            artifact_id=self.source.name,
            parser=self.name,
            source_path=str(self.source),
            data=data,
        )
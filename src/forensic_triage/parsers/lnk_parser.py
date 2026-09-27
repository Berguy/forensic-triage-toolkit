"""Decodificação de atalhos Shell Link (.lnk) do Windows — ISO/IEC 27042.

Valida o cabeçalho Shell Link e extrai, de forma determinística e
defensiva: timestamps (criação, acesso, escrita), tamanho do arquivo-alvo,
caminho base local (LinkInfo) e dados de string (caminho relativo,
argumentos, diretório de trabalho, nome e local do ícone).

Critério de validação: o magic L\\x00\\x00\\x00 é a assinatura obrigatória
do formato e é validado estritamente. O CLSID é gravado como metadado
(hex + flag de correspondência ao padrão), mas NÃO é critério de rejeição:
atalhos .lnk legítimos de ferramentas de terceiros podem carregar CLSIDs
variantes, e a triagem não deve descartar artefatos válidos por isso
(parsing defensivo, ISO/IEC 27042).
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

# Assinatura obrigatória do Shell Link (MS-SHLLINK).
LNK_MAGIC = b"L\x00\x00\x00"
# CLSID padrão {00021401-0000-0000-C000-000000000046} serializado em
# little-endian — usado apenas como referência de metadado, não como falha.
LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
# Flags do Shell Link (MS-SHLLINK)
FLAG_HAS_LINK_TARGET_IDLIST = 0x00000001
FLAG_HAS_LINK_INFO = 0x00000002
FLAG_HAS_NAME = 0x00000004
FLAG_HAS_RELATIVE_PATH = 0x00000008
FLAG_HAS_WORKING_DIR = 0x00000010
FLAG_HAS_ARGUMENTS = 0x00000020
FLAG_HAS_ICON_LOCATION = 0x00000040
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
MAX_STRING_CHARS = 1024


def _filetime_to_iso(ticks: int) -> str:
    """Converte FILETIME (100ns desde 1601-01-01) para ISO 8601 UTC."""
    if ticks <= 0:
        return ""
    return (FILETIME_EPOCH + timedelta(microseconds=ticks // 10)).isoformat()


def _read_utf16_count_prefixed(raw: bytes, offset: int) -> tuple[str, int]:
    """Lê string UTF-16-LE prefixada por contagem de caracteres (WORD).

    Retorna (valor, bytes_consumidos). Se inválida, retorna ("", 2).
    """
    if offset + 2 > len(raw):
        return "", 0
    (count,) = struct.unpack_from("<H", raw, offset)
    if count <= 0 or count > MAX_STRING_CHARS:
        return "", 2
    start = offset + 2
    end = start + count * 2
    if end > len(raw):
        return "", 2
    value = raw[start:end].decode("utf-16-le", errors="replace").rstrip("\x00")
    return value, 2 + count * 2


def _read_utf16_null_terminated(raw: bytes, offset: int) -> str:
    """Lê string UTF-16-LE terminada em nulo a partir de offset."""
    if offset >= len(raw):
        return ""
    end = offset
    while end + 1 < len(raw):
        if raw[end] == 0 and raw[end + 1] == 0:
            break
        end += 2
    return raw[offset:end].decode("utf-16-le", errors="replace")


class LnkParser(BaseParser):
    """Lê um atalho .lnk e produz os achados estruturados do alvo."""

    name: ClassVar[str] = "lnk"

    def parse(self) -> ParsedArtifact:
        self._require_min_size(0x4C)
        raw = self._raw

        # Assinatura real do formato: magic L\\x00\\x00\\x00 (estrito).
        if raw[:4] != LNK_MAGIC:
            raise MalformedArtifactError(
                f"Assinatura Shell Link inválida: {raw[:4]!r}"
            )

        flags = struct.unpack_from("<I", raw, 0x14)[0]
        file_size = struct.unpack_from("<I", raw, 0x30)[0]

        data: dict = {
            "link_clsid": raw[8:24].hex(),
            "clsid_matches_standard": raw[8:24] == LNK_CLSID,
            "flags": flags,
            "file_size": file_size,
            "created_utc": _filetime_to_iso(
                struct.unpack_from("<Q", raw, 0x18)[0]
            ),
            "accessed_utc": _filetime_to_iso(
                struct.unpack_from("<Q", raw, 0x20)[0]
            ),
            "written_utc": _filetime_to_iso(
                struct.unpack_from("<Q", raw, 0x28)[0]
            ),
        }

        # LinkInfo: caminho base local (UTF-16 terminado em nulo).
        if flags & FLAG_HAS_LINK_INFO:
            link_info_size = struct.unpack_from("<I", raw, 0x4C)[0]
            if 0x4C + link_info_size <= len(raw) and link_info_size >= 0x1C:
                header_size = struct.unpack_from("<I", raw, 0x4C + 4)[0]
                local_base_offset = struct.unpack_from("<I", raw, 0x4C + 0x10)[0]
                if header_size >= 0x1C and local_base_offset >= 0x1C:
                    base = 0x4C + local_base_offset
                    value = _read_utf16_null_terminated(raw, base)
                    if value:
                        data["local_base_path"] = value

        # StringData: campos opcionais prefixados por contagem de caracteres.
        offset = 0x4C
        if flags & FLAG_HAS_LINK_TARGET_IDLIST:
            if offset + 2 <= len(raw):
                (idlist_size,) = struct.unpack_from("<H", raw, offset)
                offset += 2 + idlist_size
        if flags & FLAG_HAS_LINK_INFO:
            if offset + 4 <= len(raw):
                (link_info_size,) = struct.unpack_from("<I", raw, offset)
                offset += link_info_size

        string_fields = [
            (FLAG_HAS_NAME, "name"),
            (FLAG_HAS_RELATIVE_PATH, "relative_path"),
            (FLAG_HAS_WORKING_DIR, "working_dir"),
            (FLAG_HAS_ARGUMENTS, "arguments"),
            (FLAG_HAS_ICON_LOCATION, "icon_location"),
        ]
        for flag, key in string_fields:
            if flags & flag:
                value, consumed = _read_utf16_count_prefixed(raw, offset)
                if value:
                    data[key] = value
                offset += consumed

        return ParsedArtifact(
            artifact_id=self.source.name,
            parser=self.name,
            source_path=str(self.source),
            data=data,
        )
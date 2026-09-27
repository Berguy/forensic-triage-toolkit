"""Contrato de parser e rotinas de validação estrutural (ISO/IEC 27041/27042).

Um parser deve ser determinístico (mesma entrada, mesma saída) e rejeitar
artefatos malformados levantando MalformedArtifactError sem interromper
a cadeia de processamento (OWASP ASVS).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar


class MalformedArtifactError(ValueError):
    """Artefato inválido ou malformado — rejeitado de forma controlada."""


@dataclass
class ParsedArtifact:
    """Resultado padronizado de um parser, apontando para a fonte original."""

    artifact_id: str
    parser: str
    source_path: str
    parsed_at_utc: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    data: dict = field(default_factory=dict)


class BaseParser(ABC):
    """Classe base que carrega o arquivo e garante a leitura segura."""

    name: ClassVar[str] = "base"

    def __init__(self, source: Path) -> None:
        if not source.is_file():
            raise MalformedArtifactError(f"Arquivo não encontrado: {source}")
        self.source = source
        self._raw = source.read_bytes()

    def _require_min_size(self, n: int) -> None:
        """Garante que o artefato tenha ao menos n bytes (varredura estrutural)."""
        if len(self._raw) < n:
            raise MalformedArtifactError(
                f"Artefato truncado: {len(self._raw)} bytes (mínimo {n})"
            )

    @abstractmethod
    def parse(self) -> ParsedArtifact:
        """Produz o achado estruturado a partir do artefato."""
        raise NotImplementedError
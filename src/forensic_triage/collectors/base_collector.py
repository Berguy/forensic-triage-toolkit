"""Contrato abstrato para todos os coletores de artefatos forenses.

Cada coletor deve: coletar artefatos de forma somente-leitura, calcular o
hash de cada artefato, registrá-lo no manifesto de evidências e auditar a
operação (ISO/IEC 27037 e 27043).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from forensic_triage.core.audit_logger import AuditLogger
from forensic_triage.core.custody_chain import CustodyChain
from forensic_triage.core.evidence_manifest import (
    CollectionMethod,
    EvidenceManifest,
    HashAlgorithm,
)
from forensic_triage.integrity.hashing import hash_file


@dataclass
class CollectedArtifact:
    """Artefato coletado com seus metadados de integridade."""

    source_path: str
    destination_path: str
    sha256: str
    collection_timestamp_utc: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    size_bytes: int = 0


class BaseCollector(ABC):
    """Classe base que orquestra coleta, hashing, manifesto e auditoria."""

    def __init__(
        self,
        output_dir: Path,
        manifest: EvidenceManifest,
        custody: CustodyChain,
        audit: AuditLogger,
        operator_identity: str,
        collection_method: CollectionMethod = CollectionMethod.LIVE,
    ) -> None:
        self.output_dir = output_dir
        self.manifest = manifest
        self.custody = custody
        self.audit = audit
        self.operator = operator_identity
        self.collection_method = collection_method
        self._collected: list[CollectedArtifact] = []

    @abstractmethod
    def collect(self) -> list[CollectedArtifact]:
        """Executa a coleta de artefatos e retorna a lista coletada."""
        raise NotImplementedError

    def _preserve(self, source: Path, relative_dest: str) -> CollectedArtifact:
        """Copia um artefato para a área de preservação, calculando o hash.

        A cópia é feita em modo somente-leitura e o hash SHA-256 é calculado
        sobre o arquivo original antes de qualquer manipulação. O artefato é
        registrado no manifesto via ``add_item``, que encadeia criptograficamente
        cada evidência (cadeia de custódia — ISO/IEC 27037).
        """
        if not source.is_file():
            raise FileNotFoundError(f"Artefato não encontrado: {source}")

        sha256 = hash_file(source)
        dest = self.output_dir / relative_dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(source.read_bytes())

        artifact = CollectedArtifact(
            source_path=str(source),
            destination_path=str(dest),
            sha256=sha256,
            size_bytes=source.stat().st_size,
        )
        self._collected.append(artifact)
        self.manifest.add_item(
            description=f"Coleta de artefato: {relative_dest}",
            source_path=str(source),
            collection_method=self.collection_method,
            hash_value=sha256,
            hash_algorithm=HashAlgorithm.SHA256,
        )
        self.audit.log_action(
            "collect",
            {"artifact": relative_dest, "sha256": sha256[:16]},
        )
        return artifact
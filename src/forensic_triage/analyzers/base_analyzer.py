"""Interface comum dos analyzers — ISO/IEC 27042 (análise e interpretação)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Nível de severidade de um achado analítico."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AnalyzerFinding:
    """Achado produzido por um analyzer a partir de um artefato parseado."""

    analyzer: str
    artifact_id: str
    title: str
    description: str
    severity: Severity
    mitre_technique: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serializa o achado para JSON, convertendo o enum de severidade."""
        return {
            "analyzer": self.analyzer,
            "artifact_id": self.artifact_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "mitre_technique": self.mitre_technique,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> AnalyzerFinding:
        """Reconstrói o achado a partir do dicionário serializado."""
        return cls(
            analyzer=data["analyzer"],
            artifact_id=data["artifact_id"],
            title=data["title"],
            description=data["description"],
            severity=Severity(data["severity"]),
            mitre_technique=data.get("mitre_technique", ""),
            evidence=data.get("evidence", {}),
        )


class BaseAnalyzer(ABC):
    """Classe base para todos os analyzers de artefatos.

    Cada analyzer recebe o resultado de um parser e devolve uma lista de
    AnalyzerFinding. A análise deve ser determinística: a mesma entrada
    produz rigorosamente a mesma saída (ISO/IEC 27042).
    """

    name: str = "base"

    @abstractmethod
    def analyze(self, parsed: dict) -> list[AnalyzerFinding]:
        """Analisa o resultado de um parser e devolve os achados."""
        raise NotImplementedError
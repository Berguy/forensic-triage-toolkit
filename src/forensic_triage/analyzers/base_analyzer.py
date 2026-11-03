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
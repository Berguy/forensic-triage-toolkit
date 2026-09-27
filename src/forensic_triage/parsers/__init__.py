"""Camada de interpretação de artefatos forenses (ISO/IEC 27041/27042)."""

from forensic_triage.parsers.base_parser import (
    BaseParser,
    MalformedArtifactError,
    ParsedArtifact,
)
from forensic_triage.parsers.evtx_parser import EvtxParser
from forensic_triage.parsers.lnk_parser import LnkParser, LNK_CLSID, LNK_MAGIC
from forensic_triage.parsers.prefetch_parser import PrefetchParser
from forensic_triage.parsers.registry_parser import RegistryParser

__all__ = [
    "BaseParser",
    "EvtxParser",
    "LNK_CLSID",
    "LNK_MAGIC",
    "LnkParser",
    "MalformedArtifactError",
    "ParsedArtifact",
    "PrefetchParser",
    "RegistryParser",
]
"""Coleta de artefatos em sistema ativo (Windows), somente-leitura.

Prioriza artefatos essenciais de triagem: Prefetch, arquivos de log,
hives do registro e lista de processos (ISO/IEC 27037).
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from forensic_triage.collectors.base_collector import BaseCollector, CollectedArtifact


class LiveCollector(BaseCollector):
    """Coleta artefatos de um sistema Windows em execução."""

    ARTIFACT_PATHS: ClassVar[dict[str, str]] = {
        "prefetch": r"C:\Windows\Prefetch",
        "event_logs": r"C:\Windows\System32\winevt\Logs",
        "sysinfo": r"C:\Windows\System32\systeminfo.exe",
    }

    def collect(self) -> list[CollectedArtifact]:
        collected: list[CollectedArtifact] = []
        for category, path in self.ARTIFACT_PATHS.items():
            source = Path(path)
            if not source.exists():
                self.audit.log_action(
                    "collect_skip",
                    {"category": category, "reason": "not_found"},
                )
                continue
            if source.is_dir():
                for item in sorted(source.iterdir()):
                    if item.is_file():
                        collected.append(
                            self._preserve(item, f"live/{category}/{item.name}")
                        )
            else:
                collected.append(
                    self._preserve(source, f"live/{category}/{source.name}")
                )
        return collected
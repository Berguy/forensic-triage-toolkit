"""Analyzer de persistência — MITRE ATT&CK T1547.001.

Detecta mecanismos de autostart em chaves Run/RunOnce do registro Windows,
classificando o caminho do executável por nível de suspeita.
"""

from __future__ import annotations

from pathlib import PureWindowsPath

from forensic_triage.analyzers.base_analyzer import (
    AnalyzerFinding,
    BaseAnalyzer,
    Severity,
)

MITRE_TECHNIQUE = "T1547.001"

# Diretórios onde executáveis de autostart legítimos raramente residem.
SUSPICIOUS_DIRS = (
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\public\\",
    "\\$recycle.bin\\",
)

# Diretórios considerados legítimos para autostart.
TRUSTED_DIRS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\",
    "\\program files (x86)\\",
)


class PersistenceAnalyzer(BaseAnalyzer):
    """Analisa chaves Run/RunOnce do registro em busca de persistência suspeita."""

    name = "persistence"

    def analyze(self, parsed: dict) -> list[AnalyzerFinding]:
        """Recebe a saída do RegistryParser e devolve achados de persistência."""
        findings: list[AnalyzerFinding] = []

        if parsed.get("parser") != "registry":
            return findings

        artifact_id = parsed.get("artifact_id", "")
        run_keys = parsed.get("data", {}).get("run_keys", [])

        for entry in run_keys:
            command = entry.get("command", "")
            if not command:
                continue

            severity = self._classify(command)
            if severity is None:
                continue

            findings.append(
                AnalyzerFinding(
                    analyzer=self.name,
                    artifact_id=artifact_id,
                    title=f"Autostart em chave Run: {PureWindowsPath(command).name}",
                    description=(
                        f"Entrada de autostart aponta para '{command}'. "
                        f"Classificação: {severity.value}."
                    ),
                    severity=severity,
                    mitre_technique=MITRE_TECHNIQUE,
                    evidence={"command": command, "key": entry.get("key", "")},
                )
            )

        return findings

    def _classify(self, command: str) -> Severity | None:
        """Classifica o caminho do comando por nível de suspeita."""
        normalized = command.lower().replace("/", "\\")

        for trusted in TRUSTED_DIRS:
            if trusted in normalized:
                return None

        for suspicious in SUSPICIOUS_DIRS:
            if suspicious in normalized:
                return Severity.CRITICAL

        return Severity.MEDIUM
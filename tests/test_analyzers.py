"""Testes dos analyzers — ISO/IEC 27042 (análise e interpretação)."""

from __future__ import annotations

from forensic_triage.analyzers.base_analyzer import Severity
from forensic_triage.analyzers.persistence_analyzer import (
    MITRE_TECHNIQUE,
    PersistenceAnalyzer,
)


def _registry_payload(run_keys: list[dict]) -> dict:
    """Monta a saída sintética de um RegistryParser."""
    return {
        "parser": "registry",
        "artifact_id": "SOFTWARE",
        "data": {"hive_type": "software", "run_keys": run_keys},
    }


def test_persistence_detects_appdata_autostart():
    parsed = _registry_payload(
        [{"key": "Run", "command": "C:\\Users\\x\\AppData\\Roaming\\evil.exe"}]
    )

    findings = PersistenceAnalyzer().analyze(parsed)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].mitre_technique == MITRE_TECHNIQUE
    assert findings[0].analyzer == "persistence"


def test_persistence_detects_temp_autostart():
    parsed = _registry_payload(
        [{"key": "Run", "command": "C:\\Windows\\Temp\\payload.exe"}]
    )

    findings = PersistenceAnalyzer().analyze(parsed)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_persistence_ignores_trusted_system32():
    """Executável em System32 não gera achado (falso positivo evitado)."""
    parsed = _registry_payload(
        [{"key": "Run", "command": "C:\\Windows\\System32\\ctfmon.exe"}]
    )

    findings = PersistenceAnalyzer().analyze(parsed)

    assert findings == []


def test_persistence_ignores_program_files():
    parsed = _registry_payload(
        [{"key": "Run", "command": "C:\\Program Files\\App\\app.exe"}]
    )

    findings = PersistenceAnalyzer().analyze(parsed)

    assert findings == []


def test_persistence_flags_unknown_path_as_medium():
    parsed = _registry_payload(
        [{"key": "Run", "command": "D:\\Ferramentas\\util.exe"}]
    )

    findings = PersistenceAnalyzer().analyze(parsed)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_persistence_handles_forward_slashes():
    """Caminhos com barra normal são normalizados antes da classificação."""
    parsed = _registry_payload(
        [{"key": "Run", "command": "C:/Users/x/AppData/Roaming/evil.exe"}]
    )

    findings = PersistenceAnalyzer().analyze(parsed)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_persistence_ignores_non_registry_parser():
    parsed = {"parser": "prefetch", "artifact_id": "APP.pf", "data": {}}

    findings = PersistenceAnalyzer().analyze(parsed)

    assert findings == []


def test_persistence_handles_empty_run_keys():
    parsed = _registry_payload([])

    findings = PersistenceAnalyzer().analyze(parsed)

    assert findings == []


def test_persistence_is_deterministic():
    """Mesma entrada gera rigorosamente a mesma saída (ISO/IEC 27042)."""
    parsed = _registry_payload(
        [{"key": "Run", "command": "C:\\Users\\x\\AppData\\Roaming\\evil.exe"}]
    )

    first = PersistenceAnalyzer().analyze(parsed)
    second = PersistenceAnalyzer().analyze(parsed)

    assert first == second
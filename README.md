# Forensic Artifact Triage Toolkit

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![CI](https://github.com/Berguy/forensic-triage-toolkit/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Tests](https://img.shields.io/badge/tests-27%20passing-brightgreen.svg)

Triagem forense de sistemas comprometidos com integridade criptográfica e conformidade **ISO/IEC 27037, 27041, 27042, 27043** e **Resolução CNJ 552/2021**.

## Conformidade forense

Este projeto segue as diretrizes da ISO/IEC 27037 (coleta e preservação de evidência digital), 27041 (garantia de adequação de métodos), 27042 (análise e interpretação) e 27043 (processos de investigação), além da ABNT NBR ISO/IEC 27037 e da Resolução CNJ 552/2021 para prova digital no Judiciário brasileiro.

## Status

- Sprint 0 — Fundação e ambiente: ✅
- Sprint 1 — Núcleo de integridade, criptografia e cadeia de custódia: ✅
- Sprint 2 — Coletores de artefatos: ✅
- Sprint 3 — Parsers: ✅
- Sprint 4 — Analyzers (base_analyzer, persistence_analyzer — MITRE T1547.001): 🚧 em desenvolvimento

## Estrutura

- `src/forensic_triage/core/` — manifesto de evidências, cadeia de custódia, log de auditoria
- `src/forensic_triage/integrity/` — hashing criptográfico multialgoritmo
- `src/forensic_triage/collectors/` — coletores de artefatos Windows
- `src/forensic_triage/parsers/` — parsers de artefatos (registro, logs)
- `src/forensic_triage/analyzers/` — analisadores de persistência e mapeamento MITRE ATT&CK
- `tests/` — suíte de testes de integridade e conformidade

## Instalação

```bash
git clone https://github.com/Berguy/forensic-triage-toolkit.git
cd forensic-triage-toolkit
python -m venv .venv
source .venv/Scripts/activate   # Windows (Git Bash)
# source .venv/bin/activate     # Linux/macOS
pip install -e .

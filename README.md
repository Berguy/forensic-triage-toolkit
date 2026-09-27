# Forensic Artifact Triage Toolkit

Conformidade forense

Este projeto segue as diretrizes da ISO/IEC 27037 (coleta e preservação de evidência digital), 27041 (garantia de adequação de métodos), 27042 (análise e interpretação) e 27043 (processos de investigação), além da ABNT NBR ISO/IEC 27037 e da Resolução CNJ 552/2021 para prova digital no Judiciário brasileiro.

Triagem forense de sistemas comprometidos com integridade criptográfica e conformidade **ISO/IEC 27037, 27041, 27042, 27043** e **Resolução CNJ 552/2021**.

## Status

- Sprint 0 — Fundação e ambiente: ✅
- Sprint 1 — Núcleo de integridade, criptografia e cadeia de custódia: em andamento

## Estrutura

- `src/forensic_triage/core/` — manifesto de evidências, cadeia de custódia, log de auditoria
- `src/forensic_triage/integrity/` — hashing criptográfico multialgoritmo
- `tests/` — suíte de testes de integridade e conformidade

## Como rodar os testes

```bash
python -m venv .venv
source .venv/Scripts/activate
pip install -e ".[dev]"
pytest
```

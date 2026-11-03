# Forensic Artifact Triage Toolkit

![License](https://img.shields.io/badge/license-MIT-blue)
![CI](https://img.shields.io/badge/CI-passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-27%20passing-brightgreen)

**Triagem forense de sistemas Windows comprometidos com integridade criptográfica e conformidade normativa.**

Toolkit em Python para coleta e análise de artefatos forenses, construído desde o primeiro commit com cadeia de custódia auditável e alinhamento às normas ISO/IEC 27037, 27041, 27042, 27043 e à Resolução CNJ nº 552/2021.

---

## Por que este projeto existe

Ferramenta forense mal construída não é ferramenta — é risco jurídico. Uma evidência digital só tem valor probatório se for possível demonstrar quem a coletou, quando, de onde, e que ela não foi alterada depois.

A maioria dos scripts de triagem disponíveis não trata isso como requisito de projeto: geram relatórios sem hash verificável, sem registro de auditoria e sem rastreabilidade entre o artefato coletado e a norma que fundamenta a coleta.

Este toolkit parte do princípio oposto: **a cadeia de custódia é o produto, não um recurso adicional**.

## O que já funciona

### Núcleo de integridade e cadeia de custódia
- **Hashing criptográfico multialgoritmo** — cálculo de SHA-256, SHA-512 e MD5 sobre artefatos coletados, com verificação de integridade posterior
- **Manifesto de evidências** — registro estruturado de cada artefato coletado, com metadados de origem, timestamp e hash
- **Cadeia de custódia** — rastreamento do ciclo de vida de cada evidência, do momento da coleta até a análise
- **Log de auditoria** — registro imutável das operações executadas sobre as evidências

### Coleta de artefatos Windows
- Coletores de artefatos do sistema operacional para triagem de máquinas potencialmente comprometidas

### Parsers de artefatos
- Parsers de artefatos de registro e logs do Windows
- Parser de arquivos LNK com decodificação de Shell Link

### Qualidade
- **27 testes automatizados** cobrindo integridade e conformidade
- **Integração contínua** em Python 3.12 e 3.13
- **Lint** com Ruff (regras I001, RUF022, SIM102)

## Conformidade normativa

O projeto segue as diretrizes:

- **ISO/IEC 27037** — identificação, coleta, aquisição e preservação de evidência digital
- **ISO/IEC 27041** — garantia de adequação e confiabilidade dos métodos investigativos
- **ISO/IEC 27042** — análise e interpretação de evidência digital
- **ISO/IEC 27043** — princípios e processos de investigação de incidentes
- **ABNT NBR ISO/IEC 27037** — versão brasileira da norma de coleta e preservação
- **Resolução CNJ nº 552/2021** — requisitos para produção de prova digital no Judiciário brasileiro

## Instalação

Requisitos: Python 3.11 ou superior.

```bash
git clone https://github.com/Berguy/forensic-triage-toolkit.git
cd forensic-triage-toolkit

python -m venv .venv

# Windows (Git Bash)
source .venv/Scripts/activate
# Linux / macOS
# source .venv/bin/activate

pip install -e .
```

Para desenvolvimento, com as dependências de teste e lint:

```bash
pip install -e ".[dev]"
```

## Uso

### Verificar a integridade de um artefato coletado

```python
from forensic_triage.integrity import calculate_hashes, verify_integrity

# Calcula os hashes de um artefato no momento da coleta
hashes = calculate_hashes("C:/evidencias/SYSTEM.hive")
print(hashes)
# {'sha256': 'a3f1...', 'sha512': '9c2e...', 'md5': '4b7d...'}

# Verifica posteriormente se o artefato permanece íntegro
resultado = verify_integrity("C:/evidencias/SYSTEM.hive", hashes)
print(resultado)
# {'integro': True, 'algoritmo_verificado': 'sha256'}
```

### Registrar um artefato no manifesto de evidências

```python
from forensic_triage.core import EvidenceManifest

manifesto = EvidenceManifest(case_id="CASO-2026-001", examiner="Berguy Silva")

manifesto.add_artifact(
    path="C:/evidencias/SYSTEM.hive",
    source_host="WS-FINANCEIRO-04",
    collection_method="cópia bit a bit",
    legal_basis="ISO/IEC 27037",
)

manifesto.export("manifesto_evidencias.json")
```

> Os exemplos acima ilustram a API do núcleo de integridade. Consulte `docs/` para a especificação técnica completa e o roadmap detalhado.

### Executar os testes

```bash
pytest
```

## Estrutura do projeto

```text
forensic_triage/
├── core/          # manifesto de evidências, cadeia de custódia, log de auditoria
├── integrity/     # hashing criptográfico multialgoritmo
├── collectors/    # coletores de artefatos Windows
├── parsers/       # parsers de artefatos (registro, logs, LNK)
└── analyzers/     # análise de persistência e mapeamento MITRE ATT&CK
```

## Roadmap

| Sprint | Escopo | Status |
|---|---|---|
| Sprint 0 | Fundação e ambiente | Concluída |
| Sprint 1 | Núcleo de integridade, criptografia e cadeia de custódia | Concluída |
| Sprint 2 | Coletores de artefatos Windows | Concluída |
| Sprint 3 | Parsers de artefatos (registro, logs, LNK) | Concluída |
| Sprint 4 | Analyzers — base_analyzer, persistence_analyzer (MITRE T1547.001) | Em andamento |
| Sprint 5 | Relatório de triagem com classificação de severidade | Planejada |
| Sprint 6 | CLI unificada e empacotamento para distribuição | Planejada |

## Contribuindo

Contribuições são bem-vindas. Para mudanças relevantes, abra uma issue descrevendo o problema ou a proposta antes de enviar um pull request.

```bash
git checkout -b feature/nome-da-feature
pytest          # garanta que os testes passam
git commit -m "feat: descrição da mudança"
```

## Licença

Distribuído sob a licença **MIT**. Consulte o arquivo [LICENSE](LICENSE) para os termos completos.

## Autor

**Berguy Silva** — Engenheiro de software, pós-graduado em Computação Forense e Perícia Digital e em Gestão de Projetos.

- LinkedIn: https://www.linkedin.com/in/BerguySilva
- GitHub: https://github.com/Berguy
- Email: contato@berguysilva.com.br

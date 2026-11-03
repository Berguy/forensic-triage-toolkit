Forensic Artifact Triage Toolkit
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg) ![CI](https://github.com/Berguy/forensic-triage-toolkit/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg) ![Tests](https://img.shields.io/badge/tests-68%20passing-brightgreen.svg) ![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg)
Triagem forense de sistemas Windows comprometidos com integridade criptográfica e conformidade normativa.
Toolkit em Python para coleta e análise de artefatos forenses, construído desde o primeiro commit com cadeia de custódia auditável e alinhamento às normas ISO/IEC 27037, 27041, 27042, 27043 e à Resolução CNJ nº 552/2021.
Por que este projeto existe
Ferramenta forense mal construída não é ferramenta — é risco jurídico. Uma evidência digital só tem valor probatório se for possível demonstrar quem a coletou, quando, de onde, e que ela não foi alterada depois.
A maioria dos scripts de triagem disponíveis não trata isso como requisito de projeto: geram relatórios sem hash verificável, sem registro de auditoria e sem rastreabilidade entre o artefato coletado e a norma que fundamenta a coleta.
Este toolkit parte do princípio oposto: a cadeia de custódia é o produto, não um recurso adicional.
O que já funciona
Núcleo de integridade e cadeia de custódia
Hashing criptográfico multialgoritmo — cálculo de SHA-256, SHA3-256 e BLAKE2b sobre artefatos coletados, com verificação de integridade posterior
Manifesto de evidências — registro estruturado de cada artefato coletado, com metadados de origem, timestamp UTC e hash
Cadeia de hashes encadeados — cada item carrega o hash do anterior, tornando qualquer adulteração detectável
Log de auditoria — registro imutável das operações executadas sobre as evidências
Coleta de artefatos Windows
Coletor de sistema ativo — captura de Prefetch, logs de eventos e artefatos do sistema em execução, com preservação somente-leitura
Coletor de imagem de disco — preservação de imagens forenses (E01/RAW) como evidência de origem, com hash e auditoria da operação de montagem
Parsers de artefatos
Parser de Prefetch — versão do formato, última execução (UTC) e contagem de execuções
Parser de Registro — hives do Windows, chaves Run/RunOnce e timestamp de última escrita
Parser de EVTX — eventos de segurança do log de eventos do Windows
Parser de LNK — decodificação de Shell Link, com caminho alvo, argumentos e timestamps
Analyzers
Analyzer de persistência — detecção de mecanismos de autostart em chaves Run/RunOnce, com classificação de severidade e mapeamento ao MITRE ATT&CK T1547.001
Classificação por suspeita — caminhos em AppData, Temp e ProgramData são classificados como críticos; diretórios de sistema legítimos são ignorados, evitando falsos positivos
Relatório de triagem
Consolidação de achados — agrega resultados de múltiplos analyzers, ordenados por severidade decrescente
Score de risco agregado — cálculo de 0 a 100 com pesos por severidade, classificando o caso em cinco faixas
Hash de integridade do relatório — SHA-256 sobre payload canônico, cobrindo achados, hashes das evidências de origem e o findings_hash dos achados
Exportação em JSON, Markdown e PDF — JSON para integração com outras ferramentas, Markdown para leitura humana, PDF para entrega formal
Verificação posterior — o relatório pode ser revalidado a qualquer momento; qualquer alteração em achado, em hash de evidência ou no findings_hash quebra a verificação
Interface de linha de comando
Comando collect — cria o manifesto de evidências do caso com identificador e identidade do perito
Comando analyze — valida os achados brutos e grava o envelope com findings_hash calculado sobre o array canônico
Comando report — consolida manifesto e achados em relatório JSON, Markdown e, opcionalmente, PDF
Comando verify — valida a integridade do manifesto, dos achados e do relatório, e confirma a consistência da cadeia entre eles
Qualidade
68 testes automatizados cobrindo integridade, conformidade, coletores, parsers, analyzers, relatório e CLI
95% de cobertura de código
Integração contínua em Python 3.12 e 3.13
Lint com Ruff
Conformidade normativa
O projeto segue as diretrizes:
ISO/IEC 27037 — identificação, coleta, aquisição e preservação de evidência digital
ISO/IEC 27041 — garantia de adequação e confiabilidade dos métodos investigativos
ISO/IEC 27042 — análise e interpretação de evidência digital
ISO/IEC 27043 — princípios e processos de investigação de incidentes
ABNT NBR ISO/IEC 27037 — versão brasileira da norma de coleta e preservação
Resolução CNJ nº 552/2021 — requisitos para produção de prova digital no Judiciário brasileiro
Instalação
Requisitos: Python 3.12 ou superior.
git clone https://github.com/Berguy/forensic-triage-toolkit.git
cd forensic-triage-toolkit

python -m venv .venv

# Windows (Git Bash)

source .venv/Scripts/activate

# Linux / macOS

# source .venv/bin/activate

pip install -e .
Para desenvolvimento, com as dependências de teste, lint e geração de PDF:
pip install -e ".[dev,pdf]"
Uso
Fluxo completo pela CLI
A CLI expõe quatro comandos que formam a cadeia de integridade completa. Cada exemplo mostra o comando e a saída esperada.

1. Criar o manifesto de evidências
   forensic-triage collect -c CASO-2026-001 -o "Berguy Silva" -O manifesto.json
   Saída esperada:
   Manifesto criado: manifesto.json
   Caso: CASO-2026-001 | Operador: Berguy Silva
2. Gravar os achados com hash de integridade
   forensic-triage analyze -i achados_brutos.json -O achados.json
   Saída esperada:
   3 achado(s) gravado(s) em achados.json
   findings_hash: c9d82bb59c0a5bbf088ec6bec7536d3b3a1a8438b1779979f294e8426ff8c6a
3. Gerar o relatório de triagem
   forensic-triage report -m manifesto.json -f achados.json -O relatorio --pdf
   Saída esperada:
   Relatório JSON: relatorio.json
   Relatório Markdown: relatorio.md
   Relatório PDF: relatorio.pdf
   Risco: 100/100 (CRÍTICO)
   Hash: 5cd2844a1d258c3304f2ab1db68f90038ad0a8a9a2dd120464c28bf601eeaf3
4. Verificar a cadeia de integridade
   forensic-triage verify -m manifesto.json -f achados.json -r relatorio.json
   Saída esperada:
   Manifesto íntegro: manifesto.json
   Achados íntegros: achados.json
   Relatório íntegro: relatorio.json
   Cadeia manifesto → relatório: consistente
   Cadeia achados → relatório: consistente
   Detecção de adulteração
   Se qualquer arquivo da cadeia for alterado, o verify e o report abortam com exit code 1. Exemplo ao adulterar a severidade de um achado no envelope de achados:
   ALERTA: achados adulterados em achados.json. Hash esperado c9d82bb59c0a5bbf..., calculado cbaabe7d4f4a1d99...
   O relatório não é gerado quando a adulteração é detectada — o comando aborta antes de escrever qualquer arquivo.
   Verificar a integridade de um artefato coletado
   Uso programático, para integração em scripts próprios.
   from forensic_triage.integrity.hashing import hash_file

# Calcula o SHA-256 de um artefato no momento da coleta

sha256 = hash_file("C:/evidencias/SYSTEM.hive")
print(sha256)

# a3f1c8e2... (64 caracteres hexadecimais)

Registrar um artefato no manifesto de evidências
from forensic_triage.core.evidence_manifest import CollectionMethod, EvidenceManifest

manifesto = EvidenceManifest(
case_id="CASO-2026-001",
operator_identity="Berguy Silva",
)

manifesto.add_item(
description="Hive SYSTEM coletada do host WS-FINANCEIRO-04",
source_path="C:/evidencias/SYSTEM.hive",
collection_method=CollectionMethod.LIVE,
hash_value=sha256,
)

manifesto.export_json("manifesto_evidencias.json")
Verificar a integridade do manifesto
from forensic_triage.core.evidence_manifest import EvidenceManifest

manifesto = EvidenceManifest.import_json("manifesto_evidencias.json")

if manifesto.verify_integrity():
print("Cadeia de custódia íntegra")
else:
print("ALERTA: manifesto adulterado")
Gerar o relatório de triagem por código
from forensic_triage.analyzers.persistence_analyzer import PersistenceAnalyzer
from forensic_triage.reporting.exporters import export_json, export_markdown
from forensic_triage.reporting.report_generator import ReportGenerator

# Analisa os artefatos parseados e obtém os achados

analyzer = PersistenceAnalyzer()
findings = analyzer.analyze(parsed_registry)

# Consolida em relatório com hash de integridade

generator = ReportGenerator(manifesto)
report = generator.generate(findings)

export_json(report, "relatorio_triagem.json")
export_markdown(report, "relatorio_triagem.md")

print(f"Risco: {report.risk_score}/100 ({report.risk_level})")
print(f"Hash: {report.integrity_hash}")
Verificar a integridade do relatório
from forensic_triage.core.evidence_manifest import EvidenceManifest
from forensic_triage.reporting.report_generator import ReportGenerator

manifesto = EvidenceManifest.import_json("manifesto_evidencias.json")
report = ReportGenerator(manifesto).generate(findings)

if report.verify_integrity():
print("Relatório íntegro")
else:
print("ALERTA: relatório adulterado")
Executar os testes
pytest
Estrutura do projeto
forensic_triage/
├── core/ # manifesto de evidências, cadeia de custódia, log de auditoria
├── integrity/ # hashing criptográfico multialgoritmo
├── collectors/ # coletores de artefatos Windows
├── parsers/ # parsers de artefatos (Prefetch, Registro, EVTX, LNK)
├── analyzers/ # análise de persistência e mapeamento MITRE ATT&CK
├── reporting/ # geração, findings_store, exportação e PDF do relatório
├── scoring/ # cálculo do score de risco agregado
└── cli.py # interface de linha de comando unificada
Roadmap
Sprint
Escopo
Status
Sprint 0
Fundação e ambiente
Concluída
Sprint 1
Núcleo de integridade, criptografia e cadeia de custódia
Concluída
Sprint 2
Coletores de artefatos Windows
Concluída
Sprint 3
Parsers de artefatos (Prefetch, Registro, EVTX, LNK)
Concluída
Sprint 4
Analyzers — base_analyzer, persistence_analyzer (MITRE T1547.001)
Concluída
Sprint 5
Relatório de triagem com hash canônico e score de risco
Concluída
Sprint 6
CLI unificada, findings_store, exportação em PDF e cadeia de integridade completa
Concluída
Sprint 7
Comando CLI para adicionar artefatos ao manifesto e coleta automatizada
Planejada
Contribuindo
Contribuições são bem-vindas. Para mudanças relevantes, abra uma issue descrevendo o problema ou a proposta antes de enviar um pull request.
git checkout -b feature/nome-da-feature
pytest # garanta que os testes passam
ruff check src tests
git commit -m "feat: descrição da mudança"
Licença
Distribuído sob a licença MIT. Consulte o arquivo LICENSE para os termos completos.
Autor
Berguy Silva — Engenheiro de software, pós-graduado em Computação Forense e Perícia Digital e em Gestão de Projetos.
LinkedIn: https://www.linkedin.com/in/BerguySilva
GitHub: https://github.com/Berguy
Email: contato@berguysilva.com.br

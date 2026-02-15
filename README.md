# 🤖 Slack Bot de Priorização de Vulnerabilidades com IA

É um bot inteligente para Slack que automatiza a priorização de vulnerabilidades de segurança utilizando Inteligência Artificial. O sistema combina análise técnica (CVE, OWASP, CVSS) com impacto de negócio para gerar relatórios executivos completos e recomendar SLAs de correção.


![Flake8](https://img.shields.io/badge/flake8-passing-brightgreen)
![Tests](https://img.shields.io/badge/tests-121%20passed-brightgreen)
![Python](https://img.shields.io/badge/python-3.9+-blue)
![PEP 8](https://img.shields.io/badge/PEP%208-compliant-blue)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 Objetivo do Projeto

Auxiliar equipes de segurança a priorizar vulnerabilidades de forma objetiva, considerando:
 
- **Impacto técnico**: Severidade CVSS, exploitabilidade, presença em CISA KEV
- **Impacto no negócio**: Criticidade do sistema, exposição de dados sensíveis, conformidade regulatória
- **Recomendações automatizadas**: Sugestões de correção e mitigação geradas por IA

---

## 🧠 Como o Bot Funciona

#### Análise de Vulnerabilidades

- **CVE única**: Análise detalhada de uma vulnerabilidade específica
- **Lista de CVEs**: Priorização consolidada de múltiplas vulnerabilidades (via arquivo CSV/XLSX)
- **Categoria OWASP**: Cálculo baseado em categorias OWASP Top 10
- **Descrição livre**: Identificação automática de categoria OWASP via IA

#### Scoring Inteligente

- **Pontuação técnica (0-60)**: Baseada em CVSS, exploitabilidade, CISA KEV
- **Pontuação de negócio (0-40)**: Coletada via perguntas interativas no Slack
- **Classificação de risco**: Crítico, Alto, Médio, Baixo
- **SLA sugerido**: Prazo recomendado para correção

#### Recálculo Dinâmico

- Permite ajuste de pontuação técnica com justificativa
- IA recalcula score considerando contexto adicional
- Histórico de recálculos preservado

#### Relatórios Executivos

- Relatório individual detalhado (CVE/OWASP/Descrição)
- Relatório consolidado para listas de CVEs
- Recomendações de correção e mitigação geradas por IA
- Exportação em formato Markdown  

---

## 🏗️ Arquitetura do Projeto

Estrutura pensada para **facilitar manutenção, testes e evolução**:
```
bot-prioriza-ai/

├── .github/
│   └── workflows/
│       └── ci.yml                          # Pipeline CI/CD completo
│
├── app/
│   │
│   ├── adapters/                           # Providers de IA
│   │   ├── base_ai_provider.py             # Interface abstrata para providers
│   │   ├── groq_ai_provider.py             # Provider Groq AI
│   │   └── internal_ai_provider.py         # Provider IA interna
│   │
│   ├── core/                               # Lógica central do bot
│   │   ├── orchestrator.py                 # Orquestrador principal de fluxos
│   │   ├── conversation_manager.py         # Gerenciamento de estado conversacional
│   │   ├── vulnerability_types.py          # Enums de tipos de vulnerabilidade
│   │   └── scoring_logic.py                # Lógica de cálculo de scores
│   │
│   ├── handlers/                           # Handlers especializados
│   │   ├── base.py                         # Handler base com métodos comuns
│   │   ├── action.py                       # Handler de ações (botões)
│   │   ├── conversation.py                 # Handler de conversação (OWASP, descrição)
│   │   ├── message_file.py                 # Handler de mensagens e arquivos
│   │   └── scoring_report.py               # Handler de scoring e relatórios
│   │
│   ├── messages/                           # Templates de mensagens
│   │   └── bot_messages.py                 # Todas as mensagens do bot
│   │
│   ├── services/                           # Serviços externos
│   │   ├── ai_service.py                   # Serviço de IA (recomendações, scoring)
│   │   ├── vulnerability_service.py        # Integração com APIs de vulnerabilidades
│   │   ├── file_processing_service.py      # Processamento de arquivos CSV/XLSX
│   │   └── owasp_service.py                # Resolução de categorias OWASP
│   │
│   ├── slack/                              # Integração Slack
│   │   └── listeners.py                    # Registro de listeners Slack
│   │
│   └── utils/                              # Utilitários
│       ├── helpers.py                      # Funções auxiliares gerais
│       ├── input_validator.py              # Validação de entradas
│       └── cache.py                        # Sistema de cache para APIs
│
├── tests/                                  # Testes unitários
│   ├── conftest.py                         # Fixtures compartilhadas
│   ├── test_flow_cve_single.py             # Testes de fluxo CVE única
│   ├── test_flow_cve_list.py               # Testes de fluxo lista de CVEs
│   ├── test_flow_owasp.py                  # Testes de fluxo OWASP
│   ├── test_flow_description.py            # Testes de fluxo descrição livre
│   ├── test_flow_regressions.py            # Testes de regressão
│   ├── test_scoring_logic.py               # Testes de lógica de scoring
│   ├── test_conversation_manager.py        # Testes de gerenciamento de estado
│   ├── test_vulnerability_service.py       # Testes de serviço de vulnerabilidades
│   ├── test_ai_service.py                  # Testes de serviço de IA
│   └── test_file_processing.py             # Testes de processamento de arquivos
│
├── logs/                                   # Logs da aplicação (gitignored)
│   └── .gitkeep
│
├── .dockerignore                           # Arquivos ignorados no build Docker
├── .env.example                            # Template de variáveis de ambiente
├── .gitignore                              # Arquivos ignorados pelo Git
├── docker-compose.yml                      # Orquestração Docker para deploy
├── Dockerfile                              # Imagem Docker da aplicação
├── main.py                                 # Entry point da aplicação
├── requirements.txt                        # Dependências Python
├── README.md                               # Documentação principal
└── LICENSE                                 # Licença MIT
```  

---
#### 🔄 Fluxo de Execução - Diagrama Geral de Arquitetura

```
┌─────────────────────────────────────────────────────────────────────┐
│                          SLACK USER                                 │
│                     (Menção ou DM ao bot)                           │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      FLOW ORCHESTRATOR                              │
│                  (Roteamento por estado)                            │
│                                                                     │
│  • Detecta tipo de entrada (CVE, OWASP, descrição, arquivo)        │
│  • Gerencia estado conversacional por user_id                      │
│  • Garante idempotência por thread_ts                              │
│  • Delega para handlers especializados                             │
└────┬────────────────┬────────────────┬────────────────┬─────────────┘
     │                │                │                │
     ▼                ▼                ▼                ▼
┌─────────────┐ ┌──────────────┐ ┌─────────────────┐ ┌──────────────┐
│  Message &  │ │Conversation  │ │   Scoring &     │ │   Action     │
│    File     │ │   Handler    │ │    Report       │ │   Handler    │
│  Handler    │ │              │ │    Handler      │ │              │
└─────────────┘ └──────────────┘ └─────────────────┘ └──────────────┘
     │                │                │                │
     │                │                │                │
     ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       SERVIÇOS EXTERNOS                             │
│                                                                     │
│  • VulnerabilityService → CISA KEV, EPSS, NVD, VulnCheck           │
│  • AIService → Groq AI / Internal AI                               │
│  • FileProcessingService → Extração de CVEs                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

### 🛠️ Tecnologias Utilizadas

#### **Backend**

- **Python 3.11+**
- **Slack Bolt SDK**: Integração com Slack
- **Requests**: Chamadas HTTP para APIs externas

#### **Inteligência Artificial**

- **Groq AI**: Provider de IA para scoring e recomendações

#### **APIs Externas**

- **VulnCheck API**: Dados de CVEs (CVSS, descrição, exploitabilidade)
- **CISA KEV**: Lista de vulnerabilidades conhecidas exploradas
- **EPSS**: Exploit Prediction Scoring System
- **NVD**: National Vulnerability Database

#### **Infraestrutura**

- **Docker**: Containerização
- **AWS EC2 (t3.micro)**: Hospedagem (Free Tier eligible)
- **GitHub Actions**: CI/CD automatizado

#### **Testes**

- **pytest**: Framework de testes unitários

---

### 📦 Instalação e Configuração

#### **Pré-requisitos**

- Python 3.11+
- Docker (opcional)
- Conta Slack com permissões de administrador
- Token VulnCheck API
- Token de IA (Groq ou provider interno)

#### **1. Clonar o Repositório**

```bash
git clone https://github.com/emilyof/bot-prioriza-ai
cd bot-prioriza-ai
```

#### **2. Crie o Ambiente Virtual**

```
python3 -m venv venv
source venv/bin/activate  # Linux/Mac

# ou
venv\Scripts\activate  # Windows
```

#### **3. Configurar Variáveis de Ambiente**

Crie um arquivo `.env` baseado no `.env.example`:

```bash
## Slack
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_APP_TOKEN=xapp-your-app-token

## AI Provider
AI_PROVIDER=groq  
AI_API_URL=https://api.groq.com/v1
AI_API_TOKEN=your-groq-api-token
AI_MODEL_OVERRIDE=llama-3.1-70b-versatile  # opicional

## VulnCheck
VULNCHECK_TOKEN=your-vulncheck-token
```

#### **4. Configure o App Slack**

- Acesse api.slack.com/apps
- Crie um novo app (From scratch)
- Ative Socket Mode em **Settings** → **Socket Mode**
- Adicione os seguintes Bot Token Scopes em OAuth & Permissions:

``app_mentions:read``

``chat:write``

``files:read``

``im:history``

``im:read``

``im:write``

- Instale o app no workspace
- Copie os tokens para o .env:

Bot Token: ``xoxb-...`` (OAuth & Permissions)

App Token: ``xapp-...`` (Basic Information → App-Level Tokens)


#### **5. Instalar Dependências**

```bash
pip install -r requirements.txt
```

#### **6. Executar Localmente**

```bash
python main.py
```

#### **7. Executar com Docker**

```bash
## Build
docker build -t bot-prioriza-ai .
## Run
docker run --env-file .env bot-prioriza-ai
```

---

### 🧪 Testes

#### **Executar Todos os Testes**

```bash
pytest
```

#### **Executar com Cobertura**

```bash
pytest --cov=app --cov-report=html
```

#### **Executar Testes Específicos**

```bash
## Testes de scoring
pytest tests/test_scoring_logic.py

## Testes de fluxo
pytest tests/test_flow_cve_single.py

## Testes de guard-rails
pytest tests/test_scoring_guard_rails.py
```

#### **Cobertura de Testes**

O projeto possui **testes unitários e de integração** orientados a fluxo e risco,
priorizando confiabilidade e manutenção.

- **Scoring Logic**: Cálculo de pontuações e classificação de risco
- **Guard-Rails**: Validação de limites técnicos
- **Fluxos**: CVE única, lista de CVEs, OWASP, descrição
- **Validação de Entrada**: Detecção de injeção e sanitização
- **Regressão**: Casos críticos de fluxo

---

### 🔒 Segurança

#### **Guard-Rails Implementados**

- **Validação de entrada**: Detecção de injeção de código e path traversal
- **Sanitização de texto**: Remoção de caracteres perigosos
- **Limites de pontuação**: Score técnico entre 30-60, negócio entre 0-40
- **Rate limiting**: Retry com backoff exponencial para APIs externas
- **Normalização de IA**: Proteção contra respostas malformadas

#### **Boas Práticas**

- Tokens armazenados em variáveis de ambiente
- Logs estruturados sem exposição de dados sensíveis
- Validação de thread_ts para evitar cross-thread injection
- Deduplicação de ações de botões

---

## 👩‍💻 Autoria

**Emily Oliveira Ferrari**  
Cybersecurity Analyst  


### 🤝 Colaboração

Agradecimento especial a **Cirano da Silva Gonçalves**, que auxiliou:

- Na revisão de **testes em produção**
- Na **integração com APIs externas** (NVD, VulnCheck, CISA KEV e similares)
- Em discussões técnicas sobre **fluxo conversacional, scoring e confiabilidade**

---
**⚡️ Desenvolvido com foco em segurança, escalabilidade e experiência do usuário.**
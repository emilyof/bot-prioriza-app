# README - Vulnerability Prioritization Slack Bot with AI

---

## 🤖 Vulnerability Prioritization Slack Bot with AI

An intelligent Slack bot that automates the prioritization of security vulnerabilities using Artificial Intelligence. The system combines technical analysis (CVE, OWASP, CVSS) with business impact to generate comprehensive executive reports and recommend remediation SLAs.

![Flake8](https://img.shields.io/badge/flake8-passing-brightgreen)
![Tests](https://img.shields.io/badge/tests-121%20passed-brightgreen)
![Python](https://img.shields.io/badge/python-3.9+-blue)
![PEP 8](https://img.shields.io/badge/PEP%208-compliant-blue)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

### 🎯 Project Objective

To assist security teams in prioritizing vulnerabilities objectively, considering:

- **Technical impact**: CVSS severity, exploitability, presence in CISA KEV
- **Business impact**: System criticality, sensitive data exposure, regulatory compliance
- **Automated recommendations**: AI-generated remediation and mitigation suggestions

---

### 🧠 How the Bot Works

#### Vulnerability Analysis

- **Single CVE**: Detailed analysis of a specific vulnerability
- **CVE list**: Consolidated prioritization of multiple vulnerabilities (via CSV/XLSX file)
- **OWASP category**: Calculation based on OWASP Top 10 categories
- **Free-text description**: Automatic identification of OWASP category via AI

#### Intelligent Scoring

- **Technical score (0-60)**: Based on CVSS, exploitability, CISA KEV
- **Business score (0-40)**: Collected via interactive questions in Slack
- **Risk classification**: Critical, High, Medium, Low
- **Suggested SLA**: Recommended timeframe for remediation

#### Dynamic Recalculation

- Allows adjustment of technical score with justification
- AI recalculates score considering additional context
- Recalculation history preserved

#### Executive Reports

- Detailed individual report (CVE/OWASP/Description)
- Consolidated report for CVE lists
- AI-generated remediation and mitigation recommendations
- Export in Markdown format

---

### 🏗️ Project Architecture

Structure designed to **facilitate maintenance, testing, and evolution**:

```
bot-prioriza-ai/

├── .github/
│   └── workflows/                          # Pipeline CI/CD completo
├── app/
│   ├── adapters/                           # Providers de IA
│   ├── core/                               # Lógica central do bot
│   ├── handlers/                           # Handlers especializados
│   ├── messages/                           # Templates de mensagens
│   ├── services/                           # Serviços externos
│   ├── slack/                              # Integração Slack
│   └── utils/                              # Utilitários
├── tests/                                  # Testes unitários
```  

---

#### 🔄 Execution Flow - General Architecture Diagram

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
│  • Detecta tipo de entrada (CVE, OWASP, descrição, arquivo)         │
│  • Gerencia estado conversacional por user_id                       │
│  • Garante idempotência por thread_ts                               │
│  • Delega para handlers especializados                              │
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
│  • VulnerabilityService → CISA KEV, EPSS, NVD, VulnCheck            │
│  • AIService → Groq AI / Internal AI                                │
│  • FileProcessingService → Extração de CVEs                         │
└─────────────────────────────────────────────────────────────────────┘
```

---

#### 🛠️ Technologies Used

#### **Backend**
- **Python 3.11+**
- **Slack Bolt SDK**: Slack integration
- **Requests**: HTTP calls to external APIs

#### **Artificial Intelligence**
- **Groq AI**: AI provider for scoring and recommendations

#### **External APIs**
- **VulnCheck API**: CVE data (CVSS, description, exploitability)
- **CISA KEV**: Known Exploited Vulnerabilities list
- **EPSS**: Exploit Prediction Scoring System
- **NVD**: National Vulnerability Database

#### **Infrastructure**
- **Docker**: Containerization
- **AWS EC2 (t3.micro)**: Hosting (Free Tier eligible)
- **GitHub Actions**: Automated CI/CD

#### **Testing**
- **pytest**: Unit testing framework

---

#### 📦 Installation and Configuration

#### **Prerequisites**

- Python 3.11+
- Docker (optional)
- Slack account with administrator permissions
- VulnCheck API token
- AI token (Groq or internal provider)

#### **1. Clone the Repository**

```bash
git clone https://github.com/emilyof/bot-prioriza-ai
cd bot-prioriza-ai
```

#### **2. Create Virtual Environment**

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac

## or
venv\Scripts\activate  # Windows
```

#### **3. Configure Environment Variables**

Create a `.env` file based on `.env.example`:

```bash
### Slack
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_APP_TOKEN=xapp-your-app-token

### AI Provider
AI_PROVIDER=groq
AI_API_URL=https://api.groq.com/v1
AI_API_TOKEN=your-groq-api-token
AI_MODEL_OVERRIDE=llama-3.1-70b-versatile  # optional

### VulnCheck
VULNCHECK_TOKEN=your-vulncheck-token
```

#### **4. Configure Slack App**

- Access api.slack.com/apps
- Create a new app (From scratch)
- Enable Socket Mode in **Settings** → **Socket Mode**
- Add the following Bot Token Scopes in OAuth & Permissions:

`app_mentions:read`

`chat:write`

`files:read`

`im:history`

`im:read`

`im:write`

- Install the app in your workspace

- Copy the tokens to .env:

Bot Token: `xoxb-...` (OAuth & Permissions)

App Token: `xapp-...` (Basic Information → App-Level Tokens)

#### **5. Install Dependencies**

```bash
pip install -r requirements.txt
```

#### **6. Run Locally**

```bash
python main.py
```

#### **7. Run with Docker**

```bash
### Build
docker build -t bot-prioriza-ai .

### Run
docker run --env-file .env bot-prioriza-ai
```

---

#### 🧪 Testing

#### **Run All Tests**

```bash
pytest
```

#### **Run with Coverage**

```bash
pytest --cov=app --cov-report=html
```

#### **Run Specific Tests**

```bash
### Scoring tests
pytest tests/test_scoring_logic.py

### Flow tests
pytest tests/test_flow_cve_single.py

### Guard-rails tests
pytest tests/test_scoring_guard_rails.py
```

#### **Test Coverage**

The project has **unit and integration tests** focused on flow and risk,

prioritizing reliability and maintainability.

- **Scoring Logic**: Score calculation and risk classification
- **Guard-Rails**: Technical limit validation
- **Flows**: Single CVE, CVE list, OWASP, description
- **Input Validation**: Injection detection and sanitization
- **Regression**: Critical flow cases

---

#### 🔒 Security

#### **Implemented Guard-Rails**

- **Input validation**: Code injection and path traversal detection
- **Text sanitization**: Removal of dangerous characters
- **Score limits**: Technical score between 30-60, business between 0-40
- **Rate limiting**: Retry with exponential backoff for external APIs
- **AI normalization**: Protection against malformed responses

#### **Best Practices**

- Tokens stored in environment variables
- Structured logs without sensitive data exposure
- thread_ts validation to prevent cross-thread injection
- Button action deduplication

---

### 👩‍💻 Authorship

**Emily Oliveira Ferrari**

Cybersecurity Analyst

#### 🤝 Collaboration

Special thanks to **Cirano da Silva Gonçalves**, who assisted with:

- **Production testing** review
- **External API integration** (NVD, VulnCheck, CISA KEV and similar)
- Technical discussions on **conversational flow, scoring, and reliability**

---

**⚡️ Developed with a focus on security, scalability, and user experience.**

# Voidwatch

**Voidwatch** is a lightweight AI-assisted endpoint behavior monitoring platform for Windows. It collects process and network telemetry, analyzes suspicious behavior with a hybrid detection pipeline, and displays alerts in a desktop dashboard.

Voidwatch is currently a **research / startup prototype** focused on endpoint visibility, explainable alerts, false-positive reduction, and safe private beta testing.

> **Status:** Prototype / private beta preparation  
> **Target users:** cybersecurity labs, student security teams, developers, small teams, and early-stage startups  
> **Platform:** Windows endpoints, FastAPI backend, Electron dashboard

---

## Key Features

- Windows endpoint agent for process and network telemetry
- FastAPI backend for telemetry ingestion and scoring
- Electron dashboard for agents, processes, alerts, settings, and feedback
- Hybrid detection engine:
  - MITRE ATT&CK-inspired rule engine
  - machine learning classifier
  - context suppression for known-good processes
- Agent enrollment with per-agent secrets
- `collect_only` mode for safe benign-data collection
- Alert feedback system for true/false positive labeling
- Allowlist support for trusted processes, publishers, paths, hashes, and parent-child pairs
- CSV report export for alerts and telemetry
- Privacy and data-collection documentation
- Docker/PostgreSQL-ready direction for private beta deployment

---

## Screenshots



![Dashboard](docs/screenshots/dashboard.png)
![Processes](docs/screenshots/processes.png)
![Alerts](docs/screenshots/alerts.png)


---

## Architecture

```text
Windows Agent / Collector
        ↓
FastAPI Backend
        ↓
Database: SQLite for prototype / PostgreSQL for beta
        ↓
Detection Engine
        ├── Rule-based scoring
        ├── ML classifier
        ├── Allowlist checks
        └── Alert generation
        ↓
Electron Dashboard
        ├── Agents
        ├── Processes
        ├── Alerts
        ├── Feedback
        ├── Reports
        └── Settings
```

### Main Components

| Component | Description |
|---|---|
| `client/agent` | Windows agent that collects process and network telemetry |
| `client/dashboard` | Electron dashboard for monitoring and analysis |
| `server/backend` | FastAPI backend, database models, API routes, scoring, reports |
| `server/model` | Training pipeline, feature extraction, datasets, evaluation tools |
| `tools/collector` | Standalone benign-data collector for external testers |
| `docs` | Privacy, data collection, security, and deployment documentation |

---

## Detection Pipeline

Voidwatch uses a hybrid detection approach.

### 1. Rule-Based Detection

The rule engine assigns risk points based on suspicious endpoint behavior, such as:

- encoded PowerShell commands
- execution-policy bypass
- download cradle behavior
- Office applications spawning shells
- browsers spawning shells
- suspicious LOLBins such as `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, and `certutil.exe`
- execution from user-writable paths such as Temp, Downloads, or AppData
- suspicious network connections
- registry persistence indicators
- scheduled-task creation indicators

Rules are designed to be explainable. Alerts should show **why** a process was considered suspicious, not only a numeric score.

### 2. Machine Learning Classifier

The ML pipeline is designed to classify process behavior using extracted behavioral features.

The current training direction uses:

- scenario-based evaluation
- cleaned attack labels
- benign collector data
- calibrated probability output
- precision, recall, F1, AUC-ROC, and AUC-PR tracking

Important feature groups include:

- process identity features
- parent-child relationship features
- command-line behavior features
- suspicious token counts
- path-category features
- network behavior features
- discovery / lateral movement / credential-access indicators
- signing and context features when available

### 3. Context Suppression

Voidwatch reduces risk for known-good or sensitive process categories, such as:

- critical Windows system processes
- Microsoft Defender and security services
- known browsers
- developer tools
- trusted publishers and paths

This is important for reducing false positives in real environments.

### 4. Allowlist Layer

The allowlist can suppress trusted activity by:

- process name
- publisher
- path
- hash
- parent-child pair

This allows beta users or administrators to mark known-safe behavior and reduce alert noise.

---

## Data Collection and Privacy

Voidwatch is designed to collect technical endpoint telemetry, not personal content.

### Collected Data

Depending on configuration, the agent or collector may collect:

- process name
- process path
- parent process
- command line
- process ID and parent process ID
- network connection status
- destination IP and port
- protocol / connection type
- digital signature status and publisher, if available
- timestamps
- agent ID / host metadata

### Not Collected

Voidwatch should **not** collect:

- passwords
- browser cookies
- browser history contents
- private messages
- screenshots
- keystrokes
- files or document contents
- tokens or secrets intentionally

For beta testing and benign-data collection, path anonymization should be enabled whenever possible.

Read more:

```text
docs/PRIVACY.md
docs/DATA_COLLECTION.md
docs/SECURITY.md
```

---

## Private Beta Modes

Voidwatch supports different operating modes.

| Mode | Purpose |
|---|---|
| `collect_only` | Collect telemetry without generating alerts; useful for benign data collection |
| `detect` | Collect telemetry and generate alerts |
| `debug` | Verbose local testing and troubleshooting |

For first external testers, use `collect_only` mode to build a clean benign dataset safely.

---

## Quick Start

> The exact paths may differ depending on your branch. Adjust commands if your folders are named differently.

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/Voidwatch.git
cd Voidwatch
```

---

## Backend Setup

### Option A — Local Python Setup

```bash
cd server/backend
python -m venv .venv
```

Activate the virtual environment:

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

**macOS/Linux:**

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create environment file:

```bash
cp .env.example .env
```

Example `.env`:

```env
DATABASE_URL=sqlite:///./voidwatch.db
HOST=0.0.0.0
PORT=8000
VOIDWATCH_API_KEY=change-this-key
CORS_ORIGINS=*
```

Start the backend:

```bash
python main.py
```

The API should be available at:

```text
http://localhost:8000
```

Health check:

```text
GET /health
```

### Option B — Docker Compose

If Docker support is configured:

```bash
docker compose up --build
```

Recommended for private beta:

```text
FastAPI backend + PostgreSQL + HTTPS reverse proxy
```

---

## Dashboard Setup

```bash
cd client/dashboard
npm install
npm start
```

The dashboard allows you to:

- view connected agents
- inspect processes
- review alerts
- provide feedback
- configure backend connection settings
- export reports

If API authentication is enabled, configure the backend URL and API key in the dashboard settings.

---

## Agent Setup

The agent is responsible for collecting endpoint telemetry and sending it to the backend.

Example configuration:

```json
{
  "server_url": "http://localhost:8000",
  "mode": "collect_only",
  "collection_interval": 10,
  "anonymize_paths": true
}
```

For private beta, the preferred flow is:

```text
1. Admin creates enrollment token
2. Tester runs agent
3. Agent calls /agents/enroll
4. Backend returns agent_id and agent_secret
5. Agent uses its own secret for future communication
```

Do not use one shared API key for all testers in a real beta.

---

## Benign Data Collector

The standalone collector is intended for safe benign-data collection from clean Windows machines.

Recommended usage:

```text
1. Tester downloads collector package
2. Tester reviews included source code
3. Tester runs the collector on a clean Windows system
4. Tester uses the computer normally
5. Collector generates a report file
6. Tester uploads the report and a console-completion screenshot
```

The collector should be used only with user consent.

---

## Training the ML Model

Training code is located in:

```text
server/model
```

Typical flow:

```bash
cd server/model
python -X utf8 train.py
```

The training pipeline should produce model artifacts and evaluation outputs such as:

```text
model files
training history
scenario evaluation metrics
confusion matrices
feature importance plots
```

### Dataset Strategy

Voidwatch should not rely on a single dataset. Recommended dataset stack:

```text
1. OTRF / Mordor attack telemetry
2. Controlled lab simulations
3. Clean Windows benign data from the collector
4. Beta-user feedback labels
```

Use three internal labels when possible:

```text
benign
malicious
unknown
```

Train only on confirmed `benign` and confirmed `malicious` samples. Exclude `unknown` samples from training.

### Evaluation Strategy

Do not rely only on random row-level splitting.

Use scenario-based evaluation:

```text
Train scenarios and test scenarios must be separated.
```

Track:

- malicious precision
- malicious recall
- malicious F1
- benign recall
- AUC-ROC
- AUC-PR
- confusion matrix
- worst-case scenario recall

Recommended target before private beta:

```text
malicious recall >= 0.75
benign recall >= 0.80
malicious F1 >= 0.70
```

---

## REST API Overview

Endpoint names may differ slightly depending on the current branch, but the backend should support these core routes:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/agents/enroll` | Enroll new agent using token |
| `POST` | `/agents/heartbeat` | Agent heartbeat |
| `POST` | `/telemetry` | Submit process/network telemetry |
| `GET` | `/agents` | List agents |
| `GET` | `/processes` | List process records |
| `GET` | `/alerts` | List alerts |
| `POST` | `/alerts/{id}/feedback` | Submit alert feedback |
| `GET` | `/feedback` | List feedback entries |
| `GET` | `/reports/alerts.csv` | Export alerts as CSV |
| `GET` | `/reports/telemetry.csv` | Export telemetry as CSV |
| `GET` | `/settings` | Runtime settings |
| `PUT` | `/settings` | Update settings |

When authentication is enabled, protected endpoints require:

```http
X-API-Key: <your-api-key>
```

Agent endpoints should use per-agent secrets after enrollment.

---

## Project Structure

```text
Voidwatch/
├── client/
│   ├── agent/                 # Windows endpoint agent
│   └── dashboard/             # Electron dashboard
│
├── server/
│   ├── backend/               # FastAPI API, database, scoring, reports
│   └── model/                 # ML training pipeline and datasets
│
├── tools/
│   └── collector/             # Standalone benign-data collector
│
├── docs/
│   ├── PRIVACY.md
│   ├── DATA_COLLECTION.md
│   └── SECURITY.md
│
├── README.md
├── .gitignore
└── docker-compose.yml
```

---

## Security Notes

Voidwatch handles sensitive endpoint telemetry. Treat it as a security product even during prototype development.

Minimum requirements for private beta:

- use HTTPS
- use per-agent secrets
- allow token revocation
- avoid committing secrets
- anonymize user paths where possible
- document exactly what is collected
- provide uninstall instructions
- keep raw datasets out of the public repository
- review false positives and false negatives manually

Never collect credentials, cookies, private files, messages, screenshots, or keystrokes.

---

## Repository Hygiene

Before publishing the repository, remove generated and private files:

```text
.git/ from exported ZIPs
.claude/
__pycache__/
node_modules/
build/
dist/
local databases
local model artifacts
raw datasets
stats generated from private experiments
agent secrets
.env files
collector executables if not intended for release
```

Recommended public repository contents:

```text
source code
documentation
sample config files
screenshots
README
license
setup instructions
```

Large datasets, model artifacts, and packaged executables should be released separately.

---

## Roadmap

### Short-Term

- fix backend startup/auth ordering issues
- clean public repository
- update README and documentation
- enable path anonymization by default for beta collection
- improve installer / one-click agent setup
- run multi-split scenario evaluation
- inspect false positives and false negatives

### Private Beta

- enroll 5–20 Windows testers
- collect 50–100 hours of clean benign telemetry
- add feedback-driven allowlist improvements
- improve dashboard explanation quality
- add PDF/CSV report exports
- deploy backend with HTTPS and PostgreSQL

### MVP

- packaged Windows agent installer
- organization/team support
- stable secure enrollment
- production database migrations
- alert investigation workflow
- pricing and pilot program
- documentation for labs and small teams

---

## Disclaimer

Voidwatch is an academic/startup prototype for defensive cybersecurity research, endpoint visibility, and controlled testing. It should only be used on systems where you have explicit permission.

Do not use Voidwatch for unauthorized monitoring, credential collection, surveillance, or activity that violates privacy, law, or institutional policy.

---

## Contact

Project: **Voidwatch**  
Founder/Developer: **Lev Vedrov**  
GitHub: `https://github.com/<your-username>`

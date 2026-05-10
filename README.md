# Voidwatch

Endpoint security monitoring system. A lightweight agent runs on monitored machines, collects process and network telemetry every 5 seconds, and sends it to a backend that scores each process using a hybrid rule engine + ML classifier. Threats are displayed in a desktop dashboard.

## Architecture

```
Agent (Python)
  └─ collects process + network telemetry every 5s
  └─ POST /telemetry → Backend

Backend (FastAPI + SQLite)
  └─ rule engine (MITRE-mapped scoring)
  └─ RandomForest classifier
  └─ alert deduplication (10-min window)
  └─ REST API → Dashboard

Dashboard (Electron)
  └─ starts backend + agent automatically on launch
  └─ Dashboard, Processes, MITRE ATT&CK views
```

## Requirements

- Python 3.11+
- Node.js 18+

```bash
pip install -r requirements.txt
cd dashboard && npm install
```

## Running

```bash
cd dashboard
npm start
```

The dashboard automatically starts the backend (port 8000) and agent. Allow ~3 seconds on first launch for the ML model to train.

## Authentication (optional)

Set `VOIDWATCH_API_KEY` on both the machine running the backend and all agent machines:

```bash
# Windows
$env:VOIDWATCH_API_KEY = "your-secret-key"

# Linux / macOS
export VOIDWATCH_API_KEY="your-secret-key"
```

If the variable is not set, the API accepts all requests (suitable for local/trusted networks).

## Risk Scoring

Each process is scored 0–150 using four components:

| Component | Description |
|---|---|
| Base score | Rule engine — MITRE-mapped detections (PowerShell abuse, LOLBins, persistence, etc.) |
| Correlation bonus | Behavioral chains — e.g. Office app spawning encoded PowerShell with network activity |
| Confidence modifier | Adjusts score up/down based on indicator strength and process context |
| Context modifier | Parent process type and execution path |

Alerts are generated at score ≥ 25. Risk levels: LOW / MEDIUM / HIGH / CRITICAL / SEVERE.

## ML Classifier

A RandomForest trained on synthetic labeled process data. Supplements (does not replace) the rule engine. Precision/recall/F1 metrics are printed to the console on each training run.

To retrain manually:
```bash
cd backend
python -c "from classifier import classifier; classifier.train()"
```

## API Endpoints

All endpoints require `X-API-Key` header if `VOIDWATCH_API_KEY` is set.

| Method | Path | Description |
|---|---|---|
| POST | `/telemetry` | Receive agent telemetry batch |
| GET | `/agents` | List registered agents |
| GET | `/processes` | List collected processes |
| GET | `/alerts` | List generated alerts |
| GET | `/timeline` | Alert event timeline |

## Project Structure

```
agent/
  main.py             — entry point, collect loop
  telemetry.py        — TelemetryEvent dataclass
  process_collector.py
  network_collector.py
  sender.py           — HTTP POST to backend
  config.py           — SERVER_URL, API_KEY, AGENT_ID

backend/
  main.py             — FastAPI app entry point
  api.py              — REST endpoints, auth, deduplication
  scoring.py          — rule engine + correlation engine
  classifier.py       — RandomForest classifier + metrics
  features.py         — feature extraction
  database.py         — SQLAlchemy models + SQLite
  models.py           — Pydantic schemas

dashboard/
  main.js             — Electron entry, spawns backend + agent
  app.js              — router, window controls, status bar
  pages/
    dashboard.js      — overview + high-risk processes
    processes.js      — full process list
    mitre.js          — MITRE ATT&CK technique mapping
```

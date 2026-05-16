# Voidwatch

Windows endpoint detection and response system. A lightweight Python agent collects process and network telemetry every 5 seconds and sends it to a FastAPI backend, which scores each process through a hybrid pipeline — a MITRE ATT&CK-mapped rule engine combined with a calibrated RandomForest classifier. Threats are surfaced in an Electron dashboard with real-time updates.

---

## Screenshots

![Dashboard](docs/screenshots/dashboard.png)
![Processes](docs/screenshots/processes.png)
![Alerts](docs/screenshots/alerts.png)
![Training Stats](backend/stats/training_curves.png)

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Backend Server                     │
│                                                       │
│  FastAPI  ──►  SQLAlchemy ORM  ──►  PostgreSQL/SQLite │
│                                                       │
│  /telemetry  ──►  score_batch()                       │
│                     ├── rule_engine()   (0–100 pts)   │
│                     └── classifier()   (+0–50 pts)    │
│                           ├── RF.predict_proba()      │
│                           └── IsotonicRegression()    │
└───────────────────────────┬──────────────────────────┘
                            │ HTTP REST
            ┌───────────────┴───────────────┐
            │                               │
     ┌──────▼──────┐                 ┌──────▼──────┐
     │  Dashboard   │                 │  Dashboard   │
     │  (Electron)  │                 │  (Electron)  │
     │  + Agent     │                 │  + Agent     │
     │  (Python)    │                 │  (Python)    │
     └─────────────┘                 └─────────────┘
```

**Backend** binds `0.0.0.0`, configured entirely via environment variables. Supports any number of simultaneous agents.

**Agent** runs as a subprocess spawned by the dashboard on launch. Collects process list + per-process network connections via `psutil`, sends telemetry batches to the backend every 5 seconds. Sends a heartbeat on each cycle before collection completes.

**Dashboard** is an Electron app. Server URL is stored in `userData/voidwatch-config.json` and synced to `localStorage` on startup. All API calls use the stored URL dynamically — no hardcoded base address.

---

## Scoring Pipeline

Each telemetry batch goes through `score_batch()` in `scoring.py`:

### 1. Rule Engine (`0–100 pts`)

Evaluates deterministic behavioral rules mapped to MITRE ATT&CK techniques:

| Rule | Points | Technique |
|---|---|---|
| Encoded PowerShell (`-enc`, `-EncodedCommand`) | 35 | T1027.010 |
| `IEX` / `Invoke-Expression` | 30 | T1059.001 |
| Execution policy bypass | 25 | T1059.001 |
| Download cradle (`WebClient`, `wget`, `curl`) | 30 | T1105 |
| Hidden window (`-WindowStyle Hidden`) | 20 | T1059.001 |
| Office app spawning shell | 40 | T1566 |
| Browser spawning shell | 35 | T1204 |
| `mshta.exe` with network | 40 | T1218.005 |
| `rundll32.exe` with network | 35 | T1218.011 |
| `regsvr32.exe` with network | 35 | T1218.010 |
| `certutil.exe` download | 40 | T1105 |
| Registry persistence | 40 | T1547.001 |
| Scheduled task creation | 35 | T1053.005 |
| Suspicious port (4444, 1337, 31337…) | 30 | T1071 |
| Temp/Downloads execution | 20 | T1204 |

### 2. ML Additive (`+0–50 pts`)

```python
ml_addon = round((ml_proba - 0.55) * 50)  # only adds if proba > 0.55
risk_score = rule_score + max(0, ml_addon)
```

### 3. Context Modifier

Multipliers applied before final score to suppress known-good processes:

| Class | Multiplier | Examples |
|---|---|---|
| Critical system | `× 0.05` | lsass, csrss, wininit, smss, winlogon |
| Driver processes | `× 0.10` | nvdisplay, lghub, corsairservice, msiafterburner |
| Security software | `× 0.20` | MsMpEng, SecurityHealthService |
| Known browsers | `× 0.40` | chrome, msedge, firefox |
| Dev tools | `× 0.50` | code, python, node, git |

Final `risk_score >= 50` → alert generated and stored in `AlertRecord`.

---

## ML Classifier

**Model:** `sklearn.ensemble.RandomForestClassifier`
- `n_estimators=200`, `max_depth=14`, `min_samples_leaf=2`
- `class_weight={0: 1, 1: 4}`

**Calibration:** `sklearn.isotonic.IsotonicRegression`
- 10% of training data held out for calibration
- Applied post-hoc to RF raw probabilities

**Training data:**
- [OTRF Security Datasets](https://github.com/OTRF) — 100+ real attack scenarios (ZIP/tar.gz)
- Benign: process snapshots collected from live Windows machines via `collect_benign.py`
- Synthetic: hand-crafted feature vectors for edge cases (signed LOLBINs, critical system processes, driver processes)

**Train/test split:** `GroupShuffleSplit` on scenario groups — entire attack scenarios go to either train or test, never split across both.

**Features (31 total):**

```
is_powershell         has_encoded_cmd        has_download_cmd
has_iex               has_ep_bypass          has_hidden_window
is_mshta              is_rundll32            is_regsvr32
is_certutil           is_office_parent       is_browser_parent
is_script_host_parent from_temp              from_downloads
from_appdata_roaming  from_system32          from_program_files
is_signed             connection_count       has_suspicious_port
has_registry_persist  has_sched_task         is_known_dev_tool
is_known_browser      cmd_is_long            suspicious_flag_count
uses_common_dev_port  has_discovery_cmd      has_lateral_movement_cmd
has_credential_dump_cmd
```

`suspicious_flag_count` is a normalized composite: sum of 9 independent behavioral flags divided by 9.

`has_credential_dump_cmd` excludes critical system processes from self-matching on their own name in the command line path.

---

## REST API

All endpoints except `/health` and `GET /settings` require `X-API-Key` header when `VOIDWATCH_API_KEY` is set.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `POST` | `/register` | Agent registration + metadata |
| `POST` | `/telemetry` | Process batch ingestion + scoring |
| `GET` | `/processes` | Query process records |
| `GET` | `/alerts` | Query alert records |
| `GET` | `/agents` | List registered agents |
| `GET` | `/timeline` | Flattened alert event timeline |
| `GET` | `/settings` | Runtime settings |
| `PUT` | `/settings` | Update retention config |
| `GET` | `/settings/stats` | DB record counts + size |
| `POST` | `/settings/prune` | Manual retention prune |

Alert deduplication: identical `(agent_id, process_name, risk_level)` within 10 minutes is dropped.

---

## Quick Start

### Backend

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env        # configure DATABASE_URL, PORT, API key
python main.py
```

**Train the model first:**
```bash
python -X utf8 train.py
# outputs: model/voidwatch_rf.joblib
#          model/voidwatch_scaler.joblib
#          model/voidwatch_calibrator.joblib
#          stats/training_history.csv
#          stats/training_curves.png
```

### Dashboard + Agent

```bash
cd dashboard
npm install
npm start
```

Dashboard spawns the agent automatically on startup, passing `VOIDWATCH_SERVER_URL` and `VOIDWATCH_API_KEY` as environment variables.

Server URL is configured in **Settings → Server Connection**.

---

## Configuration

### `backend/.env`

```env
DATABASE_URL=sqlite:///./voidwatch.db
# DATABASE_URL=postgresql://user:password@localhost:5432/voidwatch
HOST=0.0.0.0
PORT=8000
VOIDWATCH_API_KEY=
CORS_ORIGINS=*
```

PostgreSQL requires `psycopg2-binary`. Connection pool: `pool_size=10`, `max_overflow=20`, `pool_recycle=300`.

### Agent env vars

| Variable | Default |
|---|---|
| `VOIDWATCH_SERVER_URL` | `http://localhost:8000` |
| `VOIDWATCH_API_KEY` | *(empty)* |

Agent ID is persisted to `agent/.agent_id` (falls back to `~/.voidwatch/.agent_id`). Format: `{hostname}-{uuid4[:8]}`.

---

## Project Structure

```
voidwatch/
├── backend/
│   ├── main.py           # FastAPI lifespan, CORS, pruner thread
│   ├── api.py            # All route handlers
│   ├── database.py       # SQLAlchemy models + engine (PG/SQLite)
│   ├── classifier.py     # RF model, calibration, train_on(), load()
│   ├── features.py       # extract() — ProcessData → float[31]
│   ├── scoring.py        # score_batch(), rule engine, context modifier
│   ├── models.py         # Pydantic I/O schemas
│   ├── train.py          # CLI training script, OTRF loader
│   ├── collect_benign.py # Benign snapshot collector
│   ├── settings.py       # JSON-backed runtime settings
│   ├── requirements.txt
│   ├── .env.example
│   ├── datasets/otrf/
│   │   ├── attack/       # ZIP/tar.gz attack scenarios
│   │   └── benign/       # JSON benign snapshots
│   ├── model/            # joblib artifacts
│   └── stats/            # training_history.csv, PNG graphs
├── dashboard/
│   ├── main.js           # Electron main, IPC handlers, agent spawn
│   ├── preload.js        # contextBridge — config IPC + window controls
│   ├── api.js            # fetch wrapper, _serverUrl(), utilities
│   ├── app.js            # startup sequence, router, status bar
│   └── pages/
│       ├── dashboard.js  # Overview, high-risk panel, ML distribution
│       ├── processes.js  # Process table
│       ├── alerts.js     # Alert list with MITRE tags
│       ├── mitre.js      # ATT&CK technique heatmap
│       └── settings.js   # Server URL, API key, retention, DB stats
└── agent/
    ├── main.py               # Heartbeat + collection loop (5s interval)
    ├── process_collector.py  # psutil enumeration + PE signature check
    ├── network_collector.py  # Per-PID connection tracking
    ├── metadata.py           # hostname, OS, IP, username
    ├── sender.py             # POST /register, POST /telemetry
    ├── telemetry.py          # TelemetryEvent dataclass
    └── config.py             # SERVER_URL + API_KEY from env
```

---

## Requirements

| Component | Requirement |
|---|---|
| Backend | Python 3.9+ |
| Agent | Python 3.9+, Windows 10/11 |
| Dashboard | Node.js 18+, npm |
| PostgreSQL driver | `psycopg2-binary` (optional) |

---

## License

MIT

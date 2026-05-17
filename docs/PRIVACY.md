# Voidwatch Privacy Policy

**Effective date:** see git history  
**Applies to:** Voidwatch EDR agent, backend server, and dashboard

---

## What data is collected

The Voidwatch agent collects **system telemetry** from the machine it runs on:

| Data type | Examples | Purpose |
|-----------|----------|---------|
| Process name & path | `cmd.exe`, `C:\Windows\System32\cmd.exe` | Threat detection |
| Process ID and parent PID | `1234`, `5678` | Process tree analysis |
| Command-line arguments | `cmd.exe /c whoami` | Behavioral scoring |
| Network connections | destination IP, port, protocol | C2 detection |
| CPU and memory usage | % CPU, MB RAM | Anomaly baseline |
| Timestamp | UTC datetime | Event correlation |
| Hostname | machine name | Agent identification |
| Username | Windows user | Audit trail |
| OS platform | `win32` | Feature extraction |

**What is NOT collected:**

- File contents or document text
- Passwords, credentials, or clipboard data
- Browser history or cookies
- Screenshots or video
- Email or messaging content
- Personal files outside of process telemetry

---

## How data is used

1. **Threat detection** — telemetry is scored by an ML model and rule engine to identify suspicious behavior.
2. **Alert generation** — high-risk events are stored as alerts for analyst review.
3. **Model improvement** — analyst feedback (true positive / false positive labels) is used to retrain the classifier.
4. **Audit and reporting** — CSV exports are available for compliance and incident response.

Data is **never sold** to third parties and is **never transmitted** outside your Voidwatch server instance.

---

## Data retention

| Data | Default retention |
|------|------------------|
| Process telemetry | 7 days |
| Alerts | 30 days |
| Feedback labels | Indefinite (used for retraining) |
| Enrollment tokens | Until manually deleted |

Retention periods are configurable in Settings. Data pruning runs automatically every hour.

---

## Data storage

- All data is stored in the Voidwatch backend database (SQLite by default, PostgreSQL optional).
- Data is stored **on-premises** — Voidwatch does not use cloud storage or external APIs.
- Transport between agent and server uses HTTP (or HTTPS if you configure a reverse proxy with TLS).

---

## Access control

- The backend API is protected by an API key (set `VOIDWATCH_API_KEY` in `.env`).
- Each agent uses a unique per-agent secret issued at enrollment time.
- Revoked agents cannot submit telemetry.

---

## Anonymization option

The agent supports `anonymize_paths: true` in `config.json`, which replaces user home directory paths (e.g. `C:\Users\john\`) with `C:\Users\[user]\` before transmission.

---

## Contact

For privacy questions or data deletion requests, contact the Voidwatch administrator in your organization.

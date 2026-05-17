# Voidwatch Security Guide

## Authentication

### Admin API key

Set `VOIDWATCH_API_KEY` in `.env` to a strong random string (min 32 chars).  
Every dashboard and direct API request must include `X-API-Key: <key>` header.

Generate a key:
```
python -c "import secrets; print(secrets.token_hex(32))"
```

### Per-agent authentication

Each agent enrolled via token receives a unique `agent_secret` (64-char hex string).  
The agent sends `X-Agent-ID` and `X-Agent-Secret` headers with every request.  
Revoked agents are rejected at the auth layer before any DB write.

---

## Transport security

By default Voidwatch uses plain HTTP. For production deployments, place a reverse proxy with TLS in front of the backend.

**nginx example (minimum config):**
```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/ssl/voidwatch/cert.pem;
    ssl_certificate_key /etc/ssl/voidwatch/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Then set `server_url` in the agent `config.json` to `https://your-server`.

---

## Network exposure

The backend binds to `0.0.0.0:8000` by default. Restrict access:

- **Firewall rule:** Allow inbound 8000 only from agent subnets + analyst workstations.
- **CORS:** Set `CORS_ORIGINS` to the exact dashboard origin (e.g. `http://192.168.1.10:8000`) instead of `*`.

---

## Secrets management

| Secret | Storage | Notes |
|--------|---------|-------|
| `VOIDWATCH_API_KEY` | `.env` file (backend) | Never commit to git |
| Per-agent secret | `.agent_secret` file (agent dir) | Written at enrollment, chmod 600 |
| Enrollment tokens | Database, hashed not stored plain | Single-use; support expiry |

The `.gitignore` excludes `.env`, `.agent_id`, and `.agent_secret`.

---

## Least privilege

- Run the backend as a non-root user. In Docker the `CMD` runs as root by default — add `USER nobody` to the Dockerfile if your environment permits.
- The Windows agent requires `SeDebugPrivilege` to enumerate all processes. Do not run it as SYSTEM unless required — a standard user with debug rights is sufficient.

---

## Allowlist

The allowlist (`/allowlist` API, Allowlist page) lets you suppress alerts for known-good processes or hashes. Entries are checked in the scoring pipeline before an alert is written.

Use this to:
- Suppress false positives from internal tooling
- Whitelist specific command-line patterns

---

## Threat model

Voidwatch is an **endpoint telemetry and detection** system, not a prevention system. It does not:
- Block process execution
- Modify firewall rules
- Quarantine files

An attacker with local admin access can stop the agent (`taskkill`), modify `config.json`, or delete `.agent_secret`. Treat agent availability as an integrity signal — a missing heartbeat is itself a detection.

---

## Incident response

1. **Revoke** the affected agent from the Agents page (prevents further telemetry submissions).
2. **Export** alerts CSV for the affected agent (`/reports/alerts.csv?agent_id=<id>`).
3. **Review** telemetry in the Processes and MITRE ATT&CK pages filtered by agent.
4. **Rotate** `VOIDWATCH_API_KEY` and re-enroll unaffected agents if the key may be compromised.

---

## Dependency security

Keep Python packages updated:
```
pip install --upgrade -r backend/requirements.txt
```

The backend uses:
- **FastAPI / uvicorn** — ASGI framework
- **SQLAlchemy** — ORM (parameterized queries, no raw SQL string formatting)
- **scikit-learn** — ML inference
- **pydantic v2** — input validation on all API payloads

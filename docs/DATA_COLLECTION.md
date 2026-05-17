# Voidwatch Data Collection Reference

This document describes every field the agent sends to the server and how it is used.

---

## Telemetry payload (`POST /telemetry`)

Each collection cycle (default: every 10 seconds) the agent sends a JSON array of process snapshots.

### Per-process fields

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| `pid` | int | `psutil.Process.pid` | Process ID |
| `name` | str | `psutil.Process.name()` | Executable name |
| `exe` | str | `psutil.Process.exe()` | Full path; may be empty if access denied |
| `cmdline` | str | `psutil.Process.cmdline()` | Space-joined args; empty if `collect_command_line: false` |
| `ppid` | int | `psutil.Process.ppid()` | Parent PID |
| `parent_name` | str | parent's `name()` | Resolved locally on agent |
| `username` | str | `psutil.Process.username()` | DOMAIN\user format on Windows |
| `cpu_percent` | float | `psutil.Process.cpu_percent()` | Sampled over collection interval |
| `mem_mb` | float | `psutil.Process.memory_info().rss` | Resident set size in MB |
| `connections` | int | `psutil.Process.net_connections()` | Count of open TCP/UDP connections |
| `timestamp` | str | `datetime.utcnow().isoformat()` | UTC, no timezone suffix |

### Network connection fields (optional, requires `collect_network: true`)

| Field | Type | Notes |
|-------|------|-------|
| `remote_ip` | str | Remote IP address |
| `remote_port` | int | Remote port |
| `protocol` | str | `tcp` or `udp` |
| `status` | str | Connection state (e.g. `ESTABLISHED`) |

---

## Agent heartbeat

The agent sends a lightweight heartbeat via the telemetry endpoint every cycle. The server uses the `last_seen` timestamp to determine online/offline status.

---

## Enrollment payload (`POST /agents/enroll`)

Sent once during installation:

| Field | Notes |
|-------|-------|
| `token` | Single-use enrollment token |
| `hostname` | `socket.gethostname()` |
| `os` | `sys.platform` |
| `ip` | Primary Ethernet adapter IP |
| `username` | Home directory owner name |

---

## What is filtered on the agent

The agent skips processes where:
- `pid == 0` (Idle process)
- `pid == 4` (System process on Windows)
- `name` is empty (kernel threads)
- Access to process attributes is denied (`AccessDenied` exception)

---

## Agent configuration fields

`config.json` in the agent directory:

| Key | Default | Description |
|-----|---------|-------------|
| `server_url` | `http://localhost:8000` | Backend URL |
| `api_key` | `""` | Admin API key (alternative to per-agent secret) |
| `mode` | `detect` | `collect_only`, `detect`, or `debug` |
| `collection_interval` | `10` | Seconds between telemetry cycles |
| `collect_command_line` | `true` | Include process command-line arguments |
| `collect_network` | `true` | Include network connection counts |
| `anonymize_paths` | `false` | Replace user home path with `[user]` |

---

## Operating modes

| Mode | Behavior |
|------|---------|
| `collect_only` | Telemetry stored, no ML scoring, no alerts generated |
| `detect` | Telemetry stored, ML scoring runs, alerts generated for ML ≥ 0.8 |
| `debug` | Same as detect; additional verbose logging on the agent |

Modes can be changed remotely from the Agents page in the dashboard.

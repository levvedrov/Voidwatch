from models import ProcessData

SUSPICIOUS_PARENTS = {"cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "wmic.exe"}
SUSPICIOUS_PATHS   = ["\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp\\"]
ALERT_THRESHOLD    = 0.5


def score_process(proc: ProcessData) -> tuple[float, list[str]]:
    score = 0.0
    reasons = []
    name = proc.name.lower()
    cmd  = proc.command_line.lower()
    path = proc.path.lower()

    if name == "powershell.exe":
        score += 0.3
        reasons.append("PowerShell execution")

    if "-enc" in cmd or "-encodedcommand" in cmd:
        score += 0.5
        reasons.append("Encoded command argument")

    if proc.parent_name.lower() in SUSPICIOUS_PARENTS:
        score += 0.4
        reasons.append(f"Spawned by suspicious parent: {proc.parent_name}")

    if any(p in path for p in SUSPICIOUS_PATHS):
        score += 0.4
        reasons.append("Executed from suspicious path")

    if not proc.is_signed:
        score += 0.2
        reasons.append("Unsigned binary")

    if proc.connection_count > 0:
        score += min(0.1 * proc.connection_count, 0.4)
        reasons.append(f"Active network connections: {proc.connection_count}")

    return round(min(score, 1.0), 3), reasons


def score_batch(agent_id: str, processes: list[ProcessData]) -> list[dict]:
    alerts = []
    for proc in processes:
        score, reasons = score_process(proc)
        if score >= ALERT_THRESHOLD:
            alerts.append({
                "agent_id":     agent_id,
                "pid":          proc.pid,
                "process_name": proc.name,
                "reason":       "; ".join(reasons),
                "score":        score,
            })
    return alerts

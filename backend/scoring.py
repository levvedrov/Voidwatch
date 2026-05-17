"""
Voidwatch scoring engine — 4-part model:
  Final Risk = (Base + Correlation) × Confidence × Context   [capped 150]

Pipeline:
  Telemetry → Rule Engine → Feature Extraction → ML Classifier
           → Correlation Engine → Confidence Engine → Explainability → Alert
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from models import ProcessData

# ---------------------------------------------------------------------------
# Reference sets
# ---------------------------------------------------------------------------
OFFICE_APPS     = {"winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","msaccess.exe","mspub.exe"}
BROWSERS        = {"chrome.exe","firefox.exe","msedge.exe","iexplore.exe","opera.exe","brave.exe","safari.exe"}
SCRIPT_HOSTS    = {"wscript.exe","cscript.exe","mshta.exe","powershell.exe","powershell_ise.exe","cmd.exe"}
SYSTEM32_PATHS  = ["\\windows\\system32\\","\\windows\\syswow64\\"]
PROGFILES_PATHS = ["\\program files\\","\\program files (x86)\\"]
TEMP_PATHS      = ["\\temp\\","\\tmp\\"]
SUSPICIOUS_PATHS = TEMP_PATHS + ["\\downloads\\","\\appdata\\roaming\\","\\appdata\\local\\temp\\"]
SUSPICIOUS_PORTS = {4444,1337,8888,9001,31337,6666,5555,2222}
KNOWN_BAD_HASHES: set[str] = set()

# Trusted process baselines — reduce severity unless strong behavioral evidence is present.
# These processes can still be malicious when abused (e.g. encoded PowerShell, Office parent).
DEFENDER_PROCS = {"msmpeng.exe","nissrv.exe","securityhealthservice.exe",
                  "securityhealthhost.exe","mssense.exe","senseir.exe"}
BROWSER_PROCS  = {"chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe"}
DEV_TOOL_PROCS = {"code.exe","python.exe","python3.exe","node.exe","npm.exe","electron.exe",
                  "openconsole.exe","windowsterminal.exe","wt.exe","git.exe",
                  "git-remote-https.exe","devenv.exe","rider64.exe"}
CRITICAL_SYSTEM_PROCS = {
    "lsass.exe","csrss.exe","wininit.exe","smss.exe","winlogon.exe",
    "services.exe","spoolsv.exe","system","registry","ntoskrnl.exe",
    "system idle process","memory compression","secure system",
}
DRIVER_PROCS = {
    "nvdisplay.container.exe","nvcplui.exe","nvtelemetrycontainer.exe",
    "lghub.exe","lghub_agent.exe","lghub_updater.exe",
    "razer synapse service.exe","razercentralservice.exe",
    "corsairservice.exe","icue.exe",
    "steelserieshid.exe","steelseriesengine3.exe",
    "amdrsserv.exe","amdow.exe","radeoninstaller.exe",
    "rivatuner.exe","msiafterburner.exe","rtss.exe",
}

ALERT_THRESHOLD = 25   # MEDIUM+

RISK_LEVELS = [(120,"SEVERE"),(80,"CRITICAL"),(50,"HIGH"),(25,"MEDIUM"),(0,"LOW")]

# ---------------------------------------------------------------------------
# Telemetry priority tiers (used in timeline tagging)
# ---------------------------------------------------------------------------
PRIORITY_HIGH   = {"process_creation","command_line","parent_child","network_connection","powershell","registry","scheduled_task"}
PRIORITY_MEDIUM = {"file_creation","dll_load","entropy","cpu_spike"}
PRIORITY_LOW    = {"ram_usage","thread_count","browser_traffic"}


def _risk_level(score: int) -> str:
    for thr, lvl in RISK_LEVELS:
        if score >= thr:
            return lvl
    return "LOW"


def _confidence_label(mod: float) -> str:
    if mod >= 0.9:
        return "HIGH"
    if mod >= 0.65:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Part 1 — Base Severity Score
# ---------------------------------------------------------------------------
def _base(proc: ProcessData) -> tuple[float, list[str], list[str]]:
    score = 0.0
    reasons: list[str] = []
    mitre:   list[str] = []

    name   = proc.name.lower()
    cmd    = proc.command_line.lower()
    path   = proc.path.lower()
    parent = proc.parent_name.lower()

    if proc.sha256 and proc.sha256 in KNOWN_BAD_HASHES:
        score += 100
        reasons.append("Known malicious file hash")
        mitre.append("T1204")

    if name == "powershell.exe":
        score += 15
        reasons.append("PowerShell execution")
        mitre.append("T1059.001")

    if parent in OFFICE_APPS and name in {"powershell.exe","cmd.exe","wscript.exe","cscript.exe"}:
        score += 50
        reasons.append(f"Office application ({proc.parent_name}) spawned shell — high-risk chain")
        mitre += ["T1566","T1059"]

    if "-enc" in cmd or "-encodedcommand" in cmd:
        score += 45
        reasons.append("Encoded command argument (-EncodedCommand / -enc) — obfuscated payload")
        mitre += ["T1059.001","T1027"]

    if name == "powershell.exe" and any(k in cmd for k in ["downloadstring","downloadfile","webclient","invoke-webrequest","wget","curl"]):
        score += 45
        reasons.append("PowerShell download command — remote payload retrieval")
        mitre += ["T1059.001","T1105"]

    if "-executionpolicy bypass" in cmd or "-ep bypass" in cmd:
        score += 35
        reasons.append("PowerShell ExecutionPolicy bypass — defense evasion")
        mitre.append("T1059.001")

    if "-windowstyle hidden" in cmd or "-w hidden" in cmd:
        score += 30
        reasons.append("Hidden PowerShell window — concealed execution")
        mitre.append("T1059.001")

    if "iex(" in cmd or "iex " in cmd or "invoke-expression" in cmd:
        score += 40
        reasons.append("Invoke-Expression (IEX) — in-memory code execution without disk artifact")
        mitre += ["T1059.001","T1027"]

    if name == "mshta.exe" and any(k in cmd for k in ["http://","https://","vbscript:","javascript:"]):
        score += 45
        reasons.append("mshta.exe executing remote or inline script")
        mitre.append("T1218.005")

    if name == "rundll32.exe" and ("javascript:" in cmd or "http" in cmd):
        score += 35
        reasons.append("rundll32.exe with suspicious arguments")
        mitre.append("T1218.011")

    if name == "regsvr32.exe" and "/s" in cmd and ("http" in cmd or "/u" in cmd):
        score += 45
        reasons.append("regsvr32.exe executing remote script (Squiblydoo technique)")
        mitre.append("T1218.010")

    if name == "certutil.exe" and any(k in cmd for k in ["-urlcache","-decode","-decodehex"]):
        score += 40
        reasons.append("certutil.exe used for download or decode — LOLBin abuse")
        mitre += ["T1140","T1105"]

    if any(k in cmd for k in ["reg add","currentversion\\run","currentversion\\runonce"]):
        score += 55
        reasons.append("Registry Run/RunOnce persistence key modification")
        mitre.append("T1547.001")

    if (name in {"schtasks.exe","at.exe"} and "/create" in cmd) or "new-scheduledtask" in cmd:
        score += 50
        reasons.append("Scheduled task creation — persistence mechanism")
        mitre.append("T1053.005")

    if any(p in path for p in TEMP_PATHS):
        score += 35
        reasons.append("Executable launched from Temp directory")
        mitre.append("T1204")
    elif "\\downloads\\" in path:
        score += 20
        reasons.append("Executable launched from Downloads directory")
        mitre.append("T1204")
    elif "\\appdata\\roaming\\" in path:
        score += 30
        reasons.append("Executable launched from AppData\\Roaming — unusual execution path")
        mitre.append("T1036")

    _trusted_path = path and any(p in path for p in SYSTEM32_PATHS + PROGFILES_PATHS)
    if not proc.is_signed and path and not _trusted_path:
        score += 25
        reasons.append("Unsigned executable — no code signing certificate")

    if not proc.is_signed and path and not _trusted_path and proc.connection_count > 0:
        score += 25
        reasons.append("Unsigned process with active network connections")
        mitre.append("T1071")

    hit_ports = [p for p in proc.destination_ports if p in SUSPICIOUS_PORTS]
    if hit_ports:
        score += 20
        reasons.append(f"Connection to known suspicious port(s): {hit_ports}")
        mitre.append("T1071")

    # High-entropy name: only fire when ALSO running from a suspicious path AND has network
    # (avoids false positives on python.exe, msedge.exe, chrome.exe, etc.)
    if (re.match(r'^[a-z0-9]{8,12}\.exe$', name) and not proc.is_signed
            and any(p in path for p in SUSPICIOUS_PATHS) and proc.connection_count > 0):
        score += 30
        reasons.append("Random-looking name from suspicious path with network — C2 dropper pattern")
        mitre.append("T1036")

    # User-installed script interpreter with active outbound connections.
    # python.exe/node.exe installed under AppData (default python.org Windows installer path)
    # making network connections is a common Python RAT / C2 agent pattern.
    _INTERP = {"python.exe", "python3.exe", "node.exe"}
    if (name in _INTERP and proc.connection_count > 0 and path
            and "\\appdata\\local\\" in path
            and not any(p in path for p in PROGFILES_PATHS)):
        score += 55
        reasons.append(
            f"User-installed script interpreter ({proc.name}) with active network connections — "
            "common Python/Node RAT staging pattern (T1059.006)"
        )
        mitre += ["T1059.006", "T1071"]

    return score, reasons, list(dict.fromkeys(mitre))


# ---------------------------------------------------------------------------
# Part 2 — Confidence Modifier
# ---------------------------------------------------------------------------
def _confidence(proc: ProcessData, reasons: list[str]) -> tuple[float, str]:
    cmd    = proc.command_line.lower()
    parent = proc.parent_name.lower()
    path   = proc.path.lower()

    is_encoded    = "-enc" in cmd or "iex" in cmd or "invoke-expression" in cmd
    is_office_par = parent in OFFICE_APPS
    is_ms_system  = proc.is_signed and any(p in path for p in SYSTEM32_PATHS)
    is_normal_app = proc.is_signed and any(p in path for p in PROGFILES_PATHS)

    if is_office_par and is_encoded:
        return 1.3, "Exact suspicious chain matched: Office parent + encoded/IEX shell"
    if len(reasons) >= 3:
        return 1.2, "Multiple corroborating indicators"
    if is_ms_system:
        return 0.6, "Trusted Microsoft signed system binary"
    if is_normal_app:
        return 0.5, "Signed application in standard Program Files path"
    if not proc.command_line.strip():
        return 0.7, "Missing command line data — lower certainty"
    if len(reasons) == 1:
        return 0.8, "Single weak indicator"
    return 1.0, "Standard confidence"


# ---------------------------------------------------------------------------
# Part 3 — Context Modifier
# ---------------------------------------------------------------------------
def _context(proc: ProcessData) -> tuple[float, list[str]]:
    name   = proc.name.lower()
    parent = proc.parent_name.lower()
    path   = proc.path.lower()
    cmd    = proc.command_line.lower()
    notes: list[str] = []
    mod = 1.0

    if parent in OFFICE_APPS:
        mod *= 1.4; notes.append("Parent is Office application")
    elif parent in BROWSERS:
        mod *= 1.2; notes.append("Parent is browser")
    elif parent in SCRIPT_HOSTS:
        mod *= 1.3; notes.append("Parent is script host")

    if any(p in path for p in SUSPICIOUS_PATHS):
        mod *= 1.3; notes.append("Executing from Temp or AppData")

    if proc.is_signed and any(p in path for p in SYSTEM32_PATHS):
        mod *= 0.6; notes.append("Signed system binary in System32")
    elif proc.is_signed and any(p in path for p in PROGFILES_PATHS):
        mod *= 0.8; notes.append("Signed application in Program Files")

    # Trusted process baseline — reduce score unless behavioral evidence present.
    # Suppression is bypassed when: running from suspicious path, spawned by Office,
    # or using encoded/download commands (process is being abused).
    _INTERP = {"python.exe", "python3.exe", "node.exe"}
    _has_strong_signal = (
        any(p in path for p in SUSPICIOUS_PATHS)
        or parent in OFFICE_APPS
        or any(k in cmd for k in ["-enc", "-encodedcommand", "iex", "invoke-expression",
                                   "downloadstring", "downloadfile"])
        # User-installed interpreter (AppData, not Program Files) with network = bypass suppression
        or (name in _INTERP and proc.connection_count > 0
            and "\\appdata\\local\\" in path
            and not any(p in path for p in PROGFILES_PATHS))
    )
    if not _has_strong_signal:
        if name in CRITICAL_SYSTEM_PROCS:
            mod *= 0.05; notes.append(f"Critical Windows system process — heavily suppressed")
        elif name in DRIVER_PROCS:
            mod *= 0.1; notes.append(f"Known driver/peripheral process — suppressed")
        elif name in DEFENDER_PROCS:
            mod *= 0.2; notes.append(f"Microsoft Defender component — heavily suppressed")
        elif name in BROWSER_PROCS:
            mod *= 0.4; notes.append(f"Trusted browser — score reduced")
        elif name in DEV_TOOL_PROCS:
            mod *= 0.5; notes.append(f"Developer tool — score reduced")

    return round(mod, 3), notes


# ---------------------------------------------------------------------------
# Part 4 — Correlation Engine (behavioral chains)
# ---------------------------------------------------------------------------
def _correlation(proc: ProcessData, all_procs: list[ProcessData]) -> tuple[float, list[str], list[str]]:
    bonus   = 0.0
    reasons: list[str] = []
    mitre:   list[str] = []

    name   = proc.name.lower()
    cmd    = proc.command_line.lower()
    parent = proc.parent_name.lower()
    path   = proc.path.lower()

    has_network  = proc.connection_count > 0
    has_encoded  = "-enc" in cmd or "iex" in cmd or "invoke-expression" in cmd
    from_temp    = any(p in path for p in TEMP_PATHS)
    office_par   = parent in OFFICE_APPS

    if name == "powershell.exe" and has_network and has_encoded:
        bonus += 35; reasons.append("Behavioral chain: PowerShell + encoded command + network activity")
        mitre += ["T1059.001","T1105"]

    if office_par and has_network:
        bonus += 40; reasons.append("Behavioral chain: Office-spawned process with outbound network (T1566 pattern)")
        mitre += ["T1566","T1059"]

    if not proc.is_signed and has_network and from_temp:
        bonus += 35; reasons.append("Behavioral chain: unsigned process from Temp with network connections")
        mitre += ["T1204","T1071"]

    spawned_from_temp = any(
        p.parent_pid == proc.pid and any(t in p.path.lower() for t in TEMP_PATHS)
        for p in all_procs if p.pid != proc.pid
    )
    if spawned_from_temp:
        bonus += 20; reasons.append("Process spawned child executable from Temp directory")
        mitre.append("T1204")

    _PROC_MANAGERS = ({"svchost.exe","explorer.exe","services.exe","lsass.exe","csrss.exe","wininit.exe"}
                      | BROWSER_PROCS | DEV_TOOL_PROCS)
    child_count = sum(1 for p in all_procs if p.parent_pid == proc.pid)
    if child_count >= 5 and name not in _PROC_MANAGERS:
        bonus += 25; reasons.append(f"Process spawned {child_count} child processes in scan window")
        mitre.append("T1059")

    return bonus, reasons, list(dict.fromkeys(mitre))


# ---------------------------------------------------------------------------
# Threat Category
# ---------------------------------------------------------------------------
def _category(reasons: list[str], mitre: list[str]) -> str:
    r = " ".join(reasons).lower()
    m = set(mitre)

    if "T1547.001" in m or "T1053.005" in m:
        return "Persistence"
    if any(k in r for k in ["bypass","hidden window","obfusc","encoded","lolbin","squiblydoo"]):
        return "Defense Evasion"
    if m & {"T1218.005","T1218.010","T1218.011","T1140"}:
        return "Execution Abuse"
    if "T1566" in m:
        return "Initial Access / Phishing"
    if any(t.startswith("T1059") for t in m):
        return "Script Execution"
    if "T1071" in m:
        return "Suspicious Networking"
    if "T1003" in m:
        return "Credential Access"
    return "Suspicious Behavior"


# ---------------------------------------------------------------------------
# Event Timeline builder
# ---------------------------------------------------------------------------
def _timeline(proc: ProcessData, all_reasons: list[str]) -> list[dict]:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    events = [{"time": ts, "event": f"{proc.name} process observed", "priority": "HIGH"}]

    if proc.command_line.strip():
        events.append({"time": ts, "event": f"Command line captured: {proc.command_line[:120]}", "priority": "HIGH"})

    for reason in all_reasons:
        r = reason.lower()
        if "encoded" in r or "iex" in r:
            events.append({"time": ts, "event": reason, "priority": "HIGH"})
        elif "network" in r or "connection" in r:
            events.append({"time": ts, "event": reason, "priority": "HIGH"})
        elif "registry" in r or "scheduled" in r:
            events.append({"time": ts, "event": reason, "priority": "HIGH"})
        elif "unsigned" in r or "temp" in r or "download" in r:
            events.append({"time": ts, "event": reason, "priority": "MEDIUM"})
        else:
            events.append({"time": ts, "event": reason, "priority": "LOW"})

    return events


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def score_process(proc: ProcessData, all_procs: list[ProcessData], ml_proba: float = 0.0) -> dict:
    base_score, base_reasons, base_mitre = _base(proc)
    conf_mod,   conf_note                = _confidence(proc, base_reasons)
    ctx_mod,    ctx_notes                = _context(proc)
    corr_bonus, corr_reasons, corr_mitre = _correlation(proc, all_procs)

    # ML additive contribution: (proba - 0.40) × 50
    #   proba=0.95 → +27, proba=0.70 → +15, proba=0.40 → 0, proba=0.20 → -10
    ml_addon = round((ml_proba - 0.40) * 50)
    raw      = max(0.0, base_score + corr_bonus + ml_addon)
    adjusted = raw * conf_mod * ctx_mod
    final    = min(round(adjusted), 150)
    level    = _risk_level(final)

    all_reasons = base_reasons + corr_reasons + ctx_notes
    if conf_note:
        all_reasons.append(conf_note)
    if ml_proba >= 0.70:
        all_reasons.append(f"ML classifier: high malicious probability ({ml_proba:.0%})")
    elif ml_proba <= 0.20:
        all_reasons.append(f"ML classifier: low malicious probability ({ml_proba:.0%}) — likely benign")

    all_mitre = list(dict.fromkeys(base_mitre + corr_mitre))
    category  = _category(all_reasons, all_mitre)
    conf_label = _confidence_label(min(conf_mod, 1.0))
    timeline  = _timeline(proc, all_reasons)

    return {
        "process":             proc.name,
        "parent":              proc.parent_name,
        "risk_score":          final,
        "risk_level":          level,
        "confidence":          round(min(conf_mod, 1.0), 2),
        "confidence_label":    conf_label,
        "category":            category,
        "reasons":             all_reasons,
        "mitre":               all_mitre,
        "ml_score":            round(ml_proba, 3),
        "timeline":            timeline,
        "_base_score":         round(base_score, 1),
        "_correlation_bonus":  round(corr_bonus, 1),
        "_confidence_mod":     round(conf_mod, 3),
        "_context_mod":        round(ctx_mod, 3),
    }


def score_batch(agent_id: str, processes: list[ProcessData]) -> list[dict]:
    from classifier import classifier

    alerts = []
    for proc in processes:
        # rule engine first, then ML uses rule_score as a feature
        base_score = _base(proc)[0]
        ml_proba = classifier.predict_proba(proc)

        result = score_process(proc, processes, ml_proba=ml_proba)

        if result["risk_score"] >= ALERT_THRESHOLD:
            alerts.append({
                "agent_id":         agent_id,
                "pid":              proc.pid,
                "process_name":     result["process"],
                "parent_name":      result["parent"],
                "risk_score":       result["risk_score"],
                "risk_level":       result["risk_level"],
                "confidence":       result["confidence"],
                "confidence_label": result["confidence_label"],
                "category":         result["category"],
                "reasons":          result["reasons"],
                "mitre":            result["mitre"],
                "ml_score":         result["ml_score"],
                "timeline":         result["timeline"],
            })
    return alerts

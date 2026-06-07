"""
Parse OTRF Security Datasets and retrain the Voidwatch behavioral classifier.

Place downloaded ZIPs/tar.gz in:
  backend/datasets/otrf/attack/   <- malicious (label = 1, folder = ground truth)
  backend/datasets/otrf/benign/   <- benign    (label = 0)

Subdirectories are scanned recursively so you can keep the original
OTRF folder structure (attack/defense_evasion/host/*.zip, etc.)

Run from the backend folder:
  python train.py

Labeling strategy:
  - Attack datasets: every process event labeled 1 — folder origin is ground truth,
    no rule-engine filtering applied.
  - Benign datasets: every process event labeled 0.
  Both are combined with a synthetic baseline, then split at the scenario level
  (80 % train / 20 % test) so the model is evaluated on scenarios it never saw.

The classifier uses only behavioral features — rule_score_norm is NOT a feature.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np

try:
    import evtx as _evtx_lib
    _EVTX_AVAILABLE = True
except ImportError:
    _EVTX_AVAILABLE = False

_BACKEND = str(Path(__file__).resolve().parent.parent / "backend")
sys.path.insert(0, _BACKEND)

from classifier import ProcessClassifier, _VER_FILE, _MODEL_VER
from features import extract
from models import ProcessData

DATASETS_DIR = Path(__file__).parent / "datasets" / "otrf"
ATTACK_DIR   = DATASETS_DIR / "attack"
BENIGN_DIR   = DATASETS_DIR / "benign"

# EventIDs treated as process-creation events
_PROC_EIDS    = {1, 4688}
# EventIDs treated as network-connection events
_NET_EIDS     = {3, 5156}

# Processes that typically appear as background noise in attack logs.
# We skip them UNLESS they exhibit suspicious behavior — then they are real attack actors.
_BACKGROUND_IN_ATTACK = frozenset({
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "lsass.exe", "lsaiso.exe", "services.exe", "svchost.exe", "spoolsv.exe",
    "explorer.exe", "taskhostw.exe", "taskhost.exe", "dwm.exe", "conhost.exe",
    "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe",
    "searchindexer.exe", "searchhost.exe", "audiodg.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
})

_OFFICE_APPS  = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "onenote.exe"}
_SUSP_PATHS   = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                  "\\downloads\\", "\\programdata\\")
_LOLBINS      = {"mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
                  "bitsadmin.exe", "wmic.exe", "cmstp.exe", "installutil.exe"}


def _is_attack_related(proc) -> bool:
    """Return True if a process shows direct attack behavior (command-line or structural)."""
    name   = proc.name.lower()
    cmd    = proc.command_line.lower()
    path   = proc.path.lower()
    parent = proc.parent_name.lower()

    if any(k in cmd for k in ["-enc", "-encodedcommand", "frombase64string",
                                "iex", "invoke-expression"]):
        return True
    if any(k in cmd for k in ["downloadstring", "downloadfile", "invoke-webrequest",
                                "wget ", "curl ", "certutil", "bitsadmin", "mshta"]):
        return True
    if parent in _OFFICE_APPS and name in {"powershell.exe", "cmd.exe",
                                            "wscript.exe", "cscript.exe", "mshta.exe"}:
        return True
    if any(k in cmd for k in ["reg add", "currentversion\\run", "schtasks",
                                "new-scheduledtask", "startup"]):
        return True
    if any(k in cmd for k in ["ntdsutil", "vssadmin", "reg save",
                                "whoami", "net user", "nltest", "mimikatz"]):
        return True
    if "-executionpolicy bypass" in cmd or "-ep bypass" in cmd:
        return True
    if name in _LOLBINS:
        return True
    # Unsigned binary executing from suspicious path
    if not proc.is_signed and any(p in path for p in _SUSP_PATHS):
        return True
    # Unsigned binary with network connections outside trusted paths
    if (proc.connection_count > 0 and not proc.is_signed and path
            and not any(p in path for p in ("\\windows\\system32\\",
                                             "\\windows\\syswow64\\",
                                             "\\program files\\"))):
        return True
    return False


# ---------------------------------------------------------------------------
# Event parsing helpers — handles flat (Mordor) and winlogbeat formats
# ---------------------------------------------------------------------------

def _event_id(event: dict) -> int:
    if "winlog" in event:
        return int(event["winlog"].get("event_id", 0))
    return int(event.get("EventID", event.get("event_id", 0)))


def _field(event: dict, *keys: str) -> str:
    """Try winlog.event_data.KEY first, then top-level KEY."""
    if "winlog" in event:
        wd = event["winlog"].get("event_data", {})
        for k in keys:
            if k in wd:
                return str(wd[k])
    for k in keys:
        if k in event:
            return str(event[k])
    return ""


def _proc_name(image_path: str) -> str:
    return os.path.basename(image_path.replace("\\", "/")).lower()


def _sha256(hashes: str) -> str:
    for part in str(hashes).split(","):
        p = part.strip()
        if p.upper().startswith("SHA256="):
            return p[7:].lower()
    return ""


def _infer_signed(path: str) -> bool:
    p = path.lower()
    return any(x in p for x in (
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\program files\\",
        "\\program files (x86)\\",
    ))


def _parse_pid(s: str) -> int:
    """Parse decimal or 0x-prefixed hex PID string (EventID 4688 uses hex)."""
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


# ---------------------------------------------------------------------------
# NDJSON / JSON array parser
# ---------------------------------------------------------------------------

def _parse_ndjson(data: bytes) -> list[dict]:
    text = data.decode("utf-8", errors="replace").strip()
    if text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    events = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


def _classify_event(event: dict) -> tuple[str, int]:
    """Return ('proc'|'net'|'skip', event_id)."""
    eid = _event_id(event)
    if eid in _PROC_EIDS:
        return "proc", eid
    if eid in _NET_EIDS:
        return "net", eid
    return "skip", eid


# ---------------------------------------------------------------------------
# Archive parsers
# ---------------------------------------------------------------------------

def _parse_zip(zip_path: Path) -> tuple[list[dict], list[dict]]:
    """Return (process_events, network_events) from a ZIP."""
    proc, net = [], []
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not any(name.endswith(ext) for ext in (".json", ".ndjson", ".log")):
                continue
            raw = zf.read(name)
            for event in _parse_ndjson(raw):
                kind, _ = _classify_event(event)
                if kind == "proc":
                    proc.append(event)
                elif kind == "net":
                    net.append(event)
    return proc, net


def _parse_targz(tgz_path: Path) -> tuple[list[dict], list[dict]]:
    """Return (process_events, network_events) from a .tar.gz archive."""
    proc, net = [], []
    try:
        with tarfile.open(tgz_path, "r:gz") as tf:
            for member in tf.getmembers():
                if not any(member.name.endswith(ext) for ext in (".json", ".ndjson", ".log")):
                    continue
                f = tf.extractfile(member)
                if f is None:
                    continue
                raw = f.read()
                for event in _parse_ndjson(raw):
                    kind, _ = _classify_event(event)
                    if kind == "proc":
                        proc.append(event)
                    elif kind == "net":
                        net.append(event)
    except Exception:
        pass
    return proc, net


def _parse_plain(json_path: Path) -> tuple[list[dict], list[dict]]:
    """Return (process_events, network_events) from a plain JSON/NDJSON file."""
    proc, net = [], []
    raw = json_path.read_bytes()
    for event in _parse_ndjson(raw):
        kind, _ = _classify_event(event)
        if kind == "proc":
            proc.append(event)
        elif kind == "net":
            net.append(event)
    return proc, net


def _evtx_record_to_flat(record_json: str) -> dict | None:
    """Convert one evtx JSON record → flat dict matching Mordor format, or None."""
    try:
        obj = json.loads(record_json)
    except json.JSONDecodeError:
        return None

    event  = obj.get("Event", {})
    system = event.get("System", {})
    raw_eid = system.get("EventID", 0)
    if isinstance(raw_eid, dict):
        raw_eid = raw_eid.get("#text", 0)
    try:
        eid = int(raw_eid)
    except (ValueError, TypeError):
        return None

    if eid not in (_PROC_EIDS | _NET_EIDS):
        return None

    flat: dict[str, str] = {"EventID": str(eid)}
    event_data = event.get("EventData", {})
    data = event_data.get("Data", [])
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                name = item.get("#attributes", {}).get("Name", "")
                text = item.get("#text", "")
                if name:
                    flat[name] = str(text) if text is not None else ""
    elif isinstance(data, dict):
        name = data.get("#attributes", {}).get("Name", "")
        text = data.get("#text", "")
        if name:
            flat[name] = str(text) if text is not None else ""
    return flat


def _parse_evtx(evtx_path: Path) -> tuple[list[dict], list[dict]]:
    """Return (process_events, network_events) from a binary .evtx file."""
    if not _EVTX_AVAILABLE:
        return [], []
    proc, net = [], []
    try:
        parser = _evtx_lib.PyEvtxParser(str(evtx_path))
        for record in parser.records_json():
            flat = _evtx_record_to_flat(record["data"])
            if flat is None:
                continue
            kind, _ = _classify_event(flat)
            if kind == "proc":
                proc.append(flat)
            elif kind == "net":
                net.append(flat)
    except Exception:
        pass
    return proc, net


# ---------------------------------------------------------------------------
# Network map builder — handles Sysmon EventID 3 and WFP EventID 5156
# ---------------------------------------------------------------------------

def _build_net_map(net_events: list[dict]) -> dict[int, dict]:
    """Aggregate network events by PID. Handles EventID 3 and 5156."""
    nm: dict[int, dict] = defaultdict(lambda: {
        "ips": [], "ports": [], "protocols": [],
        "has_dns": False, "outbound": False,
    })
    for e in net_events:
        eid = _event_id(e)
        try:
            pid = int(_field(e, "ProcessId", "process_id"))
        except (ValueError, TypeError):
            continue

        if eid == 3:
            ip       = _field(e, "DestinationIp", "dst_ip", "DestIp")
            port     = _field(e, "DestinationPort", "dst_port")
            proto    = _field(e, "Protocol", "protocol")
            hostname = _field(e, "DestinationHostname", "dst_hostname")
            initiated = _field(e, "Initiated", "initiated").lower()
            if hostname and hostname != "-":
                nm[pid]["has_dns"] = True
            if initiated == "true":
                nm[pid]["outbound"] = True
        elif eid == 5156:
            ip        = _field(e, "DestAddress")
            port      = _field(e, "DestPort")
            proto_num = _field(e, "Protocol")
            proto     = "tcp" if proto_num == "6" else "udp" if proto_num == "17" else proto_num
            direction = _field(e, "Direction").lower()
            if "outbound" in direction:
                nm[pid]["outbound"] = True
        else:
            continue

        if ip:
            nm[pid]["ips"].append(ip)
        if port:
            try:
                nm[pid]["ports"].append(int(port))
            except ValueError:
                pass
        if proto:
            nm[pid]["protocols"].append(proto)
    return dict(nm)


# ---------------------------------------------------------------------------
# Process event → ProcessData
# Handles EventID 1 (Sysmon) and EventID 4688 (Windows Security)
# ---------------------------------------------------------------------------

def _to_process_data(event: dict, net_map: dict) -> ProcessData | None:
    eid = _event_id(event)

    if eid == 4688:
        image      = _field(event, "NewProcessName")
        cmd        = _field(event, "CommandLine", "ProcessCommandLine")
        parent     = _field(event, "ParentProcessName")
        hashes     = ""
        integrity  = ""
        parent_cmd = ""
        orig_fname = ""
        tel = _field(event, "TokenElevationType")
        token_elevated = tel in {"%%1937", "2", "TokenElevationTypeFull"}
        try:
            pid  = _parse_pid(_field(event, "NewProcessId"))
            ppid = _parse_pid(_field(event, "ProcessId") or "0")
        except (ValueError, TypeError):
            return None
    else:
        image      = _field(event, "Image",              "image")
        cmd        = _field(event, "CommandLine",        "command_line")
        parent     = _field(event, "ParentImage",        "parent_image")
        hashes     = _field(event, "Hashes",             "hashes")
        integrity  = _field(event, "IntegrityLevel",     "integrity_level")
        parent_cmd = _field(event, "ParentCommandLine",  "parent_command_line")
        orig_fname = _field(event, "OriginalFileName",   "original_filename")
        if orig_fname == "-":
            orig_fname = ""
        token_elevated = False
        try:
            pid  = int(_field(event, "ProcessId",       "process_id"))
            ppid = int(_field(event, "ParentProcessId", "parent_process_id") or 0)
        except (ValueError, TypeError):
            return None

    if not image:
        return None

    net = net_map.get(pid, {})
    return ProcessData(
        name                 = _proc_name(image),
        parent_name          = _proc_name(parent) if parent else "",
        command_line         = cmd,
        path                 = image.lower(),
        pid                  = pid,
        parent_pid           = ppid,
        cpu_usage            = 0.0,
        mem_usage            = 0.0,
        is_signed            = _infer_signed(image),
        sha256               = _sha256(hashes),
        connection_count     = len(net.get("ips", [])),
        destination_ips      = net.get("ips", []),
        destination_ports    = net.get("ports", []),
        protocols            = net.get("protocols", []),
        integrity_level      = integrity,
        parent_command_line  = parent_cmd,
        original_filename    = orig_fname,
        token_is_elevated    = token_elevated,
        has_dns_destination  = net.get("has_dns", False),
        connection_is_outbound = net.get("outbound", False),
    )


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _features_from_events(
    proc_events: list[dict], net_events: list[dict], fixed_label: int
) -> tuple[list, list]:
    net_map = _build_net_map(net_events)
    X, y = [], []
    for e in proc_events:
        proc = _to_process_data(e, net_map)
        if proc is None:
            continue
        # In attack logs: skip background processes UNLESS they show attack behavior.
        # A background process with suspicious command line / path / network IS an attack actor.
        if fixed_label == 1 and proc.name.lower() in _BACKGROUND_IN_ATTACK:
            if not _is_attack_related(proc):
                continue
        X.append(extract(proc))
        y.append(fixed_label)
    return X, y


def _features_from_zip(zip_path: Path, fixed_label: int) -> tuple[list, list]:
    return _features_from_events(*_parse_zip(zip_path), fixed_label)


def _features_from_targz(tgz_path: Path, fixed_label: int) -> tuple[list, list]:
    return _features_from_events(*_parse_targz(tgz_path), fixed_label)


def _features_from_file(json_path: Path, fixed_label: int) -> tuple[list, list]:
    return _features_from_events(*_parse_plain(json_path), fixed_label)


# ---------------------------------------------------------------------------
# Folder loader — returns (X, y, scenario_ids) for scenario-level splitting
# ---------------------------------------------------------------------------

def _load_folder(folder: Path, fixed_label: int) -> tuple[np.ndarray, np.ndarray, list[str]]:
    if not folder.exists():
        return np.empty((0, 0)), np.empty(0, dtype=int), []

    zips     = sorted(folder.rglob("*.zip"))
    tarballs = sorted(folder.rglob("*.tar.gz"))
    plains   = sorted(
        p for ext in ("*.json", "*.ndjson", "*.log")
        for p in folder.rglob(ext)
    )
    evtxs    = sorted(folder.rglob("*.evtx")) if _EVTX_AVAILABLE else []

    zip_covered: set[str] = set()
    for zp in zips:
        try:
            with zipfile.ZipFile(zp) as z:
                zip_covered.update(Path(n).name for n in z.namelist())
        except Exception:
            pass

    sources: list[tuple[str, Path]] = (
        [("zip",  p) for p in zips]
        + [("tgz",  p) for p in tarballs]
        + [("plain", p) for p in plains if p.name not in zip_covered]
        + [("evtx", p) for p in evtxs]
    )

    if not sources:
        return np.empty((0, 0)), np.empty(0, dtype=int), []

    X_all, y_all, scen_all = [], [], []
    for kind, src in sources:
        print(f"  {src.name} … ", end="", flush=True)
        try:
            if kind == "zip":
                X, y = _features_from_zip(src, fixed_label)
            elif kind == "tgz":
                X, y = _features_from_targz(src, fixed_label)
            elif kind == "evtx":
                X, y = _features_from_events(*_parse_evtx(src), fixed_label)
            else:
                X, y = _features_from_file(src, fixed_label)
        except Exception as exc:
            print(f"ERROR: {exc}")
            continue
        mal = sum(v == 1 for v in y)
        ben = sum(v == 0 for v in y)
        print(f"{mal} malicious  {ben} benign")
        scen_id = src.stem
        X_all.extend(X)
        y_all.extend(y)
        scen_all.extend([scen_id] * len(y))

    if not X_all:
        return np.empty((0, 0)), np.empty(0, dtype=int), []
    return np.array(X_all), np.array(y_all, dtype=int), scen_all


# ---------------------------------------------------------------------------
# Synthetic elevated-benign data
# ---------------------------------------------------------------------------

def _generate_synthetic_elevated_benign(n_repeats: int = 30) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    OTRF benign logs contain almost no elevated processes, so the model
    spuriously learns is_elevated → malicious. These synthetic samples teach
    it that signed, system32 processes running elevated are normal.

    24 templates × n_repeats = 720 benign elevated training samples by default.
    Added after balancing so they are never removed by the 3× cap.
    """
    templates = [
        # Core Windows session/service host processes
        ("lsass.exe",          "wininit.exe",  "C:\\Windows\\system32\\lsass.exe",
         "c:\\windows\\system32\\lsass.exe", "System", True),
        ("svchost.exe",        "services.exe", "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted",
         "c:\\windows\\system32\\svchost.exe", "System", True),
        ("svchost.exe",        "services.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
         "c:\\windows\\system32\\svchost.exe", "System", True),
        ("winlogon.exe",       "smss.exe",     "winlogon.exe",
         "c:\\windows\\system32\\winlogon.exe", "System", True),
        ("services.exe",       "wininit.exe",  "C:\\Windows\\system32\\services.exe",
         "c:\\windows\\system32\\services.exe", "System", True),
        ("csrss.exe",          "smss.exe",     "csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768",
         "c:\\windows\\system32\\csrss.exe", "System", True),
        ("spoolsv.exe",        "services.exe", "C:\\Windows\\System32\\spoolsv.exe",
         "c:\\windows\\system32\\spoolsv.exe", "System", True),
        ("wininit.exe",        "smss.exe",     "wininit.exe",
         "c:\\windows\\system32\\wininit.exe", "System", True),
        ("smss.exe",           "system",       "\\SystemRoot\\System32\\smss.exe",
         "c:\\windows\\system32\\smss.exe", "System", True),
        # Windows security / AV running at System integrity
        ("msmpeng.exe",        "services.exe", "\"C:\\Program Files\\Windows Defender\\MsMpEng.exe\"",
         "c:\\program files\\windows defender\\msmpeng.exe", "System", True),
        ("securityhealthservice.exe", "services.exe", "C:\\Windows\\system32\\SecurityHealthService.exe",
         "c:\\windows\\system32\\securityhealthservice.exe", "System", True),
        ("nissrv.exe",         "services.exe", "\"C:\\Program Files\\Windows Defender\\NisSrv.exe\"",
         "c:\\program files\\windows defender\\nissrv.exe", "High", True),
        # Admin / maintenance tools — legitimate elevated usage
        ("powershell.exe",     "explorer.exe",
         "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile Get-EventLog -LogName System -Newest 20",
         "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe", "High", True),
        ("powershell.exe",     "taskeng.exe",
         "powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\Backup.ps1",
         "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe", "High", True),
        ("cmd.exe",            "explorer.exe", "cmd.exe /c ipconfig /all",
         "c:\\windows\\system32\\cmd.exe", "High", True),
        ("mmc.exe",            "explorer.exe", "\"C:\\Windows\\system32\\mmc.exe\" \"C:\\Windows\\system32\\compmgmt.msc\" /s",
         "c:\\windows\\system32\\mmc.exe", "High", True),
        ("regedit.exe",        "explorer.exe", "\"C:\\Windows\\regedit.exe\"",
         "c:\\windows\\regedit.exe", "High", True),
        ("taskmgr.exe",        "explorer.exe", "\"C:\\Windows\\system32\\Taskmgr.exe\" /4",
         "c:\\windows\\system32\\taskmgr.exe", "High", True),
        ("eventvwr.exe",       "explorer.exe", "\"C:\\Windows\\system32\\eventvwr.exe\"",
         "c:\\windows\\system32\\eventvwr.exe", "High", True),
        # Windows Update / servicing
        ("trustedinstaller.exe","services.exe", "C:\\Windows\\servicing\\TrustedInstaller.exe",
         "c:\\windows\\servicing\\trustedinstaller.exe", "System", True),
        ("wuauclt.exe",        "svchost.exe",  "wuauclt.exe /UpdateDeploymentProvider WindowsUpdatePlugin.dll",
         "c:\\windows\\system32\\wuauclt.exe", "High", True),
        ("msiexec.exe",        "explorer.exe", "C:\\Windows\\system32\\msiexec.exe /i \"C:\\Program Files\\App\\setup.msi\"",
         "c:\\windows\\system32\\msiexec.exe", "High", True),
        # Dev tools running elevated (common for developers)
        ("devenv.exe",         "explorer.exe", "\"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\devenv.exe\"",
         "c:\\program files\\microsoft visual studio\\2022\\community\\common7\\ide\\devenv.exe", "High", True),
        ("code.exe",           "explorer.exe", "\"C:\\Program Files\\Microsoft VS Code\\Code.exe\"",
         "c:\\program files\\microsoft vs code\\code.exe", "High", True),
    ]

    X, y, scens = [], [], []
    for rep in range(n_repeats):
        for i, (name, parent, cmd, path, integrity, elevated) in enumerate(templates):
            proc = ProcessData(
                name=name, parent_name=parent, command_line=cmd, path=path,
                pid=10000 + rep * 100 + i, parent_pid=500 + i,
                cpu_usage=0.0, mem_usage=0.0,
                is_signed=True, sha256="",
                connection_count=0,
                destination_ips=[], destination_ports=[], protocols=[],
                integrity_level=integrity,
                token_is_elevated=elevated,
            )
            X.append(extract(proc))
            y.append(0)
            scens.append("synthetic_elevated_benign")

    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y, dtype=int)
    print(f"[synthetic] Generated {len(y_arr)} elevated-benign samples ({len(templates)} templates × {n_repeats} repeats)")
    return X_arr, y_arr, scens


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    from sklearn.model_selection import GroupShuffleSplit

    print("=" * 60)
    print("  Voidwatch Trainer — behavioral RF, scenario-level eval")
    print("=" * 60)

    print(f"\nAttack datasets  ({ATTACK_DIR})")
    X_atk, y_atk, scen_atk = _load_folder(ATTACK_DIR, fixed_label=1)

    print(f"\nBenign datasets  ({BENIGN_DIR})")
    X_ben_otrf, y_ben_otrf, scen_ben = _load_folder(BENIGN_DIR, fixed_label=0)

    X_test_parts: list[np.ndarray] = []
    y_test_parts: list[np.ndarray] = []
    test_scens:   list[str]        = []
    X_train_parts: list[np.ndarray] = []
    y_train_parts: list[np.ndarray] = []

    def _scenario_split(X, y, scens, label_prefix=""):
        unique = list(set(scens))
        if len(unique) < 2:
            X_train_parts.append(X); y_train_parts.append(y)
            return
        # ensure at least 1 scenario in test regardless of count
        test_frac = max(1 / len(unique), 0.2)
        gss = GroupShuffleSplit(n_splits=1, test_size=test_frac, random_state=42)
        tr_idx, te_idx = next(gss.split(X, y, groups=scens))
        X_test_parts.append(X[te_idx]); y_test_parts.append(y[te_idx])
        test_scens.extend(label_prefix + scens[i] for i in te_idx)
        X_train_parts.append(X[tr_idx]); y_train_parts.append(y[tr_idx])

    n_atk_sc = len(set(scen_atk))  if X_atk.size     else 0
    n_ben_sc = len(set(scen_ben))  if X_ben_otrf.size else 0
    print(f"\n{n_atk_sc} attack scenarios, {n_ben_sc} benign scenarios loaded")

    if X_atk.size:
        _scenario_split(X_atk, y_atk, scen_atk)
    if X_ben_otrf.size:
        _scenario_split(X_ben_otrf, y_ben_otrf, scen_ben, label_prefix="ben_")

    X_test = np.vstack(X_test_parts)    if X_test_parts else None
    y_test = np.concatenate(y_test_parts) if y_test_parts else None

    if X_test is not None:
        print(f"Scenario split — train additions: {sum(len(x) for x in X_train_parts[2:])}  "
              f"test: {len(X_test)} samples")
        print(f"Test scenarios: {sorted(set(test_scens))}")

    X = np.vstack(X_train_parts)
    y = np.concatenate(y_train_parts)

    # Balance before adding synthetic data
    mal_idx = np.where(y == 1)[0]
    ben_idx = np.where(y == 0)[0]
    if len(mal_idx) > 0 and len(ben_idx) > 3 * len(mal_idx):
        rng = np.random.RandomState(42)
        ben_idx = rng.choice(ben_idx, size=3 * len(mal_idx), replace=False)
        keep = np.concatenate([mal_idx, ben_idx])
        rng.shuffle(keep)
        X, y = X[keep], y[keep]

    # Add synthetic elevated-benign samples AFTER balancing (so they're never dropped)
    X_syn, y_syn, _ = _generate_synthetic_elevated_benign()
    X = np.vstack([X, X_syn])
    y = np.concatenate([y, y_syn])

    mal_n = int(y.sum()); ben_n = len(y) - mal_n
    print(f"\nTraining set: {len(y)} samples  ({mal_n} malicious / {ben_n} benign)")

    print("\nTraining …")
    clf = ProcessClassifier()
    clf.train_on(X, y, X_test, y_test, test_scens)
    with open(_VER_FILE, "w", encoding="utf-8") as f:
        f.write(_MODEL_VER)
    print("\nModel saved. Restart the backend to load the new classifier.")


if __name__ == "__main__":
    main()

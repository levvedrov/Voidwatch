"""
Parse OTRF Security Datasets and retrain the Voidwatch classifier.

Place downloaded ZIPs/tar.gz in:
  backend/datasets/otrf/attack/   <- malicious (label = 1)
  backend/datasets/otrf/benign/   <- benign    (label = 0, optional)

Subdirectories are scanned recursively, so you can keep the original
OTRF folder structure (attack/defense_evasion/host/*.zip, etc.)

Then run from the backend folder:
  python train_otrf.py

Labeling strategy for attack datasets:
  - Processes that trigger rule_score >= 15  -> label 1 (malicious)
  - Processes with rule_score == 0           -> label 0 (benign background)
  - Anything in between is discarded (ambiguous)
Benign datasets: everything labelled 0.
Both are combined with the existing synthetic baseline before retraining.
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

sys.path.insert(0, os.path.dirname(__file__))

from classifier import ProcessClassifier, _benign_samples, _malicious_samples, _VER_FILE, _MODEL_VER
from features import extract
from models import ProcessData
from scoring import _base

DATASETS_DIR        = Path(__file__).parent / "datasets" / "otrf"
ATTACK_DIR          = DATASETS_DIR / "attack"
BENIGN_DIR          = DATASETS_DIR / "benign"
MALICIOUS_THRESHOLD = 15   # minimum rule score to label as malicious

# EventIDs treated as process-creation events
_PROC_EIDS    = {1, 4688}
# EventIDs treated as network-connection events
_NET_EIDS     = {3, 5156}


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


# ---------------------------------------------------------------------------
# Network map builder — handles Sysmon EventID 3 and WFP EventID 5156
# ---------------------------------------------------------------------------

def _build_net_map(net_events: list[dict]) -> dict[int, dict]:
    """Aggregate network events by PID. Handles EventID 3 and 5156."""
    nm: dict[int, dict] = defaultdict(lambda: {"ips": [], "ports": [], "protocols": []})
    for e in net_events:
        eid = _event_id(e)
        try:
            pid = int(_field(e, "ProcessId", "process_id"))
        except (ValueError, TypeError):
            continue

        if eid == 3:
            # Sysmon network event — standard field names
            ip    = _field(e, "DestinationIp", "dst_ip", "DestIp")
            port  = _field(e, "DestinationPort", "dst_port")
            proto = _field(e, "Protocol", "protocol")
        elif eid == 5156:
            # Windows Filtering Platform — different field names, numeric protocol
            ip    = _field(e, "DestAddress")
            port  = _field(e, "DestPort")
            proto_num = _field(e, "Protocol")
            proto = "tcp" if proto_num == "6" else "udp" if proto_num == "17" else proto_num
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
        # Windows Security process creation — different field names, hex PIDs
        image  = _field(event, "NewProcessName")
        cmd    = _field(event, "CommandLine", "ProcessCommandLine")
        parent = _field(event, "ParentProcessName")
        hashes = ""
        try:
            pid  = _parse_pid(_field(event, "NewProcessId"))
            # In 4688, ProcessId is the *creator* (parent) PID
            ppid = _parse_pid(_field(event, "ProcessId") or "0")
        except (ValueError, TypeError):
            return None
    else:
        # EventID 1 (Sysmon) — standard flat or winlogbeat format
        image  = _field(event, "Image",         "image")
        cmd    = _field(event, "CommandLine",   "command_line")
        parent = _field(event, "ParentImage",   "parent_image")
        hashes = _field(event, "Hashes",        "hashes")
        try:
            pid  = int(_field(event, "ProcessId",       "process_id"))
            ppid = int(_field(event, "ParentProcessId", "parent_process_id") or 0)
        except (ValueError, TypeError):
            return None

    if not image:
        return None

    net = net_map.get(pid, {})
    return ProcessData(
        name              = _proc_name(image),
        parent_name       = _proc_name(parent) if parent else "",
        command_line      = cmd,
        path              = image.lower(),
        pid               = pid,
        parent_pid        = ppid,
        cpu_usage         = 0.0,
        mem_usage         = 0.0,
        is_signed         = _infer_signed(image),
        sha256            = _sha256(hashes),
        connection_count  = len(net.get("ips", [])),
        destination_ips   = net.get("ips", []),
        destination_ports = net.get("ports", []),
        protocols         = net.get("protocols", []),
    )


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _features_from_events(
    proc_events: list[dict], net_events: list[dict], fixed_label: int | None
) -> tuple[list, list]:
    net_map = _build_net_map(net_events)
    X, y = [], []
    for e in proc_events:
        proc = _to_process_data(e, net_map)
        if proc is None:
            continue
        rule_score = _base(proc)[0]
        if fixed_label is None:
            if rule_score >= MALICIOUS_THRESHOLD:
                lbl = 1
            elif rule_score == 0:
                lbl = 0
            else:
                continue   # ambiguous — skip
        else:
            lbl = fixed_label
        X.append(extract(proc, rule_score))
        y.append(lbl)
    return X, y


def _features_from_zip(zip_path: Path, fixed_label: int | None) -> tuple[list, list]:
    return _features_from_events(*_parse_zip(zip_path), fixed_label)


def _features_from_targz(tgz_path: Path, fixed_label: int | None) -> tuple[list, list]:
    return _features_from_events(*_parse_targz(tgz_path), fixed_label)


def _features_from_file(json_path: Path, fixed_label: int | None) -> tuple[list, list]:
    return _features_from_events(*_parse_plain(json_path), fixed_label)


# ---------------------------------------------------------------------------
# Folder loader — recursive scan, supports .zip / .tar.gz / plain JSON
# ---------------------------------------------------------------------------

def _load_folder(folder: Path, fixed_label: int | None) -> tuple[np.ndarray, np.ndarray]:
    if not folder.exists():
        return np.empty((0, 0)), np.empty(0, dtype=int)

    # rglob — recurse into subdirectories (attack/defense_evasion/host/*.zip, etc.)
    zips   = sorted(folder.rglob("*.zip"))
    tarballs = sorted(folder.rglob("*.tar.gz"))
    plains = sorted(
        p for ext in ("*.json", "*.ndjson", "*.log")
        for p in folder.rglob(ext)
    )

    # avoid double-counting plain files already inside a ZIP
    zip_covered: set[str] = set()
    for zp in zips:
        try:
            with zipfile.ZipFile(zp) as z:
                zip_covered.update(Path(n).name for n in z.namelist())
        except Exception:
            pass

    sources: list[tuple[str, Path]] = (
        [("zip", p) for p in zips]
        + [("tgz", p) for p in tarballs]
        + [("plain", p) for p in plains if p.name not in zip_covered]
    )

    if not sources:
        return np.empty((0, 0)), np.empty(0, dtype=int)

    X_all, y_all = [], []
    for kind, src in sources:
        print(f"  {src.name} … ", end="", flush=True)
        try:
            if kind == "zip":
                X, y = _features_from_zip(src, fixed_label)
            elif kind == "tgz":
                X, y = _features_from_targz(src, fixed_label)
            else:
                X, y = _features_from_file(src, fixed_label)
        except Exception as exc:
            print(f"ERROR: {exc}")
            continue
        mal = sum(v == 1 for v in y)
        ben = sum(v == 0 for v in y)
        print(f"{mal} malicious  {ben} benign")
        X_all.extend(X)
        y_all.extend(y)

    if not X_all:
        return np.empty((0, 0)), np.empty(0, dtype=int)
    return np.array(X_all), np.array(y_all, dtype=int)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 52)
    print("  Voidwatch OTRF Trainer")
    print("=" * 52)

    print(f"\nAttack datasets  ({ATTACK_DIR})")
    X_atk, y_atk = _load_folder(ATTACK_DIR, fixed_label=None)

    print(f"\nBenign datasets  ({BENIGN_DIR})")
    X_ben_otrf, y_ben_otrf = _load_folder(BENIGN_DIR, fixed_label=0)

    print("\nSynthetic baseline …", end=" ", flush=True)
    X_syn_mal = _malicious_samples()
    X_syn_ben = _benign_samples()
    y_syn_mal = np.ones(len(X_syn_mal),  dtype=int)
    y_syn_ben = np.zeros(len(X_syn_ben), dtype=int)
    print(f"{len(X_syn_mal)} malicious  {len(X_syn_ben)} benign")

    parts_X = [X_syn_mal, X_syn_ben]
    parts_y = [y_syn_mal, y_syn_ben]
    if X_atk.size:
        parts_X.append(X_atk)
        parts_y.append(y_atk)
    if X_ben_otrf.size:
        parts_X.append(X_ben_otrf)
        parts_y.append(y_ben_otrf)

    X = np.vstack(parts_X)
    y = np.concatenate(parts_y)

    mal_n = int(y.sum())
    ben_n = len(y) - mal_n
    print(f"\nCombined: {len(y)} samples  ({mal_n} malicious / {ben_n} benign)")

    print("\nTraining RandomForest …")
    clf = ProcessClassifier()
    clf.train_on(X, y)
    with open(_VER_FILE, "w", encoding="utf-8") as f:
        f.write(_MODEL_VER)
    print("\nModels saved. Restart the backend to load the new classifier.")


if __name__ == "__main__":
    main()

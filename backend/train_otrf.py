"""
Parse OTRF Security Datasets and retrain the Voidwatch classifier.

Place downloaded ZIPs in:
  backend/datasets/otrf/attack/   <- malicious (label = 1)
  backend/datasets/otrf/benign/   <- benign    (label = 0, optional)

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

import json
import os
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))

from classifier import ProcessClassifier, _benign_samples, _malicious_samples
from features import extract
from models import ProcessData
from scoring import _base

DATASETS_DIR        = Path(__file__).parent / "datasets" / "otrf"
ATTACK_DIR          = DATASETS_DIR / "attack"
BENIGN_DIR          = DATASETS_DIR / "benign"
MALICIOUS_THRESHOLD = 15   # minimum rule score to label as malicious


# ---------------------------------------------------------------------------
# Event parsing helpers — handles both old (flat) and new (winlogbeat) format
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


# ---------------------------------------------------------------------------
# ZIP parsing
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


def _parse_zip(zip_path: Path) -> tuple[list[dict], list[dict]]:
    """Return (process_events, network_events) from a ZIP."""
    proc, net = [], []
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not any(name.endswith(ext) for ext in (".json", ".ndjson", ".log")):
                continue
            raw = zf.read(name)
            for event in _parse_ndjson(raw):
                eid = _event_id(event)
                if eid == 1:
                    proc.append(event)
                elif eid == 3:
                    net.append(event)
    return proc, net


def _parse_plain(json_path: Path) -> tuple[list[dict], list[dict]]:
    """Return (process_events, network_events) from a plain JSON/NDJSON file."""
    proc, net = [], []
    raw = json_path.read_bytes()
    for event in _parse_ndjson(raw):
        eid = _event_id(event)
        if eid == 1:
            proc.append(event)
        elif eid == 3:
            net.append(event)
    return proc, net


def _build_net_map(net_events: list[dict]) -> dict[int, dict]:
    """Aggregate network events by PID."""
    nm: dict[int, dict] = defaultdict(lambda: {"ips": [], "ports": [], "protocols": []})
    for e in net_events:
        try:
            pid = int(_field(e, "ProcessId", "process_id"))
        except (ValueError, TypeError):
            continue
        ip    = _field(e, "DestinationIp",   "dst_ip",   "DestIp")
        port  = _field(e, "DestinationPort",  "dst_port", "DestPort")
        proto = _field(e, "Protocol",         "protocol")
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


def _to_process_data(event: dict, net_map: dict) -> ProcessData | None:
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
# Feature extraction from a single ZIP
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
    proc_events, net_events = _parse_zip(zip_path)
    return _features_from_events(proc_events, net_events, fixed_label)


def _features_from_file(json_path: Path, fixed_label: int | None) -> tuple[list, list]:
    proc_events, net_events = _parse_plain(json_path)
    return _features_from_events(proc_events, net_events, fixed_label)


def _load_folder(folder: Path, fixed_label: int | None) -> tuple[np.ndarray, np.ndarray]:
    if not folder.exists():
        return np.empty((0, 0)), np.empty(0, dtype=int)

    zips = sorted(folder.glob("*.zip"))
    plains = sorted(
        p for ext in ("*.json", "*.ndjson", "*.log") for p in folder.glob(ext)
    )

    # names already covered by ZIPs — avoid double-counting
    zip_covered: set[str] = set()
    for zp in zips:
        try:
            with zipfile.ZipFile(zp) as z:
                zip_covered.update(Path(n).name for n in z.namelist())
        except Exception:
            pass

    sources: list[Path] = zips + [p for p in plains if p.name not in zip_covered]
    if not sources:
        return np.empty((0, 0)), np.empty(0, dtype=int)

    X_all, y_all = [], []
    for src in sources:
        print(f"  {src.name} … ", end="", flush=True)
        if src.suffix == ".zip":
            X, y = _features_from_zip(src, fixed_label)
        else:
            X, y = _features_from_file(src, fixed_label)
        mal = sum(v == 1 for v in y)
        ben = sum(v == 0 for v in y)
        print(f"{mal} malicious  {ben} benign")
        X_all.extend(X)
        y_all.extend(y)

    return np.array(X_all), np.array(y_all, dtype=int)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 52)
    print("  Voidwatch OTRF Trainer")
    print("=" * 52)

    # ── OTRF attack datasets (auto-label) ──────────────────
    print(f"\nAttack datasets  ({ATTACK_DIR})")
    X_atk, y_atk = _load_folder(ATTACK_DIR, fixed_label=None)

    # ── OTRF benign datasets (force label=0) ───────────────
    print(f"\nBenign datasets  ({BENIGN_DIR})")
    X_ben_otrf, y_ben_otrf = _load_folder(BENIGN_DIR, fixed_label=0)

    # ── Synthetic baseline ─────────────────────────────────
    print("\nSynthetic baseline …", end=" ", flush=True)
    X_syn_mal = _malicious_samples()
    X_syn_ben = _benign_samples()
    y_syn_mal = np.ones(len(X_syn_mal),  dtype=int)
    y_syn_ben = np.zeros(len(X_syn_ben), dtype=int)
    print(f"{len(X_syn_mal)} malicious  {len(X_syn_ben)} benign")

    # ── Combine ────────────────────────────────────────────
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

    # ── Train ──────────────────────────────────────────────
    print("\nTraining RandomForest …")
    clf = ProcessClassifier()
    clf.train_on(X, y)
    print("\nModels saved. Restart the backend to load the new classifier.")


if __name__ == "__main__":
    main()

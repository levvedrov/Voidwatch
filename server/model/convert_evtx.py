"""
Convert EVTX-ATTACK-SAMPLES files to NDJSON for train.py

Usage:
    python convert_evtx.py <path_to_EVTX-ATTACK-SAMPLES>

Only processes the priority tactic folders that fill gaps in the current dataset.
Outputs one .ndjson file per EVTX file into datasets/otrf/attack/<tactic>/.

Install dependency first:
    pip install evtx
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import evtx as evtx_lib

# ---------------------------------------------------------------------------
# Tactic folders to import (fills dataset gaps — skip folders OTRF already covers well)
# ---------------------------------------------------------------------------

# Map from substrings found in EVTX-ATTACK-SAMPLES folder names → our output tactic folder
TACTIC_MAP: dict[str, str] = {
    "command":    "Command and Control",   # Command and Control / C2
    "c2":         "Command and Control",
    "collection": "collection",
    "exfiltrat":  "exfiltration",
    "initial":    "initial_access",
    "execution":  "execution",
    "discovery":  "discovery",
}

# Event IDs we care about
_PROC_EIDS = {1, 4688}
_NET_EIDS  = {3, 5156}
_KEEP_EIDS = _PROC_EIDS | _NET_EIDS

DATASETS_ATTACK = Path(__file__).parent / "datasets" / "otrf" / "attack"


# ---------------------------------------------------------------------------
# Parse a single EVTX record (JSON from omerbenamram/evtx) → flat dict
# ---------------------------------------------------------------------------

def _extract_event_data(event_data) -> dict[str, str]:
    """Flatten EventData.Data list into {Name: text} dict."""
    result: dict[str, str] = {}
    if isinstance(event_data, dict):
        data = event_data.get("Data", [])
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    attrs = item.get("#attributes", {})
                    name  = attrs.get("Name", "")
                    text  = item.get("#text", "")
                    if name:
                        result[name] = str(text) if text is not None else ""
        elif isinstance(data, dict):
            # Single field wrapped as dict
            attrs = data.get("#attributes", {})
            name  = attrs.get("Name", "")
            text  = data.get("#text", "")
            if name:
                result[name] = str(text) if text is not None else ""
    return result


def _record_to_flat(record_json: str) -> dict | None:
    """Convert one evtx JSON record string → flat dict or None if not wanted."""
    try:
        obj = json.loads(record_json)
    except json.JSONDecodeError:
        return None

    event  = obj.get("Event", {})
    system = event.get("System", {})

    # EventID may be plain int/str or {"#text": "1"}
    raw_eid = system.get("EventID", 0)
    if isinstance(raw_eid, dict):
        raw_eid = raw_eid.get("#text", 0)
    try:
        eid = int(raw_eid)
    except (ValueError, TypeError):
        return None

    if eid not in _KEEP_EIDS:
        return None

    fields = _extract_event_data(event.get("EventData", {}))
    fields["EventID"] = str(eid)

    # Also pull Computer for context (optional)
    computer = system.get("Computer", "")
    if computer:
        fields["Computer"] = str(computer)

    return fields


# ---------------------------------------------------------------------------
# Process one EVTX file → list of flat dicts
# ---------------------------------------------------------------------------

def convert_evtx_file(evtx_path: Path) -> list[dict]:
    records_out = []
    try:
        parser = evtx_lib.PyEvtxParser(str(evtx_path))
        for record in parser.records_json():
            flat = _record_to_flat(record["data"])
            if flat is not None:
                records_out.append(flat)
    except Exception as exc:
        print(f"    [WARN] {evtx_path.name}: {exc}")
    return records_out


# ---------------------------------------------------------------------------
# Resolve which output tactic folder a source folder maps to
# ---------------------------------------------------------------------------

def _resolve_tactic(folder_name: str) -> str | None:
    lower = folder_name.lower()
    for key, tactic in TACTIC_MAP.items():
        if key in lower:
            return tactic
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python convert_evtx.py <path_to_EVTX-ATTACK-SAMPLES>")
        sys.exit(1)

    src_root = Path(sys.argv[1])
    if not src_root.exists():
        print(f"ERROR: {src_root} does not exist")
        sys.exit(1)

    total_files   = 0
    total_records = 0
    skipped_files = 0

    # Walk tactic-level subfolders
    tactic_dirs = [d for d in sorted(src_root.iterdir()) if d.is_dir()]
    if not tactic_dirs:
        # Maybe src_root IS a tactic folder — treat parent as root
        tactic_dirs = [src_root]

    for tactic_dir in tactic_dirs:
        tactic = _resolve_tactic(tactic_dir.name)
        if tactic is None:
            print(f"  Skipping: {tactic_dir.name}  (not in priority list)")
            continue

        out_dir = DATASETS_ATTACK / tactic
        out_dir.mkdir(parents=True, exist_ok=True)

        evtx_files = sorted(tactic_dir.rglob("*.evtx"))
        if not evtx_files:
            print(f"  {tactic_dir.name}: no .evtx files found")
            continue

        print(f"\n[{tactic_dir.name}] → {tactic}/  ({len(evtx_files)} files)")

        for evtx_path in evtx_files:
            records = convert_evtx_file(evtx_path)

            proc_count = sum(1 for r in records if int(r["EventID"]) in _PROC_EIDS)
            net_count  = sum(1 for r in records if int(r["EventID"]) in _NET_EIDS)

            if not records:
                print(f"    {evtx_path.name}: 0 usable events — skip")
                skipped_files += 1
                continue

            out_file = out_dir / (evtx_path.stem + ".ndjson")
            with open(out_file, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            print(f"    {evtx_path.name}: {proc_count} proc  {net_count} net  → {out_file.name}")
            total_files   += 1
            total_records += len(records)

    print(f"\nDone. {total_files} files written, {total_records} total events, {skipped_files} skipped.")
    print(f"Output: {DATASETS_ATTACK}")
    print("Now run: python train.py")


if __name__ == "__main__":
    main()

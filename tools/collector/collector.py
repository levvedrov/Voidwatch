#!/usr/bin/env python3
"""
Voidwatch — Benign Process Collector
Standalone script, no project dependencies required.

Requirements:
  pip install psutil

Usage:
  python collect_benign.py                   # 60 min, 30s interval
  python collect_benign.py --duration 120    # 2 hours
  python collect_benign.py --interval 10     # faster snapshots

Output:
  collected_YYYYMMDD_HHMMSS.json  (saved next to this script)

Transfer the output file to:
  backend/datasets/otrf/benign/
Then retrain with:
  python train_otrf.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

OUTPUT_DIR = Path(__file__).parent


def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _signatures_many(paths: list[str]) -> dict[str, bool]:
    if not paths:
        return {}
    escaped = ", ".join(f'"{p.replace(chr(34), "")}"' for p in paths)
    script = (
        f"@({escaped}) | ForEach-Object {{ "
        f"$s = Get-AuthenticodeSignature $_; "
        f"[PSCustomObject]@{{Path=$_; Status=$s.Status}} }} | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=30,
        )
        raw = result.stdout.strip()
        if not raw:
            return {p: False for p in paths}
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        return {item["Path"]: item["Status"] == "Valid" for item in data}
    except Exception:
        return {p: False for p in paths}


def _net_by_pid() -> dict[int, list[tuple]]:
    result: dict[int, list] = {}
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid is None or not conn.raddr:
                continue
            proto = "tcp" if conn.type == 1 else "udp"
            result.setdefault(conn.pid, []).append((conn.raddr.ip, conn.raddr.port, proto))
    except Exception:
        pass
    return result


def _snapshot() -> tuple[list[dict], list[dict]]:
    snapshots = []
    for proc in psutil.process_iter():
        try:
            with proc.oneshot():
                name = proc.name()
                pid  = proc.pid
                ppid = proc.ppid()
                try:
                    cmd = " ".join(proc.cmdline())
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmd = ""
                try:
                    path = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    path = ""
            snapshots.append((name, pid, ppid, cmd, path))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    unique_paths = list({s[4] for s in snapshots if s[4]})
    sha256_map   = {p: _sha256(p) for p in unique_paths}
    sig_map      = _signatures_many(unique_paths)
    pid_to_name  = {s[1]: s[0] for s in snapshots}
    net_map      = _net_by_pid()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    proc_events: list[dict] = []
    net_events:  list[dict] = []

    for name, pid, ppid, cmd, path in snapshots:
        parent_name = pid_to_name.get(ppid, "")
        sha         = sha256_map.get(path, "")
        proc_events.append({
            "EventID":         1,
            "UtcTime":         ts,
            "ProcessId":       pid,
            "ParentProcessId": ppid,
            "Image":           path or name,
            "ParentImage":     parent_name,
            "CommandLine":     cmd,
            "Hashes":          f"SHA256={sha}" if sha else "",
        })
        for ip, port, proto in net_map.get(pid, []):
            net_events.append({
                "EventID":         3,
                "UtcTime":         ts,
                "ProcessId":       pid,
                "DestinationIp":   ip,
                "DestinationPort": port,
                "Protocol":        proto,
            })

    return proc_events, net_events


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect benign process telemetry for Voidwatch ML training")
    parser.add_argument("--duration", type=int, default=60,
                        help="Collection duration in minutes (default: 60)")
    parser.add_argument("--interval", type=int, default=30,
                        help="Snapshot interval in seconds (default: 30)")
    args = parser.parse_args()

    ts_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = OUTPUT_DIR / f"collected_{ts_str}.json"

    deadline       = time.time() + args.duration * 60
    start_time     = time.time()
    seen: set[tuple] = set()
    total_proc     = 0
    total_net      = 0
    snapshots_done = 0

    print(f"Voidwatch benign collector")
    print(f"Duration : {args.duration} min  |  Interval: {args.interval}s")
    print(f"Output   : {out_path}")
    print(f"Press Ctrl+C to stop early.\n")

    with open(out_path, "w", encoding="utf-8") as f:
        try:
            while time.time() < deadline:
                proc_events, net_events = _snapshot()
                new_count = 0

                for ev in proc_events:
                    key = (ev["ProcessId"], ev["Image"], ev["CommandLine"])
                    if key in seen:
                        continue
                    seen.add(key)
                    f.write(json.dumps(ev) + "\n")
                    new_count += 1

                for ev in net_events:
                    f.write(json.dumps(ev) + "\n")

                total_proc     += new_count
                total_net      += len(net_events)
                snapshots_done += 1

                remaining = int(deadline - time.time())
                print(
                    f"  [{snapshots_done:3d}]  +{new_count:3d} new  |  "
                    f"{total_proc:4d} procs  {total_net:4d} net  |  "
                    f"{remaining // 60}m{remaining % 60:02d}s left",
                    flush=True,
                )
                f.flush()

                if time.time() < deadline:
                    time.sleep(min(args.interval, max(0, deadline - time.time())))

        except KeyboardInterrupt:
            print("\nStopped by user.")

    elapsed = int(time.time() - start_time)
    print(f"\nFinished in {elapsed // 60}m{elapsed % 60:02d}s")
    print(f"  {total_proc} process records")
    print(f"  {total_net} network records")
    print(f"  → {out_path}")
    print(f"\nCopy this file to:  backend/datasets/otrf/benign/")
    print(f"Then run:           python train_otrf.py")


if __name__ == "__main__":
    main()

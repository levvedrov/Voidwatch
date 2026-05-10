import hashlib
import json
import subprocess
from dataclasses import dataclass

import psutil


@dataclass
class ProcessTelemetry:
    name: str
    parent_name: str
    command_line: str
    path: str
    pid: int
    parent_pid: int
    cpu_usage: float
    mem_usage: float
    is_signed: bool
    sha256: str


def _sha256_many(paths: list) -> dict:
    results = {}
    for path in paths:
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            results[path] = h.hexdigest()
        except OSError:
            results[path] = ''
    return results


def _signatures_many(paths: list) -> dict:
    if not paths:
        return {}
    escaped = ', '.join(f'"{p.replace(chr(34), "")}"' for p in paths)
    script = (
        f'@({escaped}) | ForEach-Object {{ '
        f'$s = Get-AuthenticodeSignature $_; '
        f'[PSCustomObject]@{{Path=$_; Status=$s.Status}} }} | ConvertTo-Json -Compress'
    )
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', script],
            capture_output=True, text=True, timeout=30
        )
        raw = result.stdout.strip()
        if not raw:
            return {p: False for p in paths}
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        return {item['Path']: item['Status'] == 'Valid' for item in data}
    except Exception:
        return {p: False for p in paths}


def collect_all() -> list:
    # --- pass 1: snapshot basic info (no blocking IO) ---
    snapshots = []
    for proc in psutil.process_iter():
        try:
            with proc.oneshot():
                name       = proc.name()
                pid        = proc.pid
                parent_pid = proc.ppid()
                try:
                    cmd = ' '.join(proc.cmdline())
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmd = ''
                try:
                    path = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    path = ''
                # interval=None: non-blocking, returns 0.0 on first call
                cpu = proc.cpu_percent(interval=None)
                mem = round(proc.memory_info().rss / (1024 * 1024), 2)
            snapshots.append((proc, name, pid, parent_pid, cmd, path, cpu, mem))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # --- pass 2: batch expensive IO on unique exe paths ---
    unique_paths = list({s[5] for s in snapshots if s[5]})
    sha256_map   = _sha256_many(unique_paths)
    sig_map      = _signatures_many(unique_paths)

    # --- pass 3: resolve parent names and build results ---
    pid_to_name = {s[2]: s[1] for s in snapshots}

    results = []
    for _, name, pid, parent_pid, cmd, path, cpu, mem in snapshots:
        parent_name = pid_to_name.get(parent_pid, '')
        results.append(ProcessTelemetry(
            name=name,
            parent_name=parent_name,
            command_line=cmd,
            path=path,
            pid=pid,
            parent_pid=parent_pid,
            cpu_usage=round(cpu, 2),
            mem_usage=mem,
            is_signed=sig_map.get(path, False),
            sha256=sha256_map.get(path, ''),
        ))
    return results

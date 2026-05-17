import json
import subprocess
from dataclasses import dataclass

import psutil

# Well-known Windows system processes — treated as signed when psutil
# cannot read their exe path (access denied for non-elevated agents).
_KNOWN_SYSTEM_PROCS = frozenset({
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "lsass.exe", "lsaiso.exe", "services.exe",
    "svchost.exe", "spoolsv.exe", "explorer.exe", "taskhostw.exe",
    "taskhost.exe", "dwm.exe", "conhost.exe", "fontdrvhost.exe",
    "sihost.exe", "ctfmon.exe", "runtimebroker.exe",
    "searchindexer.exe", "searchhost.exe", "msdtc.exe",
    "securityhealthservice.exe", "audiodg.exe", "wuauclt.exe",
})


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



_SIG_BATCH = 25   # keep PowerShell command well under shell limits

def _signatures_batch(paths: list) -> dict:
    escaped = ', '.join(f'"{p.replace(chr(34), "")}"' for p in paths)
    script = (
        f'@({escaped}) | ForEach-Object {{ '
        f'$s = Get-AuthenticodeSignature $_; '
        f'[PSCustomObject]@{{Path=$_; Status=$s.Status}} }} | ConvertTo-Json -Compress'
    )
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive',
             '-ExecutionPolicy', 'Bypass', '-Command', script],
            capture_output=True, text=True, timeout=15
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


def _signatures_many(paths: list) -> dict:
    if not paths:
        return {}
    results: dict = {}
    for i in range(0, len(paths), _SIG_BATCH):
        results.update(_signatures_batch(paths[i:i + _SIG_BATCH]))
    return results


_SYSTEM_PATH_FRAGMENTS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
)


def _resolve_signed(name: str, path: str, sig_map: dict) -> bool:
    # 1. Known system process names are always treated as signed
    if name.lower() in _KNOWN_SYSTEM_PROCS:
        return True
    # 2. Authenticode check for processes where we have a path
    if path:
        if sig_map.get(path, False):
            return True
        # 3. Fallback: if path is under System32/SysWow64 it's a system binary
        pl = path.lower()
        if any(f in pl for f in _SYSTEM_PATH_FRAGMENTS):
            return True
    return False


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
            is_signed=_resolve_signed(name, path, sig_map),
            sha256='',
        ))
    return results

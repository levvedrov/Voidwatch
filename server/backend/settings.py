import json
import os
from pathlib import Path

_FILE = Path(__file__).parent / "settings.json"
_DEFAULTS: dict = {"process_retain_days": 7, "alert_retain_days": 30}


def load() -> dict:
    try:
        if _FILE.exists():
            return {**_DEFAULTS, **json.loads(_FILE.read_text(encoding="utf-8"))}
    except Exception:
        pass
    return dict(_DEFAULTS)


def save(updates: dict) -> dict:
    current = load()
    for k, v in updates.items():
        if k in _DEFAULTS:
            current[k] = v
    tmp = _FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(current, indent=2), encoding="utf-8")
    os.replace(tmp, _FILE)
    return current

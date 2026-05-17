import json
import os
import socket
import uuid
from pathlib import Path

_CONFIG_FILE   = Path(__file__).parent / "config.json"
_ID_FILE       = Path(__file__).parent / ".agent_id"
_SECRET_FILE   = Path(__file__).parent / ".agent_secret"
_FALLBACK_DIR  = Path.home() / ".voidwatch"


def _read_file(primary: Path, fallback: Path) -> str:
    for f in (primary, fallback / primary.name):
        try:
            if f.exists():
                val = f.read_text(encoding="utf-8").strip()
                if val:
                    return val
        except OSError:
            pass
    return ""


def _write_file(primary: Path, fallback_dir: Path, value: str) -> None:
    for f in (primary, fallback_dir / primary.name):
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(value, encoding="utf-8")
            return
        except OSError:
            pass


def _load_config() -> dict:
    try:
        if _CONFIG_FILE.exists():
            return json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


_cfg = _load_config()

SERVER_URL = (
    _cfg.get("server_url")
    or os.environ.get("VOIDWATCH_SERVER_URL", "http://localhost:8000")
)
API_KEY = (
    _cfg.get("api_key")
    or os.environ.get("VOIDWATCH_API_KEY", "")
)
MODE = _cfg.get("mode", "detect")   # collect_only | detect | debug

AGENT_SECRET = _read_file(_SECRET_FILE, _FALLBACK_DIR) or ""

_stored_id = _read_file(_ID_FILE, _FALLBACK_DIR)
if _stored_id:
    AGENT_ID = _stored_id
else:
    AGENT_ID = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
    _write_file(_ID_FILE, _FALLBACK_DIR, AGENT_ID)

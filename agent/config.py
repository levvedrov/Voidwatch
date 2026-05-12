import os
import socket
import uuid
from pathlib import Path

SERVER_URL = os.environ.get("VOIDWATCH_SERVER_URL", "http://localhost:8000")
API_KEY    = os.environ.get("VOIDWATCH_API_KEY", "")

_ID_FILE = Path(__file__).parent / ".agent_id"
_FALLBACK_ID_FILE = Path.home() / ".voidwatch" / ".agent_id"


def _load_agent_id() -> str:
    for f in (_ID_FILE, _FALLBACK_ID_FILE):
        try:
            if f.exists():
                val = f.read_text(encoding="utf-8").strip()
                if val:
                    return val
        except OSError:
            pass

    agent_id = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"

    for f in (_ID_FILE, _FALLBACK_ID_FILE):
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(agent_id, encoding="utf-8")
            return agent_id
        except OSError:
            pass

    return agent_id  # in-memory only if all writes fail


AGENT_ID = _load_agent_id()

import socket
import uuid
from pathlib import Path

SERVER_URL = "http://localhost:8000"

_ID_FILE = Path(__file__).parent / ".agent_id"

def _load_agent_id() -> str:
    if _ID_FILE.exists():
        return _ID_FILE.read_text().strip()
    agent_id = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
    _ID_FILE.write_text(agent_id)
    return agent_id

AGENT_ID = _load_agent_id()

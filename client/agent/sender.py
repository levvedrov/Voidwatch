import datetime
import time

import requests

from config import AGENT_ID, AGENT_SECRET, API_KEY, SERVER_URL
from metadata import collect as collect_metadata


def _headers() -> dict:
    if API_KEY:
        return {"X-API-Key": API_KEY}
    if AGENT_SECRET:
        return {"X-Agent-ID": AGENT_ID, "X-Agent-Secret": AGENT_SECRET}
    return {}


def _serialize(events: list) -> dict:
    return {
        "agent_id":  AGENT_ID,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "metadata":  collect_metadata(),
        "processes": [
            {
                "name":              e.name,
                "parent_name":       e.parent_name,
                "command_line":      e.command_line,
                "path":              e.path,
                "pid":               e.pid,
                "parent_pid":        e.parent_pid,
                "cpu_usage":         e.cpu_usage,
                "mem_usage":         e.mem_usage,
                "is_signed":         e.is_signed,
                "sha256":            e.sha256,
                "connection_count":  e.connection_count,
                "destination_ips":   e.destination_ips,
                "destination_ports": e.destination_ports,
                "protocols":         e.protocols,
            }
            for e in events
        ],
    }


def register(metadata: dict) -> bool:
    try:
        resp = requests.post(
            f"{SERVER_URL}/register",
            json={"agent_id": AGENT_ID, "metadata": metadata},
            headers=_headers(),
            timeout=5,
        )
        return resp.ok
    except requests.RequestException:
        return False


def send_telemetry(events: list, retries: int = 2) -> bool:
    payload = _serialize(events)
    for attempt in range(retries):
        try:
            resp = requests.post(
                f"{SERVER_URL}/telemetry",
                json=payload,
                headers=_headers(),
                timeout=10,
            )
            return resp.status_code == 201
        except requests.RequestException:
            if attempt < retries - 1:
                time.sleep(1)
    return False

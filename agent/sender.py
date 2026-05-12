import datetime
import time

import requests

from config import AGENT_ID, API_KEY, SERVER_URL
from metadata import collect as collect_metadata


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
        headers = {"X-API-Key": API_KEY} if API_KEY else {}
        resp = requests.post(
            f"{SERVER_URL}/register",
            json={"agent_id": AGENT_ID, "metadata": metadata},
            headers=headers,
            timeout=5,
        )
        return resp.ok
    except requests.RequestException:
        return False


def send_telemetry(events: list, retries: int = 2) -> bool:
    headers = {"X-API-Key": API_KEY} if API_KEY else {}
    payload = _serialize(events)
    for attempt in range(retries):
        try:
            resp = requests.post(
                f"{SERVER_URL}/telemetry",
                json=payload,
                headers=headers,
                timeout=10,
            )
            return resp.status_code == 201
        except requests.RequestException:
            if attempt < retries - 1:
                time.sleep(1)
    return False

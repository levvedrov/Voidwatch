import datetime

import requests

from config import AGENT_ID, SERVER_URL
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


def send_telemetry(events: list) -> bool:
    try:
        resp = requests.post(
            f"{SERVER_URL}/telemetry",
            json=_serialize(events),
            timeout=10,
        )
        return resp.status_code == 201
    except requests.RequestException:
        return False

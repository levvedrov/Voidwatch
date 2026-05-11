import time

import requests

from config import SERVER_URL
from metadata import collect as collect_metadata
from network_collector import collect_network
from process_collector import collect_all
from sender import register, send_telemetry
from telemetry import TelemetryEvent

REFRESH_INTERVAL = 5


def collect_events() -> list:
    return [
        TelemetryEvent(proc_tel, collect_network(proc_tel.pid))
        for proc_tel in collect_all()
    ]


def _wait_for_backend(timeout: int = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f"{SERVER_URL}/health", timeout=2)
            return
        except requests.RequestException:
            time.sleep(2)


if __name__ == "__main__":
    _wait_for_backend()
    register(collect_metadata())
    while True:
        try:
            send_telemetry(collect_events())
        except Exception:
            pass
        time.sleep(REFRESH_INTERVAL)

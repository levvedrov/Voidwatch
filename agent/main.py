import time

from process_collector import collect_all
from network_collector import collect_network
from telemetry import TelemetryEvent
from sender import send_telemetry

REFRESH_INTERVAL = 5


def collect_events() -> list:
    return [
        TelemetryEvent(proc_tel, collect_network(proc_tel.pid))
        for proc_tel in collect_all()
    ]


if __name__ == "__main__":
    while True:
        try:
            send_telemetry(collect_events())
        except Exception:
            pass
        time.sleep(REFRESH_INTERVAL)

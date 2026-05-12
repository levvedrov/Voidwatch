import logging
import logging.handlers
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path

from metadata import collect as collect_metadata
from network_collector import collect_network
from process_collector import collect_all
from sender import register, send_telemetry
from telemetry import TelemetryEvent

REFRESH_INTERVAL    = 5
COLLECTION_TIMEOUT  = 20  # seconds; PS signature check can take up to 30s

_log_dir = Path.home() / ".voidwatch"
_log_dir.mkdir(exist_ok=True)
_file_handler = logging.handlers.RotatingFileHandler(
    _log_dir / "agent.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

import sys
_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.stream.reconfigure(encoding="utf-8", errors="replace")
_console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[_console_handler, _file_handler],
)
log = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="collector")


def collect_events() -> list:
    return [
        TelemetryEvent(proc_tel, collect_network(proc_tel.pid))
        for proc_tel in collect_all()
    ]


if __name__ == "__main__":
    log.info("Voidwatch agent starting")
    if not register(collect_metadata()):
        log.warning("Initial registration failed -will retry via telemetry")
    while True:
        future = _executor.submit(collect_events)
        try:
            events = future.result(timeout=COLLECTION_TIMEOUT)
        except FutureTimeout:
            log.warning("Collection timed out after %ds -sending heartbeat", COLLECTION_TIMEOUT)
            events = []
        except Exception as exc:
            log.error("Collection failed: %s", exc)
            events = []

        # Always send (even empty list keeps last_seen current on the backend)
        if not send_telemetry(events):
            log.warning("Telemetry send failed -backend may be unreachable")

        time.sleep(REFRESH_INTERVAL)

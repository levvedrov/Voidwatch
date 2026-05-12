import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from network_collector import collect_network
from process_collector import collect_all
from sender import send_telemetry
from telemetry import TelemetryEvent

REFRESH_INTERVAL    = 5
COLLECTION_TIMEOUT  = 20  # seconds; PS signature check can take up to 30s

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
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
    while True:
        future = _executor.submit(collect_events)
        try:
            events = future.result(timeout=COLLECTION_TIMEOUT)
        except FutureTimeout:
            log.warning("Collection timed out after %ds — sending heartbeat", COLLECTION_TIMEOUT)
            events = []
        except Exception as exc:
            log.error("Collection failed: %s", exc)
            events = []

        # Always send (even empty list keeps last_seen current on the backend)
        if not send_telemetry(events):
            log.warning("Telemetry send failed — backend may be unreachable")

        time.sleep(REFRESH_INTERVAL)

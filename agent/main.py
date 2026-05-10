import time

from process_collector import collect_all, ProcessTelemetry
from network_collector import collect_network, NetworkTelemetry
from sender import send_telemetry

REFRESH_INTERVAL = 5


class TelemetryEvent:
    def __init__(self, process_telemetry: ProcessTelemetry, network_telemetry: NetworkTelemetry):
        self.name             = process_telemetry.name
        self.parent_name      = process_telemetry.parent_name
        self.command_line     = process_telemetry.command_line
        self.path             = process_telemetry.path
        self.pid              = process_telemetry.pid
        self.parent_pid       = process_telemetry.parent_pid
        self.cpu_usage        = process_telemetry.cpu_usage
        self.mem_usage        = process_telemetry.mem_usage
        self.is_signed        = process_telemetry.is_signed
        self.sha256           = process_telemetry.sha256
        self.connection_count = network_telemetry.connection_count
        self.destination_ips  = network_telemetry.destination_ips
        self.destination_ports = network_telemetry.destination_ports
        self.protocols        = network_telemetry.protocols


def collect_events() -> list:
    events = []
    for proc_tel in collect_all():
        net_tel = collect_network(proc_tel.pid)
        events.append(TelemetryEvent(proc_tel, net_tel))
    return events


if __name__ == "__main__":
    while True:
        try:
            events = collect_events()
            send_telemetry(events)
        except Exception:
            pass
        time.sleep(REFRESH_INTERVAL)

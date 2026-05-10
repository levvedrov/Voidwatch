import time

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

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


def build_table(events: list[TelemetryEvent]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, show_lines=True, expand=True)

    table.add_column("PID",      style="cyan",    no_wrap=True, width=7)
    table.add_column("Name",     style="white",   no_wrap=True, width=20)
    table.add_column("Parent",   style="white",   no_wrap=True, width=16)
    table.add_column("CPU %",    style="yellow",  no_wrap=True, width=6)
    table.add_column("Mem MB",   style="yellow",  no_wrap=True, width=8)
    table.add_column("Signed",   style="green",   no_wrap=True, width=7)
    table.add_column("Conns",    style="magenta", no_wrap=True, width=6)
    table.add_column("Dest IPs", style="blue",    width=28)
    table.add_column("Ports",    style="blue",    width=16)
    table.add_column("Proto",    style="blue",    no_wrap=True, width=10)
    table.add_column("SHA256",   style="dim",     no_wrap=True, width=16)

    for e in events:
        signed_str = "[green]YES[/green]" if e.is_signed else "[red]NO[/red]"
        ips_str    = "\n".join(e.destination_ips) or "-"
        ports_str  = "\n".join(str(p) for p in e.destination_ports) or "-"
        proto_str  = "\n".join(e.protocols) or "-"
        sha_str    = e.sha256[:16] + "…" if e.sha256 else "-"
        conn_color = "red" if e.connection_count > 0 else "white"

        table.add_row(
            str(e.pid),
            e.name,
            e.parent_name or "-",
            str(e.cpu_usage),
            str(e.mem_usage),
            signed_str,
            f"[{conn_color}]{e.connection_count}[/{conn_color}]",
            ips_str,
            ports_str,
            proto_str,
            sha_str,
        )

    return table


def build_panel(events: list[TelemetryEvent]) -> Panel:
    timestamp = time.strftime("%H:%M:%S")
    title = f"[bold cyan]VOIDWATCH[/bold cyan] [dim]{timestamp}[/dim]  [dim]{len(events)} processes[/dim]"
    return Panel(build_table(events), title=title, border_style="cyan", padding=(0, 1))


def countdown_bar(remaining: int) -> Text:
    filled  = REFRESH_INTERVAL - remaining
    bar     = "█" * filled + "░" * remaining
    return Text(f"  [{bar}]  next refresh in {remaining}s", style="dim")


def collect_events() -> list[TelemetryEvent]:
    events = []
    for proc_tel in collect_all():
        net_tel = collect_network(proc_tel.pid)
        events.append(TelemetryEvent(proc_tel, net_tel))
    return events


if __name__ == "__main__":
    last_panel: Panel = Panel(
        Text("Starting...", style="dim"),
        title="[bold cyan]VOIDWATCH[/bold cyan]",
        border_style="cyan",
        padding=(0, 1),
    )

    with Live(console=Console(), refresh_per_second=8, screen=True) as live:
        while True:
            # collection phase — keep last table visible, spinner below
            spinner = Spinner("dots", text="  collecting telemetry...", style="bold cyan")
            live.update(Group(last_panel, spinner))

            events = collect_events()
            send_telemetry(events)
            last_panel = build_panel(events)

            # countdown phase — show updated table + progress bar
            for remaining in range(REFRESH_INTERVAL, 0, -1):
                live.update(Group(last_panel, countdown_bar(remaining)))
                time.sleep(1)

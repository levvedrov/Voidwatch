import socket
from dataclasses import dataclass

import psutil


@dataclass
class NetworkTelemetry:
    connection_count: int
    destination_ips: list
    destination_ports: list
    protocols: list


def collect_network(pid: int) -> NetworkTelemetry:
    ips = []
    ports = []
    protocols = []

    try:
        connections = psutil.Process(pid).net_connections()
        for conn in connections:
            if conn.raddr:
                ips.append(conn.raddr.ip)
                ports.append(conn.raddr.port)
                if conn.type == socket.SOCK_STREAM:
                    protocols.append('TCP')
                elif conn.type == socket.SOCK_DGRAM:
                    protocols.append('UDP')
                else:
                    protocols.append('UNKNOWN')
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    return NetworkTelemetry(
        connection_count=len(ips),
        destination_ips=ips,
        destination_ports=ports,
        protocols=protocols,
    )

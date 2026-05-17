import os
import platform
import socket


def _get_ip() -> str:
    try:
        # Connect to a routable address to discover the outbound interface IP.
        # No data is actually sent — just determines which interface would be used.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def collect() -> dict:
    return {
        "hostname": socket.gethostname(),
        "os":       f"{platform.system()} {platform.release()}",
        "ip":       _get_ip(),
        "username": os.getenv("USERNAME") or os.getenv("USER") or "unknown",
    }

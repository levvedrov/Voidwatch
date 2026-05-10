import os
import platform
import socket


def collect() -> dict:
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        ip = "unknown"

    return {
        "hostname": socket.gethostname(),
        "os":       f"{platform.system()} {platform.release()}",
        "ip":       ip,
        "username": os.getenv("USERNAME") or os.getenv("USER") or "unknown",
    }

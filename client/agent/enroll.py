"""
Called by install.bat: enroll this machine with the server using an enrollment token.
Writes .agent_id and .agent_secret to the agent directory.
"""
import json
import socket
import sys
from pathlib import Path

import requests

def main():
    if len(sys.argv) < 3:
        print("Usage: enroll.py <server_url> <token>")
        sys.exit(1)

    server_url = sys.argv[1].rstrip("/")
    token      = sys.argv[2]

    try:
        import platform, psutil
        ip = psutil.net_if_addrs().get("Ethernet", [{}])[0].get("address", "unknown")
    except Exception:
        ip = "unknown"

    payload = {
        "token":    token,
        "hostname": socket.gethostname(),
        "os":       sys.platform,
        "ip":       ip,
        "username": Path.home().name,
    }

    try:
        resp = requests.post(f"{server_url}/agents/enroll", json=payload, timeout=10)
    except requests.RequestException as e:
        print(f"Connection error: {e}")
        sys.exit(1)

    if not resp.ok:
        print(f"Enrollment failed: {resp.status_code} {resp.text}")
        sys.exit(1)

    data         = resp.json()
    agent_id     = data["agent_id"]
    agent_secret = data["agent_secret"]
    mode         = data.get("mode", "collect_only")

    base = Path(__file__).parent
    (base / ".agent_id").write_text(agent_id,     encoding="utf-8")
    (base / ".agent_secret").write_text(agent_secret, encoding="utf-8")

    config = {
        "server_url": server_url,
        "api_key": "",
        "mode": mode,
        "collection_interval": 10,
        "collect_command_line": True,
        "collect_network": True,
        "anonymize_paths": False,
    }
    (base / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    print(f"Enrolled as: {agent_id}")
    print(f"Mode: {mode}")

if __name__ == "__main__":
    main()

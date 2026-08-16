"""
Duress-Guard v4: the off-device watcher (client side).

The client runs on the protected machine. It checks in with the watcher server
regularly, and on each poll it reads any commands the owner queued remotely - most
importantly the "arm" command, which triggers the configured duress actions even when
the device is in an attacker's hands.

Wire-in: `startup_guard.py run --server <url>` checks in, polls for commands, and
executes the duress actions if the owner armed the device remotely.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path


def _post(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def check_in(server_url: str, device_id: str, status: str = "ok") -> dict:
    return _post(f"{server_url}/checkin", {"device_id": device_id, "status": status})


def arm(server_url: str, device_id: str) -> dict:
    return _post(f"{server_url}/arm", {"device_id": device_id})


def poll_commands(server_url: str, device_id: str) -> list[str]:
    return _get(f"{server_url}/commands/{device_id}").get("commands", [])


def get_status(server_url: str, device_id: str) -> dict:
    return _get(f"{server_url}/status/{device_id}")


def run_watchdog_cycle(server_url: str, device_id: str) -> dict:
    """One remote cycle: check in, then act on any pending commands.

    Returns the outcome. An 'arm' command means the owner wants the duress actions
    run on this device (e.g., it is lost or in an attacker's hands).
    """
    check_in(server_url, device_id)
    commands = poll_commands(server_url, device_id)
    return {"device_id": device_id, "commands": commands, "armed": "arm" in commands}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Duress-Guard off-device watcher client")
    parser.add_argument("--server", required=True, help="Base URL of the watcher server")
    parser.add_argument("--device-id", default="device-unknown")
    parser.add_argument("--storage-dir", default="", help="Guard config dir (for run)")
    parser.add_argument("--marker-phrase", default="my-settings")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check-in", help="Send a heartbeat")
    sub.add_parser("status", help="Show the device status at the server")
    arm = sub.add_parser("arm", help="Queue an 'arm' command (owner, remote)")
    arm.add_argument("--target", default=None, help="Device to arm (default: this device)")
    poll = sub.add_parser("poll", help="Read pending commands")
    run = sub.add_parser("run", help="Check in, poll, and run duress actions if armed")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "check-in":
        print(json.dumps(check_in(args.server, args.device_id)))
    elif args.command == "status":
        print(json.dumps(get_status(args.server, args.device_id), indent=2))
    elif args.command == "arm":
        print(json.dumps(arm(args.server, args.target or args.device_id)))
    elif args.command == "poll":
        print(json.dumps(poll_commands(args.server, args.device_id)))
    elif args.command == "run":
        outcome = run_watchdog_cycle(args.server, args.device_id)
        print(json.dumps(outcome))
        if outcome["armed"]:
            if not args.storage_dir:
                raise SystemExit("armed remotely, but no --storage-dir given to run the duress actions")
            from duress_guard import _run_configured_duress

            _run_configured_duress(args.storage_dir, args.marker_phrase)
            print("duress-actions-run")


if __name__ == "__main__":
    main()

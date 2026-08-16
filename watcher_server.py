"""
Duress-Guard v4: the off-device watcher (server side).

The weakness of a local watchdog is that an attacker with admin can kill it, disable
its task, or power-cycle the machine, and no user-mode program can stop that. The
escalation is to move the tamper *decision* off the device: the watchdog checks in
with a small server the attacker does not control. If the server stops hearing from
the device, the owner is alerted; and the owner can remotely issue an "arm" command
that the device picks up on its next poll and carries out (encrypt folders / arm
panics) - even if the device is in the attacker's hands.

This module is the server: a dependency-free HTTP service that keeps per-device
state (last check-in, missed flag, pending commands).

SECURITY NOTE, stated plainly: this is a prototype. There is NO authentication and NO
TLS here. A real deployment must run this behind HTTPS with per-device tokens, and
the arm endpoint in particular is powerful (it can trigger encryption on the device),
so it must require the owner's authentication. The design makes the boundaries
obvious so a real implementation has a checklist to fill in.

Endpoints:
  POST /checkin            {"device_id", "status"}        -> device heartbeat
  GET  /status/<device_id>                                -> last check-in + missed flag
  POST /arm                {"device_id"}                  -> queue an "arm" command
  GET  /commands/<device_id>                              -> read + clear pending commands
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class WatcherState:
    """In-memory device registry. Replace with a database in a real deployment."""

    def __init__(self, missed_after_seconds: int = 86400):
        self.devices: dict[str, dict] = {}
        self.missed_after_seconds = missed_after_seconds

    def _record(self, device_id: str) -> dict:
        return self.devices.setdefault(
            device_id, {"last_checkin": 0.0, "missed": False, "commands": []}
        )

    def checkin(self, device_id: str, status: str) -> dict:
        record = self._record(device_id)
        record["last_checkin"] = time.time()
        record["missed"] = False
        record["status"] = status
        return {"ok": True, "device_id": device_id}

    def arm(self, device_id: str) -> dict:
        record = self._record(device_id)
        record["commands"].append("arm")
        return {"ok": True, "device_id": device_id, "queued": len(record["commands"])}

    def commands(self, device_id: str) -> dict:
        record = self._record(device_id)
        pending = list(record["commands"])
        record["commands"].clear()
        return {"device_id": device_id, "commands": pending}

    def status(self, device_id: str, now: float | None = None) -> dict:
        record = self.devices.get(device_id)
        if record is None:
            return {"known": False, "device_id": device_id}
        current = time.time() if now is None else now
        missed = (current - record["last_checkin"]) > self.missed_after_seconds
        record["missed"] = missed
        return {
            "known": True,
            "device_id": device_id,
            "last_checkin": record["last_checkin"],
            "missed": missed,
            "missed_after_seconds": self.missed_after_seconds,
            "status": record.get("status", ""),
        }


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the test output clean
        pass

    def _send(self, payload: dict, code: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_POST(self):  # noqa: N802
        payload = self._read_json()
        if self.path == "/checkin":
            self._send(self.server.state.checkin(payload.get("device_id", ""), payload.get("status", "")))
        elif self.path == "/arm":
            self._send(self.server.state.arm(payload.get("device_id", "")))
        else:
            self._send({"error": "not found"}, 404)

    def do_GET(self):  # noqa: N802
        parts = self.path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "status":
            self._send(self.server.state.status(parts[1]))
        elif len(parts) == 2 and parts[0] == "commands":
            self._send(self.server.state.commands(parts[1]))
        else:
            self._send({"error": "not found"}, 404)


def start_server(host: str, port: int, missed_after_seconds: int) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Start the watcher in a background thread. Returns (server, thread)."""
    server = ThreadingHTTPServer((host, port), _Handler)
    server.state = WatcherState(missed_after_seconds=missed_after_seconds)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Duress-Guard off-device watcher server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--missed-after-seconds", type=int, default=86400)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    server, _ = start_server(args.host, args.port, args.missed_after_seconds)
    print(f"Watcher server on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()

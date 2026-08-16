"""
Duress-Guard v3: startup watchdog (dead-man's switch with tamper counter).

Design, in one paragraph: a scheduled watchdog checks in on a heartbeat. The owner
must confirm (enter the real PIN) inside a window; if the machine is unlocked and the
confirmation lapses, the watchdog first WARNS and, only when explicitly configured to
"act", runs the duress actions (encrypt folders / arm pre-boot panics). Separately,
the watchdog tracks missed heartbeats: if it stops running when it shouldn't
(killed, disabled, or the machine was power-cycled abruptly), the first missed
heartbeat is recorded and alerted, and the next one is the FINAL decision that runs
the duress actions. A clean shutdown (Task Scheduler "AtShutdown" hook calling
`clean-shutdown`) is NOT counted as a missed heartbeat.

Safeguards that keep this safe for the legitimate owner:
- Overdue confirmation alone never destroys anything by default: it warns, and only
  acts if --action-on-overdue act is explicitly configured.
- The final decision runs the *encrypt* path by default, which is reversible with the
  owner's passphrase, not an irreversible wipe.
- Every state transition is recorded in the state file and can be audited.

Honest limits (stated here so they are not papered over):
- A user-mode watchdog cannot stop an admin attacker from killing it, and it does not
  run in Safe Mode by default (see docs/STARTUP_WATCHDOG.md). Its value is tamper
  *detection* and a second layer against casual coercion, not a security boundary.
- The heartbeat relies on the scheduled task staying registered. An attacker with
  admin who knows it exists can remove the task; the remote-alert hook is what tells
  the owner that happened.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from duress_guard import PinManager, should_trigger  # noqa: F401  (reused by CLI)

STATE_NAME = "startup-guard-state.json"

DEFAULT_REQUIRE_EVERY_MINUTES = 480   # how long a confirmation stays valid
DEFAULT_HEARTBEAT_MINUTES = 5         # expected interval between watchdog runs
DEFAULT_HEARTBEAT_GRACE_MINUTES = 15  # extra slack before a gap counts as missed
DEFAULT_MAX_KILL_ATTEMPTS = 2         # first missed = warning, second = final


class StartupGuard:
    def __init__(
        self,
        state_path: Path,
        require_every_minutes: int = DEFAULT_REQUIRE_EVERY_MINUTES,
        heartbeat_minutes: int = DEFAULT_HEARTBEAT_MINUTES,
        heartbeat_grace_minutes: int = DEFAULT_HEARTBEAT_GRACE_MINUTES,
        max_kill_attempts: int = DEFAULT_MAX_KILL_ATTEMPTS,
    ):
        self.state_path = state_path
        self.require_every_minutes = require_every_minutes
        self.heartbeat_interval = (heartbeat_minutes + heartbeat_grace_minutes) * 60
        self.max_kill_attempts = max_kill_attempts
        self._state = self._load()

    def _load(self) -> dict:
        if not self.state_path.exists():
            return {
                "armed": True,
                "initialized": False,
                "confirmed_until": 0.0,
                "last_checkin": 0.0,
                "missed_heartbeats": 0,
                "clean_stop_pending": False,
                "events": [],
            }
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self._state, indent=2), encoding="utf-8")

    def _log_event(self, event: str, now: float) -> None:
        self._state.setdefault("events", []).append(
            {"at": round(now, 1), "event": event}
        )
        self._state["events"] = self._state["events"][-50:]

    def confirm(self, now: float) -> dict:
        """The owner confirms (real PIN). Extends the confirmation window and resets
        the missed-heartbeat counter - a confirmation is the strongest signal that
        the legitimate owner has the machine."""
        self._state["initialized"] = True
        self._state["confirmed_until"] = now + self.require_every_minutes * 60
        self._state["last_checkin"] = now
        self._state["missed_heartbeats"] = 0
        self._state["clean_stop_pending"] = False
        self._log_event("confirmed", now)
        self._save()
        return {"status": "confirmed", "confirmed_until": self._state["confirmed_until"]}

    def clean_shutdown(self) -> dict:
        """Called by a shutdown hook so a normal power-off is not treated as a kill."""
        self._state["clean_stop_pending"] = True
        self._state["missed_heartbeats"] = 0
        self._log_event("clean-shutdown", time.time())
        self._save()
        return {"status": "clean-shutdown-armed"}

    def check(self, now: float, action_on_overdue: str = "warn") -> dict:
        """One watchdog cycle. Returns status and whether a final decision fired."""
        state = self._state
        if not state.get("initialized"):
            # First ever run: establish the baseline without counting a missed beat.
            state["initialized"] = True
            state["last_checkin"] = now
            self._log_event("initialized", now)
        elif state.get("clean_stop_pending"):
            # Previous run ended with a clean shutdown: the gap was expected.
            state["clean_stop_pending"] = False
            state["last_checkin"] = now
            self._log_event("clean-boot-after-shutdown", now)
        elif state["armed"] and now - state.get("last_checkin", 0.0) > self.heartbeat_interval:
            # The watchdog was supposed to be running and was not: missed heartbeat.
            state["missed_heartbeats"] = state.get("missed_heartbeats", 0) + 1
            self._log_event(f"missed-heartbeat #{state['missed_heartbeats']}", now)

        state["last_checkin"] = now
        missed = state.get("missed_heartbeats", 0)
        overdue = now > state.get("confirmed_until", 0.0)

        if missed >= self.max_kill_attempts:
            state["missed_heartbeats"] = 0
            self._log_event("final-decision", now)
            self._save()
            return {"status": "final", "missed_heartbeats": missed, "overdue": overdue}

        self._save()
        if overdue:
            if action_on_overdue == "act":
                return {"status": "act", "missed_heartbeats": missed, "overdue": True}
            return {"status": "overdue-warn", "missed_heartbeats": missed, "overdue": True}
        return {"status": "ok", "missed_heartbeats": missed, "overdue": False}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Duress-Guard startup watchdog")
    parser.add_argument("--storage-dir", required=True)
    parser.add_argument("--marker-phrase", default="my-settings")
    parser.add_argument("--require-every-minutes", type=int, default=DEFAULT_REQUIRE_EVERY_MINUTES)
    parser.add_argument("--heartbeat-minutes", type=int, default=DEFAULT_HEARTBEAT_MINUTES)
    parser.add_argument("--heartbeat-grace-minutes", type=int, default=DEFAULT_HEARTBEAT_GRACE_MINUTES)
    parser.add_argument("--max-kill-attempts", type=int, default=DEFAULT_MAX_KILL_ATTEMPTS)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Print watchdog state")
    confirm = sub.add_parser("confirm", help="Confirm with the real PIN")
    confirm.add_argument("--pin", required=True)
    sub.add_parser("clean-shutdown", help="Mark a clean shutdown")
    run = sub.add_parser("run", help="Run one watchdog cycle")
    run.add_argument("--action-on-overdue", choices=["warn", "act"], default="warn")
    run.add_argument("--now", type=float, default=None, help="Override clock (testing)")
    run.add_argument("--server", default="", help="Watcher server URL for the off-device check-in + command poll (v4)")
    run.add_argument("--device-id", default="device-unknown")
    return parser


def _state_path(storage_dir: str) -> Path:
    return Path(storage_dir) / STATE_NAME


def main() -> None:
    args = build_parser().parse_args()
    now = args.now if getattr(args, "now", None) is not None else time.time()
    guard = StartupGuard(
        _state_path(args.storage_dir),
        require_every_minutes=args.require_every_minutes,
        heartbeat_minutes=args.heartbeat_minutes,
        heartbeat_grace_minutes=args.heartbeat_grace_minutes,
        max_kill_attempts=args.max_kill_attempts,
    )

    if args.command == "status":
        print(json.dumps(guard._state, indent=2))
    elif args.command == "confirm":
        # The real PIN is the confirmation. Verify it against the stored config.
        from duress_guard import DuressActions, _load_config

        _, config = _load_config(args.storage_dir, args.marker_phrase)
        if config is None:
            raise SystemExit("No guard config found - run duress_guard.py init first.")
        result = PinManager(config["pin_config"]).verify(args.pin)
        if result != "normal":
            raise SystemExit(f"confirmation rejected ({result})")
        print(json.dumps(guard.confirm(now)))
    elif args.command == "clean-shutdown":
        print(json.dumps(guard.clean_shutdown()))
    elif args.command == "run":
        result = guard.check(now, args.action_on_overdue)
        print(json.dumps(result))
        local_final = result["status"] in ("final", "act")
        if local_final:
            from duress_guard import _run_configured_duress

            _run_configured_duress(args.storage_dir, args.marker_phrase)
            print("duress-actions-run")
        if args.server:
            # Off-device layer (v4): check in, and act if the owner armed the device
            # remotely - the case where the local watchdog was defeated or the
            # device is in someone else's hands.
            from remote_watcher import run_watchdog_cycle

            outcome = run_watchdog_cycle(args.server, args.device_id)
            print(json.dumps({"remote": outcome}))
            if outcome["armed"] and not local_final:
                from duress_guard import _run_configured_duress

                _run_configured_duress(args.storage_dir, args.marker_phrase)
                print("duress-actions-run (remote arm)")


if __name__ == "__main__":
    main()

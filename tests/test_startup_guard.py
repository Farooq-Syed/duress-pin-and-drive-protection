"""Unit tests for the v3 startup watchdog (dead-man's switch + tamper counter).

Everything runs against a throwaway state file and an explicit clock, so the
heartbeat and kill-counter logic is fully deterministic.
"""

import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from startup_guard import StartupGuard  # noqa: E402

T0 = 1_000_000.0
HOUR = 3600.0
MIN = 60.0


class WatchdogStateTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.state_path = Path(self._temp.name) / "state.json"

    def tearDown(self):
        self._temp.cleanup()

    def _guard(self, **kwargs):
        return StartupGuard(self.state_path, **kwargs)

    def test_confirm_extends_window_and_resets_counter(self):
        guard = self._guard(require_every_minutes=60, max_kill_attempts=2)
        guard.confirm(T0)
        result = guard.check(T0 + 30 * MIN)
        self.assertEqual(result["status"], "ok")

    def test_overdue_warns_without_acting(self):
        guard = self._guard(require_every_minutes=60)
        guard.confirm(T0)
        result = guard.check(T0 + 2 * HOUR)
        self.assertEqual(result["status"], "overdue-warn")
        self.assertTrue(result["overdue"])

    def test_overdue_can_act_when_configured(self):
        guard = self._guard(require_every_minutes=60)
        guard.confirm(T0)
        result = guard.check(T0 + 2 * HOUR, action_on_overdue="act")
        self.assertEqual(result["status"], "act")

    def test_missed_heartbeat_is_recorded_and_second_is_final(self):
        guard = self._guard(
            heartbeat_minutes=5, heartbeat_grace_minutes=15, max_kill_attempts=2
        )
        guard.check(T0)  # first check-in establishes the baseline
        # A long gap with no check-in: the watchdog was not running.
        first = guard.check(T0 + 60 * MIN)
        self.assertEqual(first["missed_heartbeats"], 1)
        self.assertEqual(first["status"], "overdue-warn")  # warning, not final
        # A second long gap: FINAL decision.
        second = guard.check(T0 + 120 * MIN)
        self.assertEqual(second["status"], "final")

    def test_clean_shutdown_is_not_counted_as_kill(self):
        guard = self._guard(heartbeat_minutes=5, heartbeat_grace_minutes=15)
        guard.check(T0)
        guard.clean_shutdown()  # normal power-off
        result = guard.check(T0 + 60 * MIN)  # boot after clean shutdown
        self.assertEqual(result["missed_heartbeats"], 0)
        self.assertNotEqual(result["status"], "final")

    def test_confirm_resets_missed_heartbeats(self):
        guard = self._guard(heartbeat_minutes=5, heartbeat_grace_minutes=15, max_kill_attempts=2)
        guard.check(T0)
        guard.check(T0 + 60 * MIN)  # one missed heartbeat
        guard.confirm(T0 + 90 * MIN)
        # A timely check-in after confirmation must NOT add a missed heartbeat.
        result = guard.check(T0 + 90 * MIN + 60)
        self.assertEqual(result["missed_heartbeats"], 0)
        self.assertEqual(result["status"], "ok")

    def test_state_persists_across_instances(self):
        guard = self._guard()
        guard.check(T0)
        fresh = StartupGuard(self.state_path)
        self.assertEqual(fresh._state["last_checkin"], T0)


if __name__ == "__main__":
    unittest.main()

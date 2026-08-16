"""Unit + integration tests for the v4 off-device watcher.

The state tests run without any network. A lightweight integration test boots the
real HTTP server on an ephemeral port and drives it through the client, so the
full check-in / arm / poll loop is exercised.
"""

import sys
import unittest
import time
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from watcher_server import WatcherState, start_server  # noqa: E402
from remote_watcher import arm, check_in, get_status, poll_commands, run_watchdog_cycle  # noqa: E402

T0 = 1_000_000.0


class WatcherStateTests(unittest.TestCase):
    def test_checkin_records_and_clears_missed(self):
        state = WatcherState(missed_after_seconds=60)
        state.checkin("dev-1", "ok")
        record = state.devices["dev-1"]
        self.assertEqual(record["status"], "ok")
        self.assertFalse(state.status("dev-1", now=record["last_checkin"])["missed"])

    def test_missed_flag_after_timeout(self):
        state = WatcherState(missed_after_seconds=60)
        state.checkin("dev-1", "ok")
        last = state.devices["dev-1"]["last_checkin"]
        self.assertTrue(state.status("dev-1", now=last + 61)["missed"])
        self.assertFalse(state.status("dev-1", now=last + 59)["missed"])

    def test_unknown_device_reports_unknown(self):
        state = WatcherState()
        self.assertFalse(state.status("nope")["known"])

    def test_arm_queues_command_and_poll_consumes_it(self):
        state = WatcherState()
        state.arm("dev-1")
        self.assertEqual(state.commands("dev-1")["commands"], ["arm"])
        # Consumed: a second poll returns nothing.
        self.assertEqual(state.commands("dev-1")["commands"], [])


class ServerClientIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.thread = start_server("127.0.0.1", 0, missed_after_seconds=60)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_full_remote_loop(self):
        check_in(self.url, "dev-9", "ok")
        status = get_status(self.url, "dev-9")
        self.assertTrue(status["known"])
        self.assertFalse(status["missed"])

        arm(self.url, "dev-9")
        outcome = run_watchdog_cycle(self.url, "dev-9")
        self.assertTrue(outcome["armed"])
        # The command is consumed, so a second cycle reports no command.
        self.assertEqual(poll_commands(self.url, "dev-9"), [])


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the duress-guard core logic.

Everything here runs without admin rights or a real Windows lock screen: it pins
down the PIN state machine (normal / duress / invalid / locked), the lockout
behavior, the stealth storage, and the guarded duress actions.
"""

import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import duress_guard  # noqa: E402
from duress_guard import DuressActions, DuressGuard, Lockout, PinManager, StealthStore  # noqa: E402


class PinManagerTests(unittest.TestCase):
    def test_creates_and_verifies_both_pins(self):
        manager = PinManager.new("4821", "9991")
        self.assertEqual(manager.verify("4821"), "normal")
        self.assertEqual(manager.verify("9991"), "duress")
        self.assertEqual(manager.verify("0000"), "invalid")

    def test_pins_must_differ(self):
        with self.assertRaises(ValueError):
            PinManager.new("1111", "1111")

    def test_pins_must_be_numeric_and_long_enough(self):
        with self.assertRaises(ValueError):
            PinManager.new("abcd", "9991")
        with self.assertRaises(ValueError):
            PinManager.new("123", "9991")

    def test_pins_not_stored_in_plaintext(self):
        manager = PinManager.new("4821", "9991")
        config = manager._config
        self.assertNotIn("4821", json_repr(config))
        self.assertNotEqual(config["real_pin"]["hash"], config["duress_pin"]["hash"])

    def test_same_pin_hash_differs_across_salts(self):
        first = PinManager.new("4821", "9991")._config["real_pin"]
        second = PinManager.new("4821", "9991")._config["real_pin"]
        self.assertNotEqual(first["hash"], second["hash"])


def json_repr(obj):
    import json

    return json.dumps(obj)


class LockoutTests(unittest.TestCase):
    def test_locks_after_max_failures(self):
        lockout = Lockout(max_failures=3, delay_seconds=1000)
        self.assertFalse(lockout.is_locked())
        lockout.record_failure()
        lockout.record_failure()
        self.assertFalse(lockout.is_locked())
        lockout.record_failure()
        self.assertTrue(lockout.is_locked())

    def test_reset_clears_failures(self):
        lockout = Lockout(max_failures=2, delay_seconds=1000)
        lockout.record_failure()
        lockout.reset()
        lockout.record_failure()
        self.assertFalse(lockout.is_locked())


class StealthStoreTests(unittest.TestCase):
    def test_write_and_read_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StealthStore(Path(directory), "my phrase")
            store.write({"version": 1, "pin_config": {"x": 1}})
            self.assertTrue(store.config_path.exists())
            self.assertTrue(store.marker_path.exists())
            self.assertEqual(store.read()["version"], 1)

    def test_filename_derived_from_phrase(self):
        first = StealthStore(Path("."), "alpha")
        second = StealthStore(Path("."), "alpha")
        third = StealthStore(Path("."), "beta")
        self.assertEqual(first.config_path.name, second.config_path.name)
        self.assertNotEqual(first.config_path.name, third.config_path.name)

    def test_missing_config_returns_none(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StealthStore(Path(directory), "phrase")
            self.assertIsNone(store.read())


class DuressGuardTests(unittest.TestCase):
    def test_normal_pin_unlocks_and_runs_no_actions(self):
        manager = PinManager.new("4821", "9991")
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "alerts.log"
            guard = DuressGuard(manager, DuressActions(log_file=log_path))
            self.assertEqual(guard.unlock("4821"), "normal")
            self.assertFalse(log_path.exists())

    def test_duress_pin_unlocks_and_silently_logs(self):
        manager = PinManager.new("4821", "9991")
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "alerts.log"
            guard = DuressGuard(manager, DuressActions(log_file=log_path), device_id="test-host")
            # The return value looks like a successful unlock...
            self.assertEqual(guard.unlock("9991"), "duress")
            # ...but the alert was recorded.
            content = log_path.read_text(encoding="utf-8")
            self.assertIn("duress PIN entered", content)
            self.assertIn("test-host", content)

    def test_invalid_pin_counts_toward_lockout(self):
        manager = PinManager.new("4821", "9991")
        guard = DuressGuard(manager, DuressActions(), lockout=Lockout(max_failures=2, delay_seconds=1000))
        self.assertEqual(guard.unlock("0000"), "invalid")
        self.assertEqual(guard.unlock("0000"), "invalid")
        self.assertEqual(guard.unlock("4821"), "locked")
        self.assertEqual(guard.last_event, "locked")

    def test_wipe_is_noop_unless_explicitly_enabled(self):
        manager = PinManager.new("4821", "9991")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "precious"
            target.mkdir()
            (target / "file.txt").write_text("data", encoding="utf-8")
            guard = DuressGuard(manager, DuressActions(wipe_dirs=[str(target)]))
            self.assertEqual(guard.unlock("9991"), "duress")
            # Guarded wipe is off by default: data must be untouched.
            self.assertTrue((target / "file.txt").exists())


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the v2 logon-monitor mode.

The design: two Windows accounts. The normal account's password is the normal login.
A decoy account's password IS the duress password - typing it at the official login
screen logs into the decoy, and a scheduled task (see docs/LOGON_MONITOR.md and
register_logon_task.ps1) invokes `duress_guard.py on-login`, which runs the configured
duress actions. These tests pin the decision logic and the action path without a real
login screen.
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import duress_guard  # noqa: E402

PASSPHRASE = "correct horse battery staple"


class ShouldTriggerTests(unittest.TestCase):
    def test_case_insensitive_match(self):
        self.assertTrue(duress_guard.should_trigger("Decoy", "decoy"))
        self.assertTrue(duress_guard.should_trigger("decoy", "DECOY"))

    def test_mismatch_does_not_trigger(self):
        self.assertFalse(duress_guard.should_trigger("alice", "decoy"))

    def test_empty_expected_never_triggers(self):
        self.assertFalse(duress_guard.should_trigger("decoy", ""))


class OnLoginTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.storage = Path(self._temp.name)
        self.secrets = self.storage / "secrets"
        self.secrets.mkdir()
        (self.secrets / "notes.txt").write_text("secret notes", encoding="utf-8")
        self._old_env = os.environ.get("DURESS_KEY")

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("DURESS_KEY", None)
        else:
            os.environ["DURESS_KEY"] = self._old_env
        self._temp.cleanup()

    def _init_config(self, decoy_user="decoy", panic_targets=""):
        argv = [
            "duress_guard.py", "init",
            "--storage-dir", str(self.storage),
            "--pin", "4821", "--duress-pin", "9991",
            "--encrypt-dirs", str(self.secrets),
        ]
        if panic_targets:
            argv += ["--panic-targets", panic_targets]
        with mock.patch("sys.argv", argv):
            duress_guard.main()

    def test_matching_decoy_logon_runs_encryption(self):
        self._init_config()
        os.environ["DURESS_KEY"] = PASSPHRASE
        output = io.StringIO()
        with mock.patch("getpass.getuser", return_value="decoy"):
            with contextlib.redirect_stdout(output):
                argv = [
                    "duress_guard.py", "on-login",
                    "--storage-dir", str(self.storage),
                    "--expected-user", "decoy",
                ]
                with mock.patch("sys.argv", argv):
                    duress_guard.main()
        self.assertIn("duress-actions-run", output.getvalue())
        # The secret folder was encrypted by the logon trigger.
        self.assertTrue((self.secrets / "notes.txt").read_bytes() != b"secret notes")

    def test_wrong_account_logon_does_nothing(self):
        self._init_config()
        os.environ["DURESS_KEY"] = PASSPHRASE
        output = io.StringIO()
        with mock.patch("getpass.getuser", return_value="alice"):
            with contextlib.redirect_stdout(output):
                with mock.patch(
                    "sys.argv",
                    ["duress_guard.py", "on-login",
                     "--storage-dir", str(self.storage), "--expected-user", "decoy"],
                ):
                    duress_guard.main()
        self.assertIn("not-triggered", output.getvalue())
        self.assertEqual((self.secrets / "notes.txt").read_bytes(), b"secret notes")

    def test_decoy_logon_arms_panic_target(self):
        self._init_config(panic_targets=f"partition:{self.storage.as_posix()}/partition")
        target = self.storage / "partition"
        target.mkdir()
        (target / "x.bin").write_bytes(b"data")
        os.environ["DURESS_KEY"] = PASSPHRASE
        with mock.patch("getpass.getuser", return_value="decoy"):
            with mock.patch(
                "sys.argv",
                ["duress_guard.py", "on-login",
                 "--storage-dir", str(self.storage), "--expected-user", "decoy"],
            ):
                duress_guard.main()
        import panic_boot

        pending = panic_boot.list_pending(self.storage)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["kind"], "partition")


if __name__ == "__main__":
    unittest.main()

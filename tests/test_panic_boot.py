"""Unit tests for the pre-boot panic-target component.

A partition or the whole system can't be wiped from inside the running OS, so the
duress PIN records a panic marker and a pre-boot component processes it at the next
boot. These tests cover marker creation, listing, cancellation, and the guarded dry
run (no destructive action unless DURESS_WIPE_ENABLED=1).
"""

import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import panic_boot  # noqa: E402


class PanicMarkerTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.storage = Path(self._temp.name)
        self.target = self.storage / "partition"
        self.target.mkdir()
        (self.target / "data.bin").write_bytes(b"secret")

    def tearDown(self):
        self._temp.cleanup()

    def test_write_and_list_round_trip(self):
        panic_boot.write_panic_marker(self.storage, "partition", str(self.target))
        pending = panic_boot.list_pending(self.storage)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["kind"], "partition")
        self.assertEqual(pending[0]["target"], str(self.target))

    def test_invalid_kind_rejected(self):
        with self.assertRaises(ValueError):
            panic_boot.write_panic_marker(self.storage, "folder", str(self.target))

    def test_cancel_removes_pending(self):
        panic_boot.write_panic_marker(self.storage, "system", "C:")
        self.assertEqual(panic_boot.cancel_panic(self.storage), 1)
        self.assertEqual(panic_boot.list_pending(self.storage), [])

    def test_dry_run_does_not_wipe(self):
        panic_boot.write_panic_marker(self.storage, "partition", str(self.target))
        performed = panic_boot.process_pending(self.storage)
        self.assertEqual(len(performed), 1)
        self.assertFalse(performed[0]["wiped"])
        self.assertTrue((self.target / "data.bin").exists())
        self.assertEqual(panic_boot.list_pending(self.storage), [])  # consumed


if __name__ == "__main__":
    unittest.main()

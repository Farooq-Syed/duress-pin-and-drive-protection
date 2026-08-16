"""Unit tests for the BitLocker tooling.

These mock the PowerShell subprocess and SMTP, so the tests run on any machine
without admin rights and never touch a real disk or send a real email.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import bitlocker_tool  # noqa: E402


class BitlockerStatusTests(unittest.TestCase):
    def test_parses_status_output(self):
        fake_output = (
            '"Status","Protection","Encryption","Enabled"\n'
            '"FullyEncrypted","On","XtsAes256","100"\n'
        )
        with mock.patch.object(bitlocker_tool, "run_powershell", return_value=fake_output):
            status = bitlocker_tool.bitlocker_status("C:")
        self.assertEqual(status["Status"], "FullyEncrypted")
        self.assertEqual(status["Protection"], "On")
        self.assertEqual(status["Enabled"], "100")

    def test_raises_on_powershell_failure(self):
        with mock.patch.object(
            bitlocker_tool, "run_powershell", side_effect=RuntimeError("denied")
        ):
            with self.assertRaises(RuntimeError):
                bitlocker_tool.bitlocker_status("C:")


class RecoveryKeyTests(unittest.TestCase):
    def test_extracts_recovery_password_from_manage_bde_output(self):
        output = (
            "BitLocker Drive Encryption Configuration Tool\n"
            "Volume C: [OS]\n"
            "Key Protectors:\n"
            "\tTPM\n"
            "\tNumerical Password\n"
            "\t  ID: {abc-123}\n"
            "\t  Numerical Password:\n"
            "\t    123456-789012-345678-901234-567890-123456-789012-345678\n"
        )
        with mock.patch.object(bitlocker_tool, "run_powershell", return_value=output):
            key = bitlocker_tool.get_recovery_key("C:")
        self.assertEqual(key, "123456-789012-345678-901234-567890-123456-789012-345678")

    def test_raises_when_no_key_found(self):
        with mock.patch.object(bitlocker_tool, "run_powershell", return_value="no key here\n"):
            with self.assertRaises(RuntimeError):
                bitlocker_tool.get_recovery_key("C:")


class BackupTests(unittest.TestCase):
    def test_local_backup_writes_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "keys" / "recovery.txt"
            bitlocker_tool.backup_key_local("1234-5678", destination)
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_text(encoding="utf-8").strip(), "1234-5678")

    def test_email_backup_sends_one_message(self):
        smtp_config = {
            "host": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from": "sender@example.com",
        }
        with mock.patch("smtplib.SMTP") as smtp_class:
            bitlocker_tool.backup_key_email("1234-5678", smtp_config, "me@example.com")
            smtp_class.assert_called_once_with("smtp.example.com", 587)
            # "with smtplib.SMTP(...) as server" binds server to __enter__()'s result.
            entered = smtp_class.return_value.__enter__.return_value
            entered.starttls.assert_called_once()
            entered.login.assert_called_once_with("user", "pass")
            entered.sendmail.assert_called_once()
            sent_to = entered.sendmail.call_args[0][1]
            self.assertEqual(sent_to, ["me@example.com"])


if __name__ == "__main__":
    unittest.main()

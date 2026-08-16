"""Unit tests for Duress-Guard v2: encrypt-on-duress.

The encryption uses real Fernet (cryptography package); these tests run on throwaway
temporary directories so no real data is ever touched.
"""

import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import duress_encryption  # noqa: E402

PASSPHRASE = "correct horse battery staple"


class EncryptionRoundTripTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        (self.root / "docs").mkdir()
        (self.root / "docs" / "plan.txt").write_bytes(b"top secret plan")
        (self.root / "keys.txt").write_bytes(b"ssh-rsa AAAA...")
        self.nested = self.root / "docs" / "deep" / "vault.json"
        self.nested.parent.mkdir()
        self.nested.write_bytes(b'{"seed": "abandon copper"}')

    def tearDown(self):
        self._temp.cleanup()

    def test_encrypt_then_decrypt_round_trip(self):
        encrypted = duress_encryption.encrypt_directory(self.root, PASSPHRASE)
        self.assertEqual(len(encrypted), 3)
        self.assertTrue(duress_encryption.is_encrypted(self.root))
        # Files are no longer readable plaintext.
        self.assertNotIn(b"top secret plan", (self.root / "docs" / "plan.txt").read_bytes())

        decrypted = duress_encryption.decrypt_directory(self.root, PASSPHRASE)
        self.assertEqual(len(decrypted), 3)
        self.assertEqual((self.root / "docs" / "plan.txt").read_bytes(), b"top secret plan")
        self.assertEqual(self.nested.read_bytes(), b'{"seed": "abandon copper"}')
        self.assertFalse(duress_encryption.is_encrypted(self.root))

    def test_wrong_passphrase_fails_and_leaves_data_encrypted(self):
        duress_encryption.encrypt_directory(self.root, PASSPHRASE)
        with self.assertRaises(ValueError):
            duress_encryption.decrypt_directory(self.root, "wrong")
        # Still encrypted, and still recoverable with the right passphrase.
        self.assertTrue(duress_encryption.is_encrypted(self.root))
        duress_encryption.decrypt_directory(self.root, PASSPHRASE)
        self.assertEqual((self.root / "keys.txt").read_bytes(), b"ssh-rsa AAAA...")

    def test_decrypt_refuses_unencrypted_directory(self):
        with self.assertRaises(ValueError):
            duress_encryption.decrypt_directory(self.root, PASSPHRASE)
        # Data untouched by the refusal.
        self.assertEqual((self.root / "keys.txt").read_bytes(), b"ssh-rsa AAAA...")

    def test_encrypt_is_idempotent(self):
        duress_encryption.encrypt_directory(self.root, PASSPHRASE)
        self.assertEqual(duress_encryption.encrypt_directory(self.root, PASSPHRASE), [])
        duress_encryption.decrypt_directory(self.root, PASSPHRASE)
        self.assertEqual((self.root / "docs" / "plan.txt").read_bytes(), b"top secret plan")

    def test_keep_set_is_honoured(self):
        encrypted = duress_encryption.encrypt_directory(self.root, PASSPHRASE, keep={"keys.txt"})
        self.assertEqual(len(encrypted), 2)  # keys.txt is untouched
        self.assertEqual((self.root / "keys.txt").read_bytes(), b"ssh-rsa AAAA...")
        duress_encryption.decrypt_directory(self.root, PASSPHRASE)
        self.assertEqual((self.root / "docs" / "plan.txt").read_bytes(), b"top secret plan")


class DeriveKeyTests(unittest.TestCase):
    def test_key_derivation_is_deterministic_per_salt(self):
        salt = b"fixed-salt-1234"
        first = duress_encryption.derive_key(PASSPHRASE, salt)
        second = duress_encryption.derive_key(PASSPHRASE, salt)
        self.assertEqual(first, second)

    def test_different_passphrases_give_different_keys(self):
        salt = b"fixed-salt-1234"
        self.assertNotEqual(
            duress_encryption.derive_key(PASSPHRASE, salt),
            duress_encryption.derive_key("another", salt),
        )


if __name__ == "__main__":
    unittest.main()

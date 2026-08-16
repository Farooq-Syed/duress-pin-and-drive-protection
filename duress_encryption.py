"""
Duress-Guard v2: encrypt-on-duress with a key only the owner holds.

The idea behind v1's wipe action was "if I'm forced to unlock, make sure the coercer
gets nothing." Wipe achieves that but destroys the data — including for the owner.
v2 replaces it with something strictly better for the owner: on a duress PIN, the
sensitive directories are encrypted in place with a key derived from a passphrase
that is *never stored on disk*. To a coercer looking at the machine, the files are
garbage that looks exactly like a ransomware hit. The owner, who knows the
passphrase, decrypts later and loses nothing.

Honest notes:
- This is defensive self-protection: the owner is the only key holder. It is the
  software analogue of "pretend the machine already got attacked."
- The passphrase is the single point of failure. Forget it, and the data is gone for
  real. That trade-off is documented, not hidden.
- Encryption is Fernet (AES-128-CBC + HMAC-SHA256) via the `cryptography` package.
  The key is derived with PBKDF2-HMAC-SHA256 (600k iterations) from the passphrase
  plus a per-directory random salt.
- A marker file records that a directory has been encrypted; decrypt refuses to run
  on a directory without it, so you can't accidentally mangle plaintext.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_NAME = ".guard-salt"
MARKER_NAME = ".guard-encrypted"
MANIFEST_NAME = ".guard-manifest"
PBKDF2_ITERATIONS = 600_000

_RESERVED = {SALT_NAME, MARKER_NAME, MANIFEST_NAME}


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def is_encrypted(root: Path) -> bool:
    return (root / MARKER_NAME).exists()


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and path.name not in _RESERVED:
            yield path


def encrypt_directory(root: Path, passphrase: str, keep: set[str] | None = None) -> list[Path]:
    """Encrypt every file under root in place, leaving a marker and salt behind.

    Idempotent: if the directory already carries the encryption marker, it is left
    untouched. `keep` names a set of file names that must never be touched.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"Directory not found: {root}")
    if is_encrypted(root):
        return []

    keep = keep or set()
    salt_path = root / SALT_NAME
    if salt_path.exists():
        salt = salt_path.read_bytes()
    else:
        salt = os.urandom(16)
        salt_path.write_bytes(salt)

    key = derive_key(passphrase, salt)
    fernet = Fernet(key)

    encrypted: list[Path] = []
    manifest: list[str] = []
    for path in _iter_files(root):
        if path.name in keep or path.name.startswith("."):
            continue
        data = path.read_bytes()
        ciphertext = fernet.encrypt(data)
        _atomic_write(path, ciphertext)
        encrypted.append(path)
        manifest.append(str(path.relative_to(root)))

    (root / MARKER_NAME).write_text("encrypted-by-duress-guard\n", encoding="utf-8")
    (root / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return encrypted


def decrypt_directory(root: Path, passphrase: str) -> list[Path]:
    """Decrypt a directory previously encrypted by encrypt_directory.

    Refuses to run without the marker, so unencrypted data is never touched.
    Raises InvalidToken (wrapped in a clear error) on a wrong passphrase.
    Uses the manifest to know exactly which files were encrypted, so files that
    were intentionally kept in plaintext (the `keep` set) are never touched.
    """
    root = Path(root)
    if not is_encrypted(root):
        raise ValueError(
            f"No encryption marker found in {root} - refusing to touch unencrypted data."
        )

    salt_path = root / SALT_NAME
    if not salt_path.exists():
        raise ValueError("Encryption marker present but salt missing - directory is unrecoverable.")

    manifest_path = root / MANIFEST_NAME
    if not manifest_path.exists():
        raise ValueError("Encryption marker present but manifest missing - directory is unrecoverable.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    key = derive_key(passphrase, salt_path.read_bytes())
    fernet = Fernet(key)

    decrypted: list[Path] = []
    for relative in manifest:
        path = root / relative
        if not path.is_file():
            continue
        ciphertext = path.read_bytes()
        try:
            plaintext = fernet.decrypt(ciphertext)
        except InvalidToken as error:
            raise ValueError(
                f"Wrong passphrase or tampered file: {path}"
            ) from error
        _atomic_write(path, plaintext)
        decrypted.append(path)

    for reserved in (MARKER_NAME, MANIFEST_NAME, SALT_NAME):
        (root / reserved).unlink(missing_ok=True)
    return decrypted


def _atomic_write(path: Path, data: bytes) -> None:
    temp = path.with_name(path.name + ".tmp")
    temp.write_bytes(data)
    os.replace(temp, path)

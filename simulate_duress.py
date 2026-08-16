"""
Duress-Guard v2: controlled simulation of the encrypt-on-duress flow.

This runs the full scenario in a throwaway sandbox directory with fake "sensitive"
files. Nothing here touches a real disk or a real login. It proves:

  1. the normal PIN unlocks and changes nothing;
  2. the duress PIN looks like a successful unlock but encrypts the sensitive
     directory in place - the files become unreadable garbage, i.e. the machine
     "looks like it was hit by ransomware";
  3. the owner, holding the passphrase, decrypts and recovers byte-identical files;
  4. a wrong passphrase fails loudly and leaves the data encrypted;
  5. decrypt refuses to touch a directory that was never encrypted.

Exit code is 0 only if every step passes.

Usage:
    python simulate_duress.py                 # throwaway sandbox, cleaned up
    python simulate_duress.py --sandbox out   # keep the sandbox for inspection
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

import duress_encryption
from duress_guard import DuressActions, DuressGuard, PinManager

REAL_PIN = "4821"
DURESS_PIN = "9991"
PASSPHRASE = "correct horse battery staple"


def _make_sensitive_files(root: Path) -> dict[str, bytes]:
    files = {
        "secrets/passwords.txt": b"master: hunter2\nemail: syed88011@gmail.com\n",
        "secrets/keys.txt": b"aws-access-key: AKIA1234\nprivate-key: ----BEGIN----\n",
        "secrets/notes/wallet.json": b'{"seed": "abandon copper able"}',
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return files


def _read_all(root: Path) -> dict[str, bytes]:
    reserved = (duress_encryption.SALT_NAME, duress_encryption.MARKER_NAME, duress_encryption.MANIFEST_NAME)
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and path.name not in reserved
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sandbox", default=None, help="Keep the sandbox at this path")
    args = parser.parse_args()

    cleanup = args.sandbox is None
    sandbox = Path(args.sandbox) if args.sandbox else Path(tempfile.mkdtemp(prefix="duress-sim-"))
    sensitive = sandbox / "sensitive"
    originals = _make_sensitive_files(sensitive)
    print(f"Sandbox: {sandbox}")

    checks: list[tuple[str, bool]] = []
    manager = PinManager.new(REAL_PIN, DURESS_PIN)
    actions = DuressActions(encrypt_dirs=[str(sensitive)])
    guard = DuressGuard(manager, actions, encryption_passphrase=PASSPHRASE, device_id="sim-host")

    # 1. Normal PIN: unlock, nothing changes.
    result = guard.unlock(REAL_PIN)
    after_normal = _read_all(sensitive)
    checks.append(("normal PIN unlocks cleanly", result == "normal"))
    checks.append(("normal PIN leaves files untouched", after_normal == originals))

    # 2. Duress PIN: returns a success-looking unlock, encrypts in place.
    result = guard.unlock(DURESS_PIN)
    checks.append(("duress PIN looks like a successful unlock", result == "duress"))
    encrypted_state = _read_all(sensitive)
    checks.append(("sensitive files are no longer readable", encrypted_state != originals))
    checks.append(("encryption marker is present", duress_encryption.is_encrypted(sensitive)))

    # 3. Owner decrypts with the passphrase and recovers everything.
    decrypted_paths = duress_encryption.decrypt_directory(sensitive, PASSPHRASE)
    restored = _read_all(sensitive)
    checks.append(("owner decrypts and recovers byte-identical files", restored == originals))
    checks.append(("all original files were touched by encryption", len(decrypted_paths) == len(originals)))
    checks.append(("marker removed after decryption", not duress_encryption.is_encrypted(sensitive)))

    # 4. Wrong passphrase fails loudly.
    duress_encryption.encrypt_directory(sensitive, PASSPHRASE)
    try:
        duress_encryption.decrypt_directory(sensitive, "wrong passphrase")
        checks.append(("wrong passphrase is rejected", False))
    except ValueError:
        checks.append(("wrong passphrase is rejected", True))

    # 5. Decrypt refuses on a never-encrypted directory.
    plain_dir = sandbox / "plain"
    plain_dir.mkdir()
    (plain_dir / "readme.txt").write_text("hello", encoding="utf-8")
    try:
        duress_encryption.decrypt_directory(plain_dir, PASSPHRASE)
        checks.append(("decrypt refuses to touch unencrypted data", False))
    except ValueError:
        checks.append(("decrypt refuses to touch unencrypted data", True))

    # 6. Partition / whole-system targets: duress writes a pre-boot panic marker,
    #    the machine keeps working, and the dry-run wiper touches nothing.
    import panic_boot

    partition_dir = sandbox / "partition"
    partition_dir.mkdir()
    (partition_dir / "sensitive.bin").write_bytes(b"partition secrets")
    partition_guard = DuressGuard(
        PinManager.new(REAL_PIN, DURESS_PIN),
        DuressActions(panic_targets=[{"kind": "partition", "target": str(partition_dir)}]),
        panic_storage_dir=sandbox,
        device_id="sim-host",
    )
    result = partition_guard.unlock(DURESS_PIN)
    pending = panic_boot.list_pending(sandbox)
    checks.append(("duress on a partition target returns success-looking unlock", result == "duress"))
    checks.append(("panic marker is recorded for the next boot", len(pending) == 1 and pending[0]["kind"] == "partition"))
    checks.append(("partition data is untouched until boot-time processing", (partition_dir / "sensitive.bin").exists()))
    performed = panic_boot.process_pending(sandbox)
    checks.append(("boot-time wiper is a guarded dry run (nothing wiped)", performed[0]["wiped"] is False))
    checks.append(("partition data survives the dry run", (partition_dir / "sensitive.bin").read_bytes() == b"partition secrets"))
    checks.append(("processed panic markers are consumed", panic_boot.list_pending(sandbox) == []))

    # 7. Owner can cancel a pending panic before reboot.
    partition_guard.unlock(DURESS_PIN)
    checks.append(("a second duress re-arms the panic marker", len(panic_boot.list_pending(sandbox)) == 1))
    cancelled = panic_boot.cancel_panic(sandbox)
    checks.append(("owner can cancel a pending panic", cancelled == 1 and panic_boot.list_pending(sandbox) == []))

    print()
    failed = 0
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        failed += 0 if passed else 1

    print()
    if failed == 0:
        print(f"Simulation PASSED ({len(checks)}/{len(checks)} checks).")
        if cleanup:
            import shutil

            shutil.rmtree(sandbox, ignore_errors=True)
            print(f"Cleaned up sandbox {sandbox}.")
        else:
            print(f"Sandbox kept at {sandbox} for inspection.")
        return 0
    print(f"Simulation FAILED ({failed} check(s) failed).")
    if cleanup:
        import shutil

        shutil.rmtree(sandbox, ignore_errors=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

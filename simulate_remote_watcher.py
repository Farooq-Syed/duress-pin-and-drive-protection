"""
Duress-Guard v4: controlled simulation of the off-device watcher.

Scenario, in a throwaway sandbox with a real local watcher server:
  1. The device checks in with the watcher -> the server knows it is alive.
  2. The device goes dark (taken offline / the local watchdog was killed) -> the
     server marks the device as MISSED once the timeout passes.
  3. The owner, off-device, issues the remote "arm" command.
  4. The device's next poll reads the command and runs the duress actions even
     though the local machine may be in someone else's hands -> the sensitive
     folder is encrypted (reversible by the owner with the passphrase).

This is the escalation that survives the admin attacker: the decision to act moves
off the device, outside the attacker's reach.

Exit code is 0 only if every check passes.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest.mock as mock
from pathlib import Path

import duress_guard
import duress_encryption
from remote_watcher import arm, check_in, get_status, run_watchdog_cycle
from watcher_server import start_server

REAL_PIN = "4821"
PASSPHRASE = "correct horse battery staple"
DEVICE_ID = "sim-device"


def _init_guard_config(storage: Path, secrets: Path) -> None:
    argv = [
        "duress_guard.py", "init",
        "--storage-dir", str(storage),
        "--pin", REAL_PIN, "--duress-pin", "9991",
        "--encrypt-dirs", str(secrets),
    ]
    with mock.patch("sys.argv", argv):
        duress_guard.main()


def main() -> int:
    sandbox = Path(tempfile.mkdtemp(prefix="duress-v4-"))
    secrets = sandbox / "secrets"
    secrets.mkdir()
    (secrets / "notes.txt").write_bytes(b"secret notes that must be protected")
    os.environ["DURESS_KEY"] = PASSPHRASE
    _init_guard_config(sandbox, secrets)

    server, thread = start_server("127.0.0.1", 0, missed_after_seconds=60)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    checks: list[tuple[str, bool]] = []

    # 1. Device is alive and checks in.
    check_in(url, DEVICE_ID, "ok")
    status = get_status(url, DEVICE_ID)
    checks.append(("watcher knows the device is alive", status["known"] and not status["missed"]))

    # 2. Device goes dark: after the timeout the watcher marks it MISSED.
    record = server.state.devices[DEVICE_ID]
    missed = server.state.status(DEVICE_ID, now=record["last_checkin"] + 61)
    checks.append(("watcher flags a device that stopped checking in", missed["missed"]))

    # 3. Owner arms the device remotely (off-device, outside the attacker's reach).
    arm(url, DEVICE_ID)

    # 4. Device's next poll reads the command and runs the duress actions.
    outcome = run_watchdog_cycle(url, DEVICE_ID)
    checks.append(("device poll retrieves the remote arm command", outcome["armed"]))
    if outcome["armed"]:
        duress_guard._run_configured_duress(str(sandbox), "my-settings")
    checks.append(("remote arm triggers encryption of the sensitive folder", duress_encryption.is_encrypted(secrets)))
    checks.append(("encrypted data is NOT the original plaintext", (secrets / "notes.txt").read_bytes() != b"secret notes that must be protected"))
    duress_encryption.decrypt_directory(secrets, PASSPHRASE)
    checks.append(("owner recovers byte-identical data after remote arm", (secrets / "notes.txt").read_bytes() == b"secret notes that must be protected"))

    # The arm command was consumed by the poll.
    checks.append(("arm command is consumed after the poll", run_watchdog_cycle(url, DEVICE_ID)["armed"] is False))

    print()
    failed = 0
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        failed += 0 if passed else 1

    server.shutdown()
    server.server_close()
    shutil.rmtree(sandbox, ignore_errors=True)
    print()
    if failed == 0:
        print(f"v4 simulation PASSED ({len(checks)}/{len(checks)} checks).")
        return 0
    print(f"v4 simulation FAILED ({failed} check(s) failed).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""
Duress-Guard v3: controlled simulation of the startup watchdog.

Scenario it walks through, in a throwaway sandbox:
  1. The watchdog boots for the first time (baseline established).
  2. The owner confirms with the real PIN -> machine is trusted.
  3. A timely check-in -> everything fine.
  4. The confirmation lapses (machine unlocked, nobody confirmed) -> WARNING only,
     nothing destroyed (the safeguard against the legitimate owner).
  5. The watchdog stops checking in when it should (killed / disabled / abrupt
     power-off) -> first missed heartbeat is recorded and warned about.
  6. A second missed heartbeat -> FINAL decision: the sensitive folders are
     encrypted (reversible by the owner with the passphrase).
  7. Separately, a CLEAN shutdown is proven NOT to count as a missed heartbeat.

Exit code is 0 only if every check passes. Nothing real is touched.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest.mock as mock
from pathlib import Path

import duress_guard
import duress_encryption
from startup_guard import StartupGuard

REAL_PIN = "4821"
PASSPHRASE = "correct horse battery staple"
T0 = 1_000_000.0
HOUR = 3600.0
MIN = 60.0


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
    sandbox = Path(tempfile.mkdtemp(prefix="duress-v3-"))
    secrets = sandbox / "secrets"
    secrets.mkdir()
    (secrets / "notes.txt").write_bytes(b"secret notes that must be protected")
    os.environ["DURESS_KEY"] = PASSPHRASE
    _init_guard_config(sandbox, secrets)

    checks: list[tuple[str, bool]] = []
    guard = StartupGuard(
        sandbox / "startup-guard-state.json",
        require_every_minutes=60,
        heartbeat_minutes=5,
        heartbeat_grace_minutes=15,
        max_kill_attempts=2,
    )

    # 1-3. Baseline, confirm, timely check-in.
    first = guard.check(T0)
    checks.append(("first boot establishes a baseline", first["status"] == "overdue-warn" or first["status"] == "ok"))
    confirmed = guard.confirm(T0 + MIN)
    checks.append(("owner confirms with the real PIN", confirmed["status"] == "confirmed"))
    timely = guard.check(T0 + 2 * MIN)
    checks.append(("timely check-in is fine", timely["status"] == "ok"))

    # 4. Confirmation lapses and the watchdog missed its heartbeat -> FIRST missed
    #    heartbeat recorded, WARNING only, nothing destroyed (safeguard for the owner).
    overdue = guard.check(T0 + 5 * HOUR, action_on_overdue="warn")
    checks.append(("lapsed confirmation + first missed heartbeat warns, not acts", overdue["status"] == "overdue-warn"))
    checks.append(("first missed heartbeat is recorded", overdue["missed_heartbeats"] == 1))
    checks.append(("warning alone touches no data", (secrets / "notes.txt").read_bytes() == b"secret notes that must be protected"))

    # 5. Second missed heartbeat -> FINAL decision: folders encrypted (reversible).
    final = guard.check(T0 + 7 * HOUR)
    checks.append(("second missed heartbeat triggers the final decision", final["status"] == "final"))
    if final["status"] == "final":
        duress_guard._run_configured_duress(str(sandbox), "my-settings")
    checks.append(("sensitive folder is now encrypted", duress_encryption.is_encrypted(secrets)))
    checks.append(("encrypted data is NOT the original plaintext", (secrets / "notes.txt").read_bytes() != b"secret notes that must be protected"))
    # Owner recovery still works (the key is the passphrase, not the watchdog).
    duress_encryption.decrypt_directory(secrets, PASSPHRASE)
    checks.append(("owner recovers byte-identical data after the final decision", (secrets / "notes.txt").read_bytes() == b"secret notes that must be protected"))

    # 7. Clean shutdown is NOT a missed heartbeat.
    guard2 = StartupGuard(
        sandbox / "startup-guard-state2.json",
        require_every_minutes=60, heartbeat_minutes=5, heartbeat_grace_minutes=15,
    )
    guard2.check(T0)
    guard2.clean_shutdown()
    after_boot = guard2.check(T0 + 3 * HOUR)
    checks.append(("clean shutdown is not counted as a kill attempt", after_boot["missed_heartbeats"] == 0 and after_boot["status"] != "final"))

    print()
    failed = 0
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        failed += 0 if passed else 1

    print()
    import shutil

    shutil.rmtree(sandbox, ignore_errors=True)
    if failed == 0:
        print(f"v3 simulation PASSED ({len(checks)}/{len(checks)} checks).")
        return 0
    print(f"v3 simulation FAILED ({failed} check(s) failed).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

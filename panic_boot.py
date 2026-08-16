"""
Duress-Guard v2: pre-boot panic targets (partition / whole-system).

Folder targets are encrypted immediately when the duress PIN is entered, because the
machine is on. A partition or the whole system *cannot* be wiped from inside the
running OS - the live filesystem is locked, and the system partition holds the running
code. The honest design defers those to the next boot:

  1. On a duress PIN, the guard writes a *panic marker* that records the target
     (partition letter or system) and a timestamp.
  2. A pre-boot component (this module, invoked before the OS loads in a real
     deployment; a simulation here) reads pending markers and wipes the recorded
     targets.

The machine still boots and works afterwards, which is exactly the "the attacker can't
tell what's missing, and the owner can feign ignorance" property. The owner knows a
panic marker is pending and can cancel it (delete the marker) before reboot if they
changed their mind.

Reality checks, stated plainly:
- This survives a reboot but NOT an attacker pulling the drive out. That scenario is
  only handled by full-disk encryption (BitLocker), which is in this project's other
  half.
- The wipe is destructive and irreversible. It is guarded exactly like the v1 wipe:
  nothing destructive runs unless DURESS_WIPE_ENABLED=1, and even then only the exact
  targets recorded in markers are touched.
- A real pre-boot wiper is firmware/bootkit territory (documented as future work);
  this module is the tested, safe simulation of that component.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

PANIC_DIR_NAME = ".guard-panic"

VALID_KINDS = {"partition", "system"}


def _panic_dir(storage_dir: Path) -> Path:
    return storage_dir / PANIC_DIR_NAME


def write_panic_marker(storage_dir: Path, kind: str, target: str) -> Path:
    """Record a pending pre-boot wipe. kind: 'partition' or 'system'."""
    if kind not in VALID_KINDS:
        raise ValueError(f"Invalid panic kind: {kind}")
    if not target:
        raise ValueError("Panic target cannot be empty.")
    directory = _panic_dir(storage_dir)
    directory.mkdir(parents=True, exist_ok=True)
    marker = directory / f"{kind}-{int(time.time())}.json"
    marker.write_text(
        json.dumps({"kind": kind, "target": target, "created": int(time.time())}),
        encoding="utf-8",
    )
    return marker


def list_pending(storage_dir: Path) -> list[dict]:
    directory = _panic_dir(storage_dir)
    if not directory.exists():
        return []
    markers = []
    for path in sorted(directory.glob("*.json")):
        markers.append(json.loads(path.read_text(encoding="utf-8")))
    return markers


def cancel_panic(storage_dir: Path) -> int:
    """Cancel all pending panics (the owner changed their mind). Returns count removed."""
    directory = _panic_dir(storage_dir)
    if not directory.exists():
        return 0
    removed = 0
    for path in directory.glob("*.json"):
        path.unlink(missing_ok=True)
        removed += 1
    return removed


def process_pending(storage_dir: Path) -> list[dict]:
    """Run the pre-boot component against pending markers (simulated here).

    Reports each pending target. The actual destructive wipe only executes when
    DURESS_WIPE_ENABLED=1; otherwise this is a dry run that lists what would happen.
    """
    performed: list[dict] = []
    for marker in list_pending(storage_dir):
        record = dict(marker)
        record["wiped"] = False
        if os.environ.get("DURESS_WIPE_ENABLED") == "1":
            # In a real deployment this runs before the OS loads and wipes the
            # partition. In the simulation, `target` is a path we are allowed to
            # test against; the caller decides what it points at.
            if marker["kind"] == "partition" and Path(marker["target"]).exists():
                import shutil

                shutil.rmtree(marker["target"], ignore_errors=True)
                record["wiped"] = True
        performed.append(record)
    # Markers are consumed once processed, exactly as a pre-boot wipe would consume them.
    cancel_panic(storage_dir)
    return performed

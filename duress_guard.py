"""
Duress-Guard: a duress-aware unlock layer prototype.

A user has two PINs. The real PIN unlocks normally. The duress PIN *looks* like a
successful login but is treated as a duress event: the configured actions run
silently (log an alert, optionally email a contact, optionally flag a decoy profile
or a guarded wipe). The machine keeps working in the duress case so the person
forcing the PIN does not notice anything unusual.

Design choices worth knowing:
- PINs are never stored in plaintext; each is stored as salt + SHA-256.
- Comparison is constant-time (hmac.compare_digest) to avoid timing side channels.
- Consecutive invalid attempts trigger a lockout delay (a simple, testable
  rate-limit stand-in; a real credential provider would talk to the OS lockout
  policy).
- Destructive actions (wipe) are off by default and must be explicitly configured.
- Config lives in a user-chosen directory under a filename derived from a marker
  phrase the user remembers, plus a visible-but-innocuous marker file. This is
  stealth storage for convenience, not a security boundary.

This is the testable core of a credential provider. A real provider is C++/COM and
needs a Windows SDK build; see docs/CREDENTIAL_PROVIDER.md.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import smtplib
import time
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_VERSION = 1


def _hash_with_salt(pin: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, 100_000)
    return digest.hex()


def _new_salt() -> bytes:
    return os.urandom(16)


@dataclass
class DuressActions:
    """What happens on a duress PIN. Everything is opt-in."""

    log_file: Path | None = None          # append a silent local alert
    email_to: str | None = None           # send an alert email (needs smtp config)
    decoy: bool = False                   # flag: caller presents a decoy profile
    wipe_dirs: list[str] = field(default_factory=list)  # guarded, off by default
    encrypt_dirs: list[str] = field(default_factory=list)  # encrypt in place (v2)
    panic_targets: list[dict] = field(default_factory=list)  # pre-boot wipes (v2)


class PinManager:
    """Stores and verifies the real and duress PINs (salted hashes)."""

    def __init__(self, config: dict):
        self._config = config

    @classmethod
    def new(cls, real_pin: str, duress_pin: str) -> "PinManager":
        if real_pin == duress_pin:
            raise ValueError("Real PIN and duress PIN must differ.")
        if not real_pin.isdigit() or not duress_pin.isdigit():
            raise ValueError("PINs must be numeric.")
        if len(real_pin) < 4 or len(duress_pin) < 4:
            raise ValueError("PINs must be at least 4 digits.")
        config = {
            "version": CONFIG_VERSION,
            "real_pin": {"salt": _new_salt().hex(), "hash": None},
            "duress_pin": {"salt": _new_salt().hex(), "hash": None},
        }
        manager = cls(config)
        manager.set_pin("real_pin", real_pin)
        manager.set_pin("duress_pin", duress_pin)
        return manager

    def set_pin(self, key: str, pin: str) -> None:
        salt = bytes.fromhex(self._config[key]["salt"])
        self._config[key]["hash"] = _hash_with_salt(pin, salt)

    def _verify(self, key: str, pin: str) -> bool:
        salt = bytes.fromhex(self._config[key]["salt"])
        expected = self._config[key]["hash"]
        actual = _hash_with_salt(pin, salt)
        return hmac.compare_digest(expected, actual)

    def verify(self, pin: str) -> str:
        """Return "normal", "duress", or "invalid"."""
        if self._verify("real_pin", pin):
            return "normal"
        if self._verify("duress_pin", pin):
            return "duress"
        return "invalid"


class Lockout:
    """Simple consecutive-failure lockout. N failures -> wait delay seconds."""

    def __init__(self, max_failures: int = 5, delay_seconds: int = 15):
        self.max_failures = max_failures
        self.delay_seconds = delay_seconds
        self.failures = 0
        self.locked_until = 0.0

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.max_failures:
            self.locked_until = time.monotonic() + self.delay_seconds
            self.failures = 0

    def is_locked(self) -> bool:
        return time.monotonic() < self.locked_until

    def reset(self) -> None:
        self.failures = 0


class StealthStore:
    """Config storage in a user-chosen directory under a derived filename.

    The filename is derived from a marker phrase the user remembers, so the owner
    can always find the config ("I remember the directory and the phrase") while the
    file does not announce itself as security software. A visible marker file also
    records the location in a way only the owner recognizes.
    """

    MARKER_PREFIX = ".keep-"

    def __init__(self, storage_dir: Path, marker_phrase: str):
        self.storage_dir = storage_dir
        stem = hashlib.sha1(marker_phrase.encode("utf-8")).hexdigest()[:12]
        self.config_path = storage_dir / f"cfg-{stem}.json"
        self.marker_path = storage_dir / f"{self.MARKER_PREFIX}{stem}.dat"

    def write(self, payload: dict) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.marker_path.write_text(
            "don't delete - local project settings\n", encoding="utf-8"
        )

    def read(self) -> dict | None:
        if not self.config_path.exists():
            return None
        return json.loads(self.config_path.read_text(encoding="utf-8"))


def send_alert_email(actions: DuressActions, smtp: dict | None, device_id: str) -> None:
    """Send a duress alert email. smtp: {host, port, username, password, from, to}."""
    if actions.email_to is None or not smtp:
        return
    message = (
        f"Subject: Duress alert - {device_id}\n\n"
        f"The duress PIN was entered on {device_id} at "
        f"{time.strftime('%Y-%m-%d %H:%M:%S')}.\n"
    )
    with smtplib.SMTP(smtp["host"], int(smtp["port"])) as server:
        server.starttls()
        server.login(smtp["username"], smtp["password"])
        server.sendmail(smtp["from"], [smtp["to"]], message)


class DuressGuard:
    def __init__(
        self,
        manager: PinManager,
        actions: DuressActions,
        lockout: Lockout | None = None,
        smtp: dict | None = None,
        device_id: str = "device-unknown",
        encryption_passphrase: str | None = None,
        panic_storage_dir: Path | None = None,
    ):
        self.manager = manager
        self.actions = actions
        self.lockout = lockout or Lockout()
        self.smtp = smtp
        self.device_id = device_id
        self.encryption_passphrase = encryption_passphrase
        self.panic_storage_dir = panic_storage_dir or Path(".")
        self.last_event: str | None = None

    def unlock(self, pin: str) -> str:
        """Attempt an unlock. Returns "normal" | "duress" | "locked" | "invalid"."""
        if self.lockout.is_locked():
            self.last_event = "locked"
            return "locked"

        result = self.manager.verify(pin)
        if result == "invalid":
            self.lockout.record_failure()
            self.last_event = "invalid"
            return "invalid"

        self.lockout.reset()
        self.last_event = result
        if result == "duress":
            self._run_duress_actions()
        return result

    def _run_duress_actions(self) -> None:
        if self.actions.log_file is not None:
            line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} duress PIN entered on {self.device_id}\n"
            self.actions.log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.actions.log_file.open("a", encoding="utf-8") as handle:
                handle.write(line)
        if self.actions.email_to is not None:
            send_alert_email(self.actions, self.smtp, self.device_id)
        if self.actions.encrypt_dirs:
            # v2: encrypt in place instead of (or in addition to) wiping. The key
            # comes from a passphrase the owner holds; it is never stored on disk.
            if self.encryption_passphrase is not None:
                from duress_encryption import encrypt_directory

                for directory in self.actions.encrypt_dirs:
                    encrypt_directory(directory, self.encryption_passphrase)
        if self.actions.panic_targets:
            # v2: partition / whole-system targets can't be wiped from inside the
            # running OS, so record a panic marker that a pre-boot component will
            # process at the next boot. The machine keeps working in the meantime.
            from panic_boot import write_panic_marker

            for target in self.actions.panic_targets:
                write_panic_marker(
                    self.panic_storage_dir, target["kind"], target["target"]
                )
        if self.actions.wipe_dirs:
            # Guarded: only runs when explicitly configured. Deliberately no-op in
            # this prototype unless WIPE_ENABLED is set, so a misconfiguration can
            # never destroy data by accident.
            if os.environ.get("DURESS_WIPE_ENABLED") == "1":
                _wipe_directories(self.actions.wipe_dirs)


def _wipe_directories(dirs: list[str]) -> None:
    import shutil

    for directory in dirs:
        path = Path(directory)
        if path.exists() and path.is_dir():
            shutil.rmtree(path, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Duress-Guard unlock layer")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Create or update the PIN configuration")
    init.add_argument("--storage-dir", required=True, help="User-chosen directory")
    init.add_argument("--marker-phrase", default="my-settings", help="Phrase that derives the config filename")
    init.add_argument("--pin", required=True)
    init.add_argument("--duress-pin", required=True)
    init.add_argument("--wipe-dirs", default="", help="Comma-separated dirs for the guarded wipe action")
    init.add_argument("--encrypt-dirs", default="", help="Comma-separated dirs to encrypt on duress (v2)")
    init.add_argument("--panic-targets", default="", help="Comma-separated kind:target pairs for pre-boot wipe, e.g. partition:E:,system:C: (v2)")
    init.add_argument("--log-file", default="", help="Path to a silent alert log")
    init.add_argument("--email-to", default="", help="Email to alert on duress")

    check = sub.add_parser("check", help="Verify a PIN and print the result")
    check.add_argument("--storage-dir", required=True)
    check.add_argument("--marker-phrase", default="my-settings")
    check.add_argument("--pin", required=True)

    login = sub.add_parser(
        "on-login",
        help="Logon-monitor mode: run the configured duress actions when the decoy account logs in (v2).",
    )
    login.add_argument("--storage-dir", required=True)
    login.add_argument("--marker-phrase", default="my-settings")
    login.add_argument("--expected-user", required=True, help="The decoy account whose logon triggers the actions")
    return parser


def _load_config(storage_dir: str, marker_phrase: str) -> tuple[StealthStore, dict | None]:
    store = StealthStore(Path(storage_dir), marker_phrase)
    return store, store.read()


def _parse_panic_targets(raw: str) -> list[dict]:
    targets = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        kind, _, target = entry.partition(":")
        if kind not in {"partition", "system"}:
            raise ValueError(f"Unknown panic kind: {kind}")
        targets.append({"kind": kind, "target": target.strip()})
    return targets


def should_trigger(current_user: str, expected_user: str) -> bool:
    """True when the logged-in user is the decoy account the logon monitor watches."""
    return bool(expected_user) and current_user.strip().lower() == expected_user.strip().lower()


def _run_configured_duress(storage_dir: str, marker_phrase: str) -> None:
    """Load the stored config and run its duress actions (logon-monitor mode).

    The encryption passphrase is taken from the DURESS_KEY environment variable;
    it is never stored on disk. If a configured action needs it and it is missing,
    that action is skipped and the run reports which actions executed.
    """
    store, config = _load_config(storage_dir, marker_phrase)
    if config is None:
        raise SystemExit("No config found - run init first.")

    actions = DuressActions(
        log_file=Path(config["actions"].get("log_file")) if config["actions"].get("log_file") else None,
        email_to=config["actions"].get("email_to") or None,
        wipe_dirs=config["actions"].get("wipe_dirs") or [],
        encrypt_dirs=config["actions"].get("encrypt_dirs") or [],
        panic_targets=config["actions"].get("panic_targets") or [],
    )
    manager = PinManager(config["pin_config"])
    guard = DuressGuard(
        manager,
        actions,
        encryption_passphrase=os.environ.get("DURESS_KEY"),
        panic_storage_dir=Path(storage_dir),
        device_id=f"logon-{os.environ.get('USERNAME', 'unknown')}",
    )
    guard._run_duress_actions()
    print("duress-actions-run")


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "init":
        store = StealthStore(Path(args.storage_dir), args.marker_phrase)
        manager = PinManager.new(args.pin, args.duress_pin)
        actions = DuressActions(
            log_file=Path(args.log_file) if args.log_file else None,
            email_to=args.email_to or None,
            wipe_dirs=[d.strip() for d in args.wipe_dirs.split(",") if d.strip()],
            encrypt_dirs=[d.strip() for d in args.encrypt_dirs.split(",") if d.strip()],
            panic_targets=_parse_panic_targets(args.panic_targets),
        )
        payload = {
            "version": CONFIG_VERSION,
            "pin_config": manager._config,
            "actions": {
                "log_file": str(actions.log_file) if actions.log_file else "",
                "email_to": actions.email_to or "",
                "wipe_dirs": actions.wipe_dirs,
                "encrypt_dirs": actions.encrypt_dirs,
                "panic_targets": actions.panic_targets,
                "decoy": actions.decoy,
            },
        }
        store.write(payload)
        print(f"Config written to: {store.config_path}")
        print(f"Marker file: {store.marker_path}")
    elif args.command == "check":
        store, config = _load_config(args.storage_dir, args.marker_phrase)
        if config is None:
            raise SystemExit("No config found - run init first.")
        manager = PinManager(config["pin_config"])
        result = manager.verify(args.pin)
        print(result)
    elif args.command == "on-login":
        import getpass

        if not should_trigger(getpass.getuser(), args.expected_user):
            print("not-triggered")
            return
        _run_configured_duress(args.storage_dir, args.marker_phrase)


if __name__ == "__main__":
    main()

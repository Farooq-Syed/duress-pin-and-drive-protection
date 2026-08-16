"""
Duress-Guard: BitLocker drive-encryption management with recoverable keys.

This is the half of the project that actually defends against bootable-media
attacks (e.g., Hiren's BootCD). If the drive is BitLocker-encrypted with a strong
pre-boot protector, an attacker booting external media sees only ciphertext; the
password-reset trick that reads the SAM database fails because there is no readable
volume without the key.

The tool wraps the built-in Windows BitLocker tooling (PowerShell / manage-bde) so
nothing here reimplements crypto. It provides:
- status()          - current BitLocker state for a volume
- enable_bitlocker() - turn BitLocker on with a TPM protector (needs admin)
- get_recovery_key() - read the recovery key
- backup_key()       - store the key where the USER chooses: a local file, an
                       email, or printed for manual cloud/offline storage

The email path is opt-in and requires an SMTP config (e.g., a Gmail app password).
Sending a recovery key by email is a convenience; if that mailbox is ever
compromised, so is the disk. The design doc (PAPER.md) covers that trade-off.
"""

from __future__ import annotations

import argparse
import smtplib
import subprocess
from pathlib import Path


def run_powershell(command: str) -> str:
    """Run a PowerShell command and return stdout. Separated so tests can mock it."""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"PowerShell failed: {result.stderr.strip()}")
    return result.stdout


def bitlocker_status(mount_point: str = "C:") -> dict:
    command = (
        "$v = Get-BitLockerVolume -MountPoint " + mount_point + "; "
        "[pscustomobject]@{Status=$v.VolumeStatus; Protection=$v.ProtectionStatus; "
        "Encryption=$v.EncryptionMethod; Enabled=$v.EncryptionPercentage} | ConvertTo-Csv -NoTypeInformation"
    )
    output = run_powershell(command)
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) < 2:
        raise RuntimeError("Could not read BitLocker status.")
    headers = lines[0].replace('"', "").split(",")
    values = lines[1].replace('"', "").split(",")
    return dict(zip(headers, values))


def enable_bitlocker(mount_point: str = "C:", protector: str = "tpm") -> str:
    """Enable BitLocker with a TPM (or password) protector. Requires admin rights."""
    if protector == "tpm":
        command = f"Enable-BitLocker -MountPoint {mount_point} -TpmProtector"
    elif protector == "password":
        command = f"Enable-BitLocker -MountPoint {mount_point} -PasswordProtector"
    else:
        raise ValueError(f"Unsupported protector: {protector}")
    return run_powershell(command)


def get_recovery_key(mount_point: str = "C:") -> str:
    command = f"manage-bde -protectors {mount_point} -get -RecoveryPassword"
    output = run_powershell(command)
    for line in output.splitlines():
        line = line.strip()
        # Recovery keys print as groups of digits, e.g. 123456-123456-...
        if len(line) >= 8 and all(ch.isdigit() or ch == "-" for ch in line):
            return line
    raise RuntimeError("No recovery password found in BitLocker output.")


def backup_key_local(recovery_key: str, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(recovery_key + "\n", encoding="utf-8")
    return destination


def backup_key_email(recovery_key: str, smtp: dict, to: str) -> None:
    """Email the recovery key. smtp: {host, port, username, password, from}."""
    message = (
        f"Subject: BitLocker recovery key\n\n"
        f"Recovery key: {recovery_key}\n\n"
        "Store this somewhere safe and delete this email after saving it.\n"
    )
    with smtplib.SMTP(smtp["host"], int(smtp["port"])) as server:
        server.starttls()
        server.login(smtp["username"], smtp["password"])
        server.sendmail(smtp["from"], [to], message)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BitLocker drive protection")
    parser.add_argument("--mount-point", default="C:")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Show BitLocker status")
    enable = sub.add_parser("enable", help="Enable BitLocker (admin required)")
    enable.add_argument("--protector", choices=["tpm", "password"], default="tpm")

    backup = sub.add_parser("backup-key", help="Export and store the recovery key")
    backup.add_argument("--method", choices=["local", "email", "print"], required=True)
    backup.add_argument("--dest", default="recovery_key.txt", help="Local destination file")
    backup.add_argument("--to", default="", help="Email recipient for --method email")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "status":
        status = bitlocker_status(args.mount_point)
        for key, value in status.items():
            print(f"{key}: {value}")
    elif args.command == "enable":
        enable_bitlocker(args.mount_point, args.protector)
        print(f"BitLocker enabled on {args.mount_point}. "
              "Run --backup-key to store the recovery key somewhere safe.")
    elif args.command == "backup-key":
        recovery_key = get_recovery_key(args.mount_point)
        if args.method == "print":
            print(recovery_key)
        elif args.method == "local":
            path = backup_key_local(recovery_key, Path(args.dest))
            print(f"Recovery key written to: {path}")
        elif args.method == "email":
            if not args.to:
                raise SystemExit("--method email requires --to")
            smtp = {
                "host": input("SMTP host: ").strip() or "smtp.gmail.com",
                "port": int(input("SMTP port: ").strip() or "587"),
                "username": input("SMTP username: ").strip(),
                "password": input("SMTP app password: ").strip(),
                "from": input("From address: ").strip(),
            }
            backup_key_email(recovery_key, smtp, args.to)
            print(f"Recovery key emailed to {args.to}.")


if __name__ == "__main__":
    main()

# Duress-Guard: a layered duress-PIN and drive-protection project

**Farooq Syed** · M.S. in Computer and Information Security Systems, Eastern Illinois University · 2026

*Prototype for a personal-device protection tool: a duress-aware unlock layer plus
BitLocker drive encryption with recovery-key backup to a user-chosen location.
Developed with AI coding assistance; the design, threat model, and code were
directed, reviewed, and verified by the author. This is a defensive, anti-theft
project for protecting a user's own device.*

## What this is

Windows has no supported way for a normal application to replace the login screen, and
any tool that hides files is powerless against an attacker who boots external media.
This project takes the honest, layered approach to the same goal:

1. **A duress-aware unlock layer** (`duress_guard.py`) — a real, testable
   implementation of a duress PIN: the user enters either their real PIN or a duress
   PIN, and the system responds differently depending on which one it was. The duress
   path can silently alert a contact, drop the user into a decoy profile, or trigger
   a guarded wipe — whichever the user configures.
2. **Drive encryption with recoverable keys** (`bitlocker_tool.py`) — enables
   BitLocker (the *actual* defense against bootable-media attacks like Hiren's
   BootCD), exports the recovery key, and stores it where the user chooses: a local
   file in their selected directory, an email, or a location they control (GDrive,
   etc.).
3. **Stealth storage** — configuration and keys live in a user-selected directory,
   not a well-known path, with a marker file so the *owner* can always find it.

## What this is NOT (read this first)

- It does **not** replace the Windows login screen. See `docs/CREDENTIAL_PROVIDER.md`
  for what that actually requires (a C++ credential provider) and why the logic here
  is the part you can prototype and test.
- Hiding files is **obscurity, not security**. Against a bootable forensics/repair
  tool, only encryption matters.
- Encryption is not a silver bullet either: an attacker with physical access *before*
  the machine boots can still attempt evil-maid or cold-boot attacks. Secure Boot +
  TPM-based BitLocker + a strong PIN raise the bar; nothing removes it entirely.

## Layout

```text
.
|-- duress_guard.py          # PIN management, verify, lockout, duress actions
|-- bitlocker_tool.py        # BitLocker status/enable + recovery-key backup
|-- requirements.txt
|-- README.md
|-- PAPER.md                 # design, threat model, honest limitations
|-- docs/
|   `-- CREDENTIAL_PROVIDER.md
|-- tests/
|   |-- test_duress.py
|   `-- test_bitlocker.py
```

## Quick start

```powershell
python -m pip install -r requirements.txt
python -m pytest            # run the test suite (no admin needed)

# Duress layer: configure a real PIN + duress PIN
python duress_guard.py --init --storage-dir "D:\MyStuff\.config" --pin 4821 --duress-pin 9991

# BitLocker tool: check status, enable, back up the recovery key
python bitlocker_tool.py --status
python bitlocker_tool.py --enable
python bitlocker_tool.py --backup-key --method email --to mybackup@gmail.com
```

Every destructive action is off by default and must be explicitly configured.

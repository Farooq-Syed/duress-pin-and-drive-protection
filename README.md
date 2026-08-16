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
   path can silently alert a contact, drop the user into a decoy profile, encrypt
   sensitive folders, or arm a pre-boot partition wipe — whichever the user configures.
2. **Drive encryption with recoverable keys** (`bitlocker_tool.py`) — enables
   BitLocker (the *actual* defense against bootable-media attacks like Hiren's
   BootCD), exports the recovery key, and stores it where the user chooses: a local
   file in their selected directory, an email, or a location they control (GDrive,
   etc.).
3. **Stealth storage** — configuration and keys live in a user-selected directory,
   not a well-known path, with a marker file so the *owner* can always find it.

## v2 additions

- **Encrypt-on-duress instead of wipe** (`duress_encryption.py`). On a duress PIN,
  configured folders are encrypted in place with a key derived from a passphrase only
  the owner holds. To a coercer the files look like a ransomware hit; the owner
  decrypts later and loses nothing. Real Fernet crypto (AES-128-CBC + HMAC), not a toy.
- **Configurable targets.** The user picks what the duress PIN protects: a **folder**
  (encrypted immediately, machine on), a **partition**, or the **whole system** (panic
  marker processed at next boot by a pre-boot component — you can't wipe the running
  OS from inside it). Machine keeps working afterward, so nothing looks wrong.
- **Controlled simulation** (`simulate_duress.py`). Runs the whole scenario in a
  throwaway sandbox: normal unlock, duress unlock, files become unreadable garbage,
  owner decrypts byte-identical, wrong passphrase rejected, panic markers armed/cancelled.
  18 checks, all passing.
- **Logon monitor** (`on-login` mode + `register_logon_task.ps1`). Duress through the
  *official* login screen using two accounts: the decoy account's password IS the
  duress password, and a scheduled task runs the duress actions when that account logs
  in. No custom login screen needed. See `docs/LOGON_MONITOR.md`.

## v3 additions

- **Startup watchdog** (`startup_guard.py`). A dead-man's switch with a tamper counter:
  the owner confirms with the real PIN inside a window; if confirmation lapses it
  warns (never destroys on its own), and if the watchdog stops checking in when it
  should (killed / task disabled / abrupt power-off) the first missed heartbeat is
  recorded, the second triggers the final decision (encrypt folders / arm panics).
  A clean shutdown is not counted. Tested end-to-end by `simulate_startup_guard.py`
  (11/11). Safe-Mode limits are documented honestly in `docs/STARTUP_WATCHDOG.md`.

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
|-- duress_guard.py          # PIN management, verify, lockout, duress actions + on-login mode
|-- duress_encryption.py     # v2: encrypt-on-duress (Fernet, owner-held key)
|-- panic_boot.py            # v2: pre-boot panic markers for partition/system targets
|-- bitlocker_tool.py        # BitLocker status/enable + recovery-key backup
|-- simulate_duress.py       # v2: controlled simulation of the whole flow
|-- startup_guard.py         # v3: startup watchdog (dead-man's switch + tamper counter)
|-- simulate_startup_guard.py# v3: controlled simulation of the watchdog
|-- register_logon_task.ps1  # v2: register the logon-monitor scheduled task
|-- requirements.txt
|-- README.md
|-- PAPER.md                 # design, threat model, honest limitations
|-- docs/
|   |-- CREDENTIAL_PROVIDER.md
|   |-- LOGON_MONITOR.md
|   `-- STARTUP_WATCHDOG.md
|-- tests/
|   |-- test_duress.py
|   |-- test_bitlocker.py
|   |-- test_encryption.py
|   |-- test_panic_boot.py
|   |-- test_login_monitor.py
|   `-- test_startup_guard.py
```

## Quick start

```powershell
python -m pip install -r requirements.txt
python -m pytest            # run the test suite (no admin needed)
python simulate_duress.py   # controlled simulation of the v2 flow

# Duress layer: configure a real PIN + duress PIN
python duress_guard.py --init --storage-dir "D:\MyStuff\.config" --pin 4821 --duress-pin 9991
python duress_guard.py --init --storage-dir "D:\MyStuff\.config" --pin 4821 --duress-pin 9991 `
    --encrypt-dirs "D:\MyStuff\secrets" --panic-targets "partition:E:,system:C:"

# BitLocker tool: check status, enable, back up the recovery key
python bitlocker_tool.py --status
python bitlocker_tool.py --enable
python bitlocker_tool.py --backup-key --method email --to mybackup@gmail.com
```

Every destructive action is off by default and must be explicitly configured.

# The logon monitor: duress through the official login screen

## The idea

"Do not replace the login screen. Let the real one accept both a normal password and
a duress password, and only run the duress actions when the duress one is typed."

The OS will not let a normal program read what is typed at the login screen — that
runs on the secure desktop. But the same user-visible behavior is achievable with
two accounts:

- **Normal account** — its password is the everyday login. Nothing special happens.
- **Decoy account** — its password **is** your duress password. Typing it at the
  official screen logs you into the decoy account, which looks like a normal desktop.
  A scheduled task registered for that account fires `duress_guard.py on-login`, which
  runs whatever duress actions you configured: encrypt the sensitive folders, arm the
  pre-boot partition wipes, send the alert.

To anyone standing over the user, the login "worked" and the machine behaves normally.
That is exactly the intended property. The owner knows the duress password is actually
the decoy account's login, and can later decrypt everything.

## Why two accounts and not two passwords on one account

Windows only ever accepts the single real password of the account you name. The
"one account, two passwords" version is only possible with a **credential provider**
(C++/COM), which is the documented follow-up in CREDENTIAL_PROVIDER.md. The two-account
layout reaches the same effect with standard Windows tooling, no C++.

## Setup

1. Create the decoy account (standard user, non-admin is fine).
2. Configure the guard with the actions you want:
   ```powershell
   python duress_guard.py --init --storage-dir "D:\MyStuff\.config" --pin 4821 --duress-pin 9991 `
       --encrypt-dirs "D:\MyStuff\secrets" --panic-targets "partition:E:,system:C:"
   ```
   (The `--pin`/`--duress-pin` here are the values the guard logic checks when it
   runs interactively; for the logon monitor the decoy *account password* is the
   trigger.)
3. Set the encryption passphrase in the decoy account's environment:
   `setx DURESS_KEY "your passphrase"` (run once in that account).
4. Register the task (admin):
   ```powershell
   .\register_logon_task.ps1 -DecoyUser "decoy" -PythonExe "C:\Python312\python.exe" `
       -ScriptDir "D:\DuressGuard" -StorageDir "D:\MyStuff\.config"
   ```
5. Test in a VM: log into the decoy account and confirm the sensitive folder is now
   encrypted (marker present) and the partition panic marker is armed.

## Honest limitations

- The duress action only fires at the *decoy account's* logon. If the coercer uses
  the normal account, nothing happens (that is the point).
- The logon monitor runs after boot. It does nothing about the "drive pulled out and
  booted with Hiren's" scenario — only full-disk encryption (BitLocker, in this
  project) covers that.
- The passphrase travels through the decoy account's environment. A local attacker
  with admin on the decoy account could read it; a real deployment should fetch it
  from a protected store or hardware key.

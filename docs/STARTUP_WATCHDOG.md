# The startup watchdog (v3): dead-man's switch + tamper counter

## What it does

A scheduled watchdog that turns "don't let an intruder just keep the machine" into a
safe, testable mechanism:

- **Confirmation window.** After the machine is unlocked, the owner confirms with the
  real PIN (`startup_guard.py confirm --pin <real-pin>`). That confirmation stays
  valid for a window you set (default 8 hours, so the legitimate owner is not nagged).
  If the confirmation lapses, the watchdog first **warns**; it only runs the duress
  actions if you explicitly configure `--action-on-overdue act`.
- **Heartbeat + tamper counter.** The watchdog is meant to check in every few minutes.
  If it stops checking in when it shouldn't (killed, its task disabled, or the machine
  was power-cycled abruptly), the first missed heartbeat is **recorded and warned**;
  the next one is the **final decision** and runs the duress actions. A clean shutdown
  (Task Scheduler `AtShutdown` hook calling `clean-shutdown`) is not counted.
- **Final decision** runs the reversible path by default: folders get encrypted with
  the owner's passphrase, and/or pre-boot panic markers are armed. Wipe stays
  triple-guarded and off.

## The safeguards that make this safe for the owner

1. Overdue confirmation alone destroys nothing: it warns, and only acts when
   explicitly configured. Forgetting your own PIN should cost a warning, not your data.
2. The final decision encrypts (recoverable) rather than wipes.
3. Every transition is recorded in the state file (audit trail).

## Honest limits (do not skip this section)

- **A user-mode watchdog cannot stop a determined attacker.** One with admin can kill
  the process, remove the scheduled task, or boot around it. The watchdog's real value
  is *tamper detection* — the remote-alert hook tells you someone tried — and a second
  layer against casual coercion, not a security boundary.
- **Safe Mode:** a Task Scheduler startup task does **not** run in Safe Mode, by
  design. Making a Windows *service* load in Safe Mode is possible (SafeBoot registry
  keys) but fragile, and it only matters if the drive is not already BitLocker-protected:
  on an encrypted drive, Safe Mode boot still requires the pre-boot key, so an attacker
  cannot get to Safe Mode without it. Encryption, again, is the foundation.
- **The drive-pulled-out scenario is still BitLocker's job.** If the attacker removes
  the drive, the watchdog never runs. Only full-disk encryption (the other half of this
  project) covers that.

## Setup

1. Configure the guard with the actions you want (see README).
2. Register the watchdog on a periodic schedule, e.g. via Task Scheduler:
   - Trigger: at logon + repeat every 5 minutes.
   - Action: `python startup_guard.py --storage-dir "D:\MyStuff\.config" run`
3. Register a shutdown hook: Task Scheduler trigger `AtShutdown`,
   action `python startup_guard.py --storage-dir "D:\MyStuff\.config" clean-shutdown`.
4. The owner confirms after boot: `python startup_guard.py --storage-dir ... confirm --pin <real-pin>`.
5. Optional remote alert: wire the `email_to` action so a missed heartbeat also pings
   you off-device.

## Testing

```powershell
python -m pytest tests/test_startup_guard.py
python simulate_startup_guard.py
```

Both are green: 8 unit tests + 11 simulation checks covering baseline, confirm, warn,
first/second missed heartbeat, final decision, owner recovery, and clean shutdown.

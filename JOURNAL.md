# Duress-Guard: development journal

## Why this project exists

A recurring idea that comes up when people talk about protecting their own devices:
"what if I had a PIN that worked but didn't?" A duress PIN, plus the worry that a
thief can boot a repair disk and crack the login. The useful part is separating the
two problems, because they have different answers: coercion is a duress problem, and
bootable-media cracking is an encryption problem.

## What I learned while building it

- **You can't replace the login screen with an app.** I knew this was a C++/COM
  credential provider going in, but it's worth stating plainly in the docs so the
  project doesn't promise something it can't deliver. The testable thing is the logic
  and the threat model, not the logon UI.
- **Hiding files does nothing against a boot disk.** If the drive isn't encrypted,
  the attacker reads the raw disk and the "hidden" config is just bytes. I made the
  stealth storage a convenience feature with an honest label rather than a security
  claim. The actual defense is BitLocker, so I built a turnkey wrapper around the OS's
  own tooling instead of reimplementing crypto.
- **The wipe feature is the dangerous one.** I made it opt-in, and then guarded it a
  second time behind an environment flag so a misconfiguration can't destroy data. A
  defensive tool should be *incapable* of nuking the owner's files by accident.
- **A Python bug that was actually a PowerShell bug.** The BitLocker status command
  uses a PowerShell hashtable `@{...}`, and Python's `.format()` was trying to
  interpolate `{Status=...}` as a field. Fixing it taught me to look for brace
  collisions between the two languages before blaming the shell.

## State

20 tests, all green. Core: PIN state machine (salted hashes, constant-time compare,
lockout), duress actions (silent log, email, guarded wipe, decoy flag), stealth
storage, BitLocker status/enable/recovery-key backup (local / email / print). The
credential-provider path is documented in docs/CREDENTIAL_PROVIDER.md as a C++ follow-up.

## v2: encrypt instead of wipe, panic targets, logon monitor

Three big changes, driven by a threat-model discussion:

- **Encrypt-on-duress.** Wipe destroys the owner's data too. v2 encrypts the
  sensitive folders in place with a key from a passphrase only the owner holds. To a
  coercer it looks exactly like a ransomware hit; the owner recovers everything.
  Real Fernet, not a toy. A unit test caught a real design flaw here: decrypt had to
  know which files were actually encrypted, so I added a manifest. Good bug to catch.
- **Configurable targets + pre-boot panic.** A folder can be encrypted immediately;
  a partition or the whole system cannot be wiped from inside the running OS, so the
  duress PIN arms a panic marker processed at next boot by a pre-boot component. The
  machine keeps working after a duress login, which is the "nothing looks wrong"
  property the user wanted. The wiper is triple-guarded and tested as a dry run.
- **Logon monitor.** The user's instinct was right: don't build a custom login screen,
  use the official one. A normal program can't read login-screen input (secure
  desktop), but two accounts achieve the same effect: the decoy account's password IS
  the duress password, and a scheduled task fires the actions on its logon. Documented
  honestly, including that the "one account, two passwords" version needs the C++
  credential provider.

The threat-model correction that mattered most: the drive-pulled-out + Hiren's
scenario is NOT a duress-PIN problem (the PIN never runs), it is a BitLocker problem,
and the design now says so explicitly.

State: 37 tests green, simulation 18/18.

## v3: startup watchdog (dead-man's switch + tamper counter)

The user's idea: a startup program that asks for a password after unlock, acts if it
is not given, records the first attempt to kill it, and makes the next attempt final.

I built it, but not exactly as described, and the differences are the interesting
part:

- **Overdue confirmation never destroys on its own.** The owner who forgets the PIN
  is the most likely false-positive victim, so "no confirmation" WARNS first and only
  acts when explicitly configured. A dead-man's switch that punishes its owner is not
  a feature.
- **The tamper counter is a heartbeat, not a "kill detection".** A user-mode program
  cannot actually tell when an admin killed it. What it CAN detect is "the watchdog
  stopped checking in when it should" - which is the honest signal, and it has the
  same user-visible behavior: first missed beat recorded, second is final.
- **Clean shutdown is not a kill.** An AtShutdown hook distinguishes a normal
  power-off from a power-cycle by someone who did not want the watchdog running.
- **Safe Mode is documented, not faked.** Startup tasks don't run in Safe Mode by
  design. I wrote down the reality (encryption is what actually gates Safe Mode on an
  encrypted drive) rather than claiming it would "work in safe mode if possible".

The one genuinely strong idea in the request was the right one: encryption makes the
whole thing possible, because the "final decision" can be a *reversible* encryption
instead of a destructive wipe.

State: 44 tests green; v3 simulation 11/11; v2 simulation 18/18.

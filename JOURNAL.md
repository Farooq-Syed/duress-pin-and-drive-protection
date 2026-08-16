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

# Duress-Guard: design, threat model, and honest limitations

**Farooq Syed** · M.S. in Computer and Information Security Systems, Eastern Illinois University · 2023

*Prototype for personal-device protection: a duress-aware unlock layer plus BitLocker
drive encryption with user-chosen key backup. Defensive, anti-theft research.
Developed with AI coding assistance; design and code directed, reviewed, and verified
by the author.*

## 1. The problem, as a user would describe it

"Someone might force me to unlock my machine, or steal it and crack the login with a
bootable tool. I want a login that does not behave like the normal one when I am
under duress, and I want my data to be useless to a thief even if they boot around
the login."

Two separate threats hide in that sentence, and the fix is different for each:

- **Threat A — coercion:** the owner is *forced* to unlock. The answer is a **duress
  PIN**: an input that looks like a successful login but is not a normal one.
- **Threat B — theft + offline cracking:** the device is gone and the attacker boots
  external media (Hiren's BootCD and friends) to reset the password or read the disk.
  The answer is **full-disk encryption**, because a bootable tool cannot read
  ciphertext, and the password-reset trick depends on reading an unencrypted SAM.

A third desire — "don't store the config where everyone looks" — is real but must be
labeled honestly: it is obscurity and convenience, not a security boundary.

## 2. What the prototype does

**Duress layer (`duress_guard.py`).** A PIN state machine with salted, hashed PINs,
constant-time comparison, and a consecutive-failure lockout. Entering the duress PIN
returns a success-looking result while silently running the configured actions:

- append a local alert log,
- optionally email a contact,
- optionally signal a decoy profile (prototype flag; a real provider would present a
  sandboxed/limited desktop),
- optionally trigger a **guarded** wipe — off by default, and even when configured it
  is a no-op unless `DURESS_WIPE_ENABLED` is set, so a misconfiguration can never
  destroy data by accident.

**Drive protection (`bitlocker_tool.py`).** Wraps the OS's own BitLocker tooling:
status check, enable (TPM or password protector), read the recovery key, and store it
where the *user* chooses — a local file, an email, or printed for manual storage in
GDrive/offline. Nothing here reimplements cryptography; it makes the OS's encryption
turnkey and recoverable.

**Stealth storage (`StealthStore`).** The user picks a directory and a marker phrase
they remember. The config filename is derived from the phrase, and an innocuous marker
file records the location. The owner can always find it; a stranger skimming the
folder sees nothing labeled "security."

## 3. Threat model

Assumes: the owner is the legitimate user; the attacker has physical access and wants
data or access; the owner may be coerced into unlocking.

| Attack | Defended by | Residual risk |
|---|---|---|
| Bootable media (Hiren's) password reset | BitLocker full-disk encryption | None, if volume is fully encrypted and key unknown |
| Force the owner to unlock | Duress PIN → decoy / alert / guarded wipe | Owner may be hurt before entering it; nothing software fixes that |
| Sniff the PIN (shoulder/keylogger) | None in this prototype | Real-world: hardware or behavioral PIN entry |
| Evil maid (tamper before boot) | Secure Boot + TPM-protected BitLocker (config) | TPM reset attacks, cheap DMA attacks in some hardware |
| Cold-boot memory attack | None | Requires physical access + memory retention; mitigations are hardware-specific |
| Read the "hidden" config | Nothing — it is plaintext | Encryption of the config is future work |

The table says the important thing plainly: **the bootable-media attack is defeated by
encryption, and only by encryption.** Hiding the file that runs the duress layer does
not matter to an attacker who can read the raw disk; it matters only to a casual
browser of the filesystem.

## 4. Design decisions and why

- **Salted SHA-256 (PBKDF2) for PINs, never plaintext.** A PIN is low-entropy; hashing
  without salt would be trivially reversible by dictionary.
- **Constant-time comparison (`hmac.compare_digest`).** Keeps the "which PIN did they
  enter" answer from leaking through timing.
- **Guard every destructive action.** Wipe is the one action that can cause
  unrecoverable harm, so it is triple-guarded (config + env flag + code review).
- **Wrap the OS, don't reimplement.** BitLocker is already the industry answer for
  Threat B; a from-scratch disk crypto tool in a portfolio would be a liability, not
  an asset.
- **User chooses the storage location.** Matches the requirement ("the user will know
  where it lies") and avoids the false promise that there is a universally "safe" path.

## 5. Honest limitations

- This is **not** a Windows credential provider. It cannot replace the login screen.
  See `docs/CREDENTIAL_PROVIDER.md` for what that requires. The value delivered here is
  the logic, the threat model, and the testable prototype.
- **Obscurity is not security.** The stealth storage is convenience.
- **Email key backup trades one risk for another.** If that mailbox is compromised, so
  is the disk. The tool says so when it sends.
- The lockout is a rate-limit stand-in; the OS's real lockout policy is stronger.
- No protection against malware already running on the machine when the PIN is
  entered, or against keylogging that is already resident.

## 6. Future work

- A real credential provider (C++) wrapping this logic (decoys, SAM-free unlock).
- Encrypting the duress config itself (e.g., with the DPAPI or a derived key) so the
  "hidden" file is also unreadable.
- Duress variants: a *different* duress PIN per escalation level (e.g., "alert" vs.
  "wipe"), and alert channels beyond email.
- Hardware-backed PIN entry (TPM + PIN protector on BitLocker, which already exists and
  should be the default).

## 7. Conclusion

The honest engineering result is that the user's two instincts are both right but
solve different halves: a duress PIN is a coercion defense, and encryption is the
theft-and-cracking defense. The prototype builds the first and turns the second into a
turnkey operation, with the limits of each written down instead of papered over.

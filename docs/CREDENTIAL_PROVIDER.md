# Building a real Windows credential provider for the duress PIN

The prototype in this project proves the *logic* of a duress PIN. Actually replacing
the Windows login screen with that logic requires a **credential provider** — a COM
component that Windows loads at the logon screen. This is the honest path, and it is
a C++ project, not a Python one.

## Why you can't do it in Python

Windows logon is handled by `winlogon.exe`; third-party login UI is plugged in
exclusively through the credential provider API (`ICredentialProvider`,
`ICredentialProviderCredential`, and friends). A normal application never gets to draw
the logon screen. The provider is a native DLL registered under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`.
There is no supported managed/Python route.

## The pieces you'd build (and what each must do)

1. **Provider + credential COM classes.** Implement `ICredentialProvider` (enumerate
   one credential) and `ICredentialProviderCredential` (the PIN tile: `GetSerialization`
   is where you answer "did they unlock?").
2. **PIN verification.** Import the exact state machine from `duress_guard.py` —
   salted hashes, constant-time compare, lockout. Better: rewrite it in C++ rather
   than calling into Python, since the provider runs in the secure logon context.
3. **Decoy profile.** On a duress PIN, `GetSerialization` can return the credentials
   of a *different* local account (a locked-down decoy). That is the cleanest "duress
   unlock": the machine logs you into a sandboxed desktop, looks normal, holds nothing.
4. **Alert path.** `GetSerialization` runs before the desktop; keep the alert to a
   fast, non-blocking signal (spool a file / notify a service). Do NOT open sockets
   from the logon process.
5. **Secure Boot + TPM note.** A credential provider still runs *after* boot. The
   bootable-media attack is stopped by BitLocker + Secure Boot, not by the provider.

## Risks to plan for

- A broken provider can lock you out of the machine. Always keep a second login path
  (e.g., a normal PIN provider registered alongside), and test on a VM first.
- The provider runs early; any bug is a blue screen at best, a lockout at worst.
- Signing and deployment: the DLL should be signed and registered with care.
- Windows logon runs in a security context that has no access to your normal user
  filesystem; design storage accordingly.

## Suggested order

1. Read the official sample: Microsoft's **Windows Credential Provider sample**
   (github.com/microsoft/Windows-classic-samples, path
   `Samples/Win7Samples/security/credentialproviders`).
2. Build the sample unchanged in Visual Studio (community is free) on a VM.
3. Port the duress logic to C++, add the decoy-account switch.
4. Add the alert spool and test the duress path in the VM.
5. Only then consider a live device, with a recovery path ready.

This is very achievable — the prototype you have is exactly the "what should the
provider do" spec. What it needs is a Windows SDK build environment, which this
repo (and this machine) cannot provide or test.

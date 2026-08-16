# The off-device watcher (v4)

## Why this exists

Every earlier layer is defeated by the same scenario: an attacker with admin can kill
the watchdog, delete its scheduled task, or pull the machine offline. No user-mode
program can stop that. The fix is to move the tamper *decision* off the device, to a
small server the attacker does not control.

## How it works

- **Check-in.** The device (via the watchdog's `run --server <url>`) sends a heartbeat
  to the watcher server on a schedule.
- **Missed detection.** If the server stops hearing from the device past a timeout, it
  marks the device MISSED. The owner learns the device went dark.
- **Remote arm.** The owner, off-device, issues `arm` against the device. The device's
  next poll reads the command and runs the configured duress actions - encrypt the
  sensitive folders (reversible with the owner's passphrase), arm pre-boot panics -
  even while the device is in the attacker's hands.

The key property: the decision to act originates off-device, so a compromised machine
cannot veto it. This is the same architecture real anti-theft products use (remote
wipe / Find My Device).

## Run it

```powershell
# Server (somewhere the attacker does not control)
python watcher_server.py --port 8765

# Device: local watchdog + remote check-in/poll
python startup_guard.py --storage-dir "D:\MyStuff\.config" run --server http://watcher-host:8765 --device-id my-laptop

# Owner, remotely:
python remote_watcher.py --server http://watcher-host:8765 --device-id my-laptop status
python remote_watcher.py --server http://watcher-host:8765 --device-id my-laptop arm
```

## SECURITY NOTES - read before any real use

This is a prototype and is **not safe to expose on the internet as-is**:

1. **No authentication.** Anyone who can reach the server can check in as a device or
   read its status. A real deployment needs per-device tokens (a shared secret per
   device, checked on every endpoint).
2. **No TLS.** The arm command is powerful (it can trigger encryption on the device).
   It must only travel over HTTPS, and the arm endpoint in particular should require
   the owner's own credential.
3. **The server is the trust root.** Whoever controls the watcher server can arm any
   device. Run it where the owner controls it.
4. The in-memory device registry is lost on restart; a real deployment needs durable
   storage and should tolerate devices checking in from changing IPs.

The design deliberately exposes these boundaries so the prototype makes the checklist
for a production version obvious instead of pretending they do not exist.

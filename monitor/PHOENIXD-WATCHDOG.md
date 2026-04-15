# Phoenixd Watchdog Service

Systemd timer that checks phoenixd health every 2 minutes and auto-restarts it if the HTTP API is unresponsive.

## Why this exists

Phoenixd occasionally gets stuck in a reconnect loop to ACINQ's LSP node (ECONNRESET errors). When this happens, the process stays alive but the HTTP API becomes completely unresponsive. LNbits can't create invoices, so all LNURL payments (including zaps from Wallet of Satoshi, etc.) fail with "problem processing the lnurl".

The existing email monitor (`monitor.mjs`) detects this and alerts, but doesn't fix it. This watchdog automatically restarts phoenixd to restore service.

## How it works

1. Calls `GET /getinfo` on `http://127.0.0.1:9740` with the password from `/home/phoenixd/.phoenix/phoenix.conf`
2. If the first check fails, waits 10 seconds and retries (avoids false positives from transient blips)
3. If both checks fail, runs `systemctl restart phoenixd`
4. Waits 10 seconds after restart, then verifies the API is back
5. All events logged to syslog under tag `phoenixd-monitor`

## Files on server (46.225.78.116)

| File | Purpose |
|------|---------|
| `/usr/local/bin/check-phoenixd.sh` | Health check script |
| `/etc/systemd/system/check-phoenixd.service` | Systemd oneshot service |
| `/etc/systemd/system/check-phoenixd.timer` | Runs the service every 2 minutes |

## Commands

```bash
# Check timer status
systemctl status check-phoenixd.timer

# View upcoming schedule
systemctl list-timers check-phoenixd.timer

# Run a manual check
systemctl start check-phoenixd.service

# View watchdog logs
journalctl -t phoenixd-monitor

# Disable the watchdog
systemctl stop check-phoenixd.timer
systemctl disable check-phoenixd.timer
```

## Incident: 2026-04-15

- **~11:54 UTC**: Phoenixd entered reconnect loop to ACINQ node `03864ef...` at `3.33.236.230`. Every attempt got `ECONNRESET (104): Connection reset by peer`.
- **~16:31 UTC**: Diagnosed via LNbits logs showing `Unable to connect to http://127.0.0.1:9740., Status: pending` and phoenixd logs full of Noise handshake ECONNRESET errors.
- **~16:33 UTC**: `systemctl restart phoenixd` restored service. Channel returned to `Normal` state immediately.
- **Root cause**: Likely a bug in phoenixd where the reconnect loop blocks the Kotlin coroutine event loop, making the HTTP server unresponsive even though the process is alive.
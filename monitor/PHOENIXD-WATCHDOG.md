# Phoenixd watchdog

Systemd timer that restarts phoenixd when its HTTP API stops responding.

## What it solves

Phoenixd can enter a reconnect loop to ACINQ's LSP node that blocks its event loop. The
process stays alive and `systemctl status phoenixd` reports it active, but the HTTP API
never answers. LNbits cannot create invoices, so every LNURL payment fails with "problem
processing the lnurl". Left alone this persists until someone restarts the service by
hand; the last occurrence lasted about five hours.

The email monitor detects the condition but does not act on it. This watchdog restores
service without anyone being woken.

## How it works

1. Calls `GET /getinfo` on `http://127.0.0.1:9740`, authenticating with the password from
   `/home/phoenixd/.phoenix/phoenix.conf`
2. On failure, waits 10 seconds and retries, so a transient blip does not trigger a restart
3. If both checks fail, runs `systemctl restart phoenixd`
4. Waits 10 seconds and verifies the API is answering again
5. Logs every outcome to syslog under the tag `phoenixd-monitor`

A restart also produces an ALERT and a RECOVERED email from the monitor a few minutes
apart. That pair is expected, not a second incident.

## Files

| File | Purpose |
|---|---|
| `check-phoenixd.sh` | Health check and restart logic |
| `check-phoenixd.service` | Oneshot systemd unit |
| `check-phoenixd.timer` | Runs the service every 2 minutes |

`deploy.sh` installs all three and enables the timer.

## Commands

```bash
systemctl status check-phoenixd.timer      # is it active
systemctl list-timers check-phoenixd.timer # next run
systemctl start check-phoenixd.service     # run a check now
journalctl -t phoenixd-monitor             # what it has done
systemctl disable --now check-phoenixd.timer
```

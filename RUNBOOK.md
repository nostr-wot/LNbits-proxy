# Runbook

What to look at when zaps stop working, in the order worth checking. Paths below assume
the reference layout; adjust for your own.

## First: did it already fix itself?

The phoenixd watchdog runs every 2 minutes and restarts the backend when its HTTP API
stops answering. Most of the outages seen so far were that fault, and it now self-heals.

```bash
journalctl -t phoenixd-monitor --since '1 hour ago'
```

A restart there produces an ALERT and a RECOVERED from the monitor a few minutes apart.
That pair is expected noise, not a second incident.

## One-line triage

```bash
curl -s https://<your-domain>/healthz | jq
```

`/healthz` opens both LNbits databases, checks the admin key is configured and pings
LNbits. It returns 503 with a per-dependency reason. This is more informative than the
process manager, which reports the proxy as online even when every request is failing.

## Where the logs are

| What | Where |
|---|---|
| Proxy | `pm2 logs zaps-provision` |
| Monitor, per-check results | `/srv/zaps-monitor/monitor.log` (one JSON object per run) |
| Monitor, cron output | `/srv/zaps-monitor/cron.log` |
| Watchdog | `journalctl -t phoenixd-monitor` |
| LNbits | `journalctl -u lnbits` |
| phoenixd | `journalctl -u phoenixd`, `/home/phoenixd/.phoenix/phoenix.log` |

The proxy logs request paths only, never query strings: those carry NIP-57 zap requests
and payer comments.

## Symptoms

### "Problem processing the LNURL", or payments failing

Usually phoenixd is alive but its HTTP API is wedged in a reconnect loop to the LSP, which
blocks its event loop. `systemctl status phoenixd` still reports active.

```bash
journalctl -u lnbits --since '10 min ago' | grep 9740
PASS=$(grep http-password /home/phoenixd/.phoenix/phoenix.conf | head -1 | cut -d= -f2)
curl -m 5 -u ":$PASS" http://127.0.0.1:9740/getinfo      # should answer instantly
tail -50 /home/phoenixd/.phoenix/phoenix.log | grep -iE 'ECONNRESET|CLOSED|ESTABLISHING'
systemctl restart phoenixd
```

First seen 2026-04-15, stuck ~5 hours before a manual restart. The watchdog exists because
of this.

### Provisioning returns 503 "could not be linked"

A wallet was created in LNbits but could not be linked to its Nostr pubkey, so the keys
were deliberately withheld: handing them out would let the wallet receive sats that no
later provision could find. The orphaned wallet id is in the proxy log.

```bash
pm2 logs zaps-provision --lines 500 --nostream | grep ORPHANED
```

Almost always database contention. Check nothing is holding a long write on the LNbits
database, then have the user retry. The orphan is an empty wallet and safe to leave.

### Everyone is getting 429

The rate limiter keys on the rightmost `X-Forwarded-For` entry. If a CDN was added in
front without `real_ip_header`, that entry is the CDN's edge address and every visitor
behind one edge shares a bucket of 3–5 requests a minute.

```bash
tail -20 /var/log/nginx/access.log      # first field must be visitor addresses, not edges
```

### The proxy will not start

It refuses to start on a missing database path or a missing admin key, and says which:

```bash
pm2 logs zaps-provision --lines 50 --nostream | grep FATAL
```

### NWC management returning 502

```bash
pm2 logs zaps-provision --lines 200 --nostream | grep '\[nwc\]'
```

Each failure logs its upstream status and path, never the key or body. A 502 on `PUT` for
a key that once existed used to mean an expired grant still holding the provider's primary
key; that is cleared automatically now.

### No monitor mail at all

The monitor refuses to run unconfigured rather than reporting a stack it cannot see.

```bash
tail -20 /srv/zaps-monitor/cron.log
/srv/zaps-monitor/run-monitor.sh          # run it by hand; should print ALL OK
```

Check `zaps-monitor.env` is readable and mode 600. Remember alerting needs two consecutive
failures by default.

## Rolling back

```bash
cd /srv/LNbits-proxy && ./deploy.sh --ref <previous-commit>
```

Or restore the dated backups the last deploy left beside the live files, then restart the
proxy process. Never restart LNbits or phoenixd for a proxy-only change.

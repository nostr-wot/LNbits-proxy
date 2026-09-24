# Runbook

What to check when zaps stop working. Paths assume the reference layout; adjust for your
own.

## Start here

**1. Did it already recover?** The phoenixd watchdog restarts the Lightning backend every
time its HTTP API stops answering, which is the most common cause.

```bash
journalctl -t phoenixd-monitor --since '1 hour ago'
```

A restart produces an ALERT and a RECOVERED email a few minutes apart. That pair is
expected.

**2. Ask the service what is wrong.**

```bash
curl -s https://<your-domain>/healthz | jq
```

`/healthz` opens both LNbits databases, checks the admin key is configured and pings
LNbits, returning 503 with a per-dependency reason. The process manager reports the proxy
as online even when every request is failing, so start here instead.

## Logs

| What | Where |
|---|---|
| Proxy | `pm2 logs zaps-provision` |
| Monitor, per-check results | `/srv/zaps-monitor/monitor.log`, one JSON object per run |
| Monitor, cron output | `/srv/zaps-monitor/cron.log` |
| Watchdog | `journalctl -t phoenixd-monitor` |
| LNbits | `journalctl -u lnbits` |
| phoenixd | `journalctl -u phoenixd`, `/home/phoenixd/.phoenix/phoenix.log` |

The proxy logs request paths only. Query strings carry NIP-57 zap requests and payer
comments, so they are never written to logs.

## Symptoms

### "Problem processing the LNURL", or payments failing

phoenixd is alive but its HTTP API is wedged. `systemctl status phoenixd` still reports
active.

```bash
journalctl -u lnbits --since '10 min ago' | grep 9740
PASS=$(grep http-password /home/phoenixd/.phoenix/phoenix.conf | head -1 | cut -d= -f2)
curl -m 5 -u ":$PASS" http://127.0.0.1:9740/getinfo      # should answer instantly
tail -50 /home/phoenixd/.phoenix/phoenix.log | grep -iE 'ECONNRESET|CLOSED|ESTABLISHING'
systemctl restart phoenixd
```

### Provisioning returns 503, "could not be linked"

A wallet was created in LNbits but could not be mapped to its Nostr pubkey, so its keys
were withheld deliberately: handing them out would let the wallet receive sats that no
later provision could find. The orphaned wallet id is in the log.

```bash
pm2 logs zaps-provision --lines 500 --nostream | grep ORPHANED
```

Usually database contention. Check nothing is holding a long write on the LNbits
database, then have the user retry. The orphan is an empty wallet and safe to leave.

### A returning user is offered a new wallet instead of theirs

Their pubkey is missing from the mapping database. Check it and re-import if needed:

```bash
sqlite3 /srv/zaps-provision/provisioning.sqlite3 \
  "SELECT wallet_id FROM provisioned WHERE pubkey='<hex>'"
node scripts/backfill-provisioned.mjs --verify-only
```

`--verify-only` confirms every pubkey resolves to the wallet it should. Do not let a user
provision again until this is resolved, or they will end up with a second wallet.

### Everyone is getting 429

The rate limiter keys on the rightmost `X-Forwarded-For` entry. If a CDN was put in front
without `real_ip_header`, that entry is the CDN's edge address and every visitor behind
one edge shares a bucket of 3–5 requests a minute.

```bash
tail -20 /var/log/nginx/access.log   # first field must be visitor addresses, not edges
```

### The proxy will not start

It refuses to start on a missing database path or a missing admin key, and says which.

```bash
pm2 logs zaps-provision --lines 50 --nostream | grep FATAL
```

### NWC management returning 502

```bash
pm2 logs zaps-provision --lines 200 --nostream | grep '\[nwc\]'
```

Each failure logs its upstream status and path, never the key or body.

### No monitor mail at all

The monitor refuses to run unconfigured rather than reporting a stack it cannot see.

```bash
tail -20 /srv/zaps-monitor/cron.log
/srv/zaps-monitor/run-monitor.sh      # run by hand, should print ALL OK
```

Check `zaps-monitor.env` is readable and mode 600. Alerting needs two consecutive
failures by default.

## Rolling back

```bash
cd /srv/LNbits-proxy && ./deploy.sh --ref <previous-commit>
```

Or restore the dated backups the last deploy left beside the live files and restart the
proxy process. Never restart LNbits or phoenixd for a proxy-only change.

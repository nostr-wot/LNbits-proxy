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

### Provisioning returns 426 or authentication fails after upgrade

426 means the client still calls the retired v1 routes. Upgrade the client to the v2
body-bound transaction flow; do not restore an unsigned-body fallback. Deploy only after
compatible clients are ready. Check `PUBLIC_ORIGIN` exactly matches the externally served
HTTPS origin. Query strings on v2 paths are rejected. Browser callers additionally need
an exact `BROWSER_ORIGINS` entry and a matching signed `client-origin` tag.

Check the client clock, exact serialized body hash and transaction header for 403s.
Do not log Authorization or X-Nostr-Transaction values. A challenge is consumed once,
including when a later wallet operation fails; retries need a fresh challenge and signature.
All proxy processes must use the same `PROVISION_DB_PATH`; its `auth_challenges_v2` table
is the persistent nonce store. A process restart does not clear valid challenges.

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

## Account deletion

`POST /api/v2/delete-account` is the in-app "delete my account" path (App Store
guideline 5.1.1(v)). The README has the wire contract. What it does, in order:

1. Refuses with 409 if the account has a balance the user did not acknowledge, or an
   outgoing payment still pending. Nothing is touched.
2. Revokes every NWC grant through the provider's API with the wallet's own admin
   key, expired grants included, then lists again and fails if any remain. If the
   user had switched the provider off, it is switched back on for that account first
   so the revocation is accepted.
3. Deletes the Lightning Address pay link from the lnurlp database.
4. Reads the balance again, so a zap that landed in between is counted.
5. In one transaction on the LNbits database, deletes the account's rows in
   `balance_check`, `balance_notify`, `tiny_url`, `wasm_invocations`, `extensions`,
   `webpush_subscriptions`, `assets`, `audit`, then `wallets` and `accounts`. Tables a
   given LNbits version lacks are skipped.
6. In one transaction on `PROVISION_DB_PATH`, deletes the `provisioned` row and adds
   one row to `account_deletions` (timestamp and forfeited msat only).

A failure at any step returns 502 or 500 and leaves the earlier steps done; the next
call repeats the finished ones harmlessly and completes the rest.

**Why direct database writes and not the LNbits API.** LNbits' user-management API
(`DELETE /users/api/v1/user/{id}` and `.../wallet/{id}`) only accepts an admin
*account* session or access token, not the wallet key this proxy holds as
`LNBITS_ADMIN_KEY`. The proxy already writes LNbits' `accounts`, `extensions` and
`pay_links` tables directly, so deletion reverses provisioning the same way. The rows
are hard-deleted, which is stronger than LNbits' own admin delete (that one only
flags wallets `deleted` and keeps their rows).

**Limitations to know about:**

- **LNbits' authentication cache.** LNbits caches wallet-key lookups for
  `AUTH_AUTHENTICATION_CACHE_MINUTES` (default 10). The proxy cannot clear that cache
  from outside, so for up to that long LNbits may still accept the deleted wallet's
  keys on cached-key endpoints, such as listing payments via `GET /api/v1/payments`.
  Creating an invoice or paying one still fails, because both reload the wallet
  first. The keys exist only on the user's own device, which has just deleted them.
  Restarting LNbits clears the cache, but do not restart it just for this.
- **The payment ledger is retained.** `apipayments` rows stay, keyed by the deleted
  wallet id, so node balance and LNbits liabilities still reconcile. Nothing links
  them to the pubkey any more: the account row (`accounts.pubkey`, `username`) and
  the mapping are gone. Payment `extra` fields can still carry NIP-57 zap requests,
  which name the payer and recipient. Purge those by hand if a request requires it.
- **Invoices issued before deletion.** An unpaid invoice still in its expiry window
  can settle after the wallet is gone. LNbits then records it against a wallet id that
  no longer exists, and the sats stay on the node. Find them with:

  ```bash
  sqlite3 /home/lnbits/lnbits/data/database.sqlite3 \
    "SELECT checking_id, amount, status FROM apipayments
     WHERE wallet_id NOT IN (SELECT id FROM wallets) AND status = 'success' AND amount > 0"
  ```
- **NWC provider disabled for the whole instance.** If `nwcprovider` is not installed
  and active, its API cannot be called and grants are not revoked. They stay in the
  provider's own database pointing at a wallet that no longer exists, so they cannot
  spend. Remove them with the provider's tools if it is re-enabled.
- **Shared wallets.** If another LNbits user had a shared wallet pointing at this one,
  their share stops working. The proxy never creates shares.
- **Logs.** The proxy's own log lines carry 16-character pubkey prefixes and wallet
  ids from earlier provisioning and claims. They age out under whatever pm2 log
  rotation the host runs; deletion does not rewrite them.

**Verifying a deletion.** The operator does not learn which account was deleted, by
design. Check the anonymous record and the log line:

```bash
sqlite3 /srv/zaps-provision/provisioning.sqlite3 \
  "SELECT id, datetime(deleted_at,'unixepoch'), forfeited_msat FROM account_deletions ORDER BY id DESC LIMIT 5"
pm2 logs zaps-provision --lines 500 --nostream | grep '\[delete-account\]'
```

If a user reports a specific pubkey, `SELECT 1 FROM provisioned WHERE pubkey='<hex>'`
must return nothing, and `curl -s 'https://<your-domain>/api/lightning-address?pubkey=<hex>'`
must return `{"address":null}`. A nonzero `forfeited_msat` is balance the user chose
to give up; it stays on the node.

A 409 `shared_account` means the mapping points at an LNbits account or wallet another
pubkey also maps to. That should never happen; check `provisioned` for duplicate
`user_id` or `wallet_id` values before the user retries.

## Rolling back

```bash
cd /srv/LNbits-proxy && ./deploy.sh --ref <previous-commit>
```

Or restore the dated backups the last deploy left beside the live files and restart the
proxy process. Restore `monitor.mjs` from the **same backup stamp** along with the proxy
modules: the v2 monitor calls a POST challenge endpoint that the legacy proxy does not
serve. Restoring only the old server leaves the new monitor reporting false failures.
The failed-deploy rollback commands printed by `deploy.sh` include the monitor restore.
Cron loads the restored monitor on its next run; it needs no service restart. Never
restart LNbits or phoenixd for a proxy-only change.

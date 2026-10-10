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

## Inbound liquidity

phoenixd receives through a single channel to ACINQ's LSP. When a deposit does not fit
the channel's inbound liquidity, phoenixd buys more on the fly and takes the whole fee,
mining plus LSP service fee, out of **that one deposit**. LNbits records it as a fee on
the incoming payment and credits the user `amount - fee`.

What this cost once: auto-liquidity bought about 2M sat inbound in March. On 2026-09-30
the LSP spliced 1,994,225 sat of it back out because it was unused (capacity fell to
69,775 sat) and nobody noticed. On 2026-10-07 a deposit of just under 100k sat did not
fit the ~40k left; phoenixd bought about 2.1M sat and charged 21,476 sat to that user. The
absolute fee cap did not help: phoenixd applies it to the mining fee only.

The monitor now reports each step of that before a user pays for it. Everything below
assumes phoenixd's API on `127.0.0.1:9740`:

```bash
PASS=$(grep '^http-password=' /home/phoenixd/.phoenix/phoenix.conf | head -1 | cut -d= -f2)
curl -s -u ":$PASS" http://127.0.0.1:9740/getinfo | jq '{version, channels}'
```

### The alerts

| Mail | Meaning | Do |
|---|---|---|
| `ALERT: Inbound Liquidity failing` | Inbound below the floor, no channel, or a channel not `Normal` | Buy liquidity deliberately (below) before the next deposit does it for you. A non-`Normal` channel right after a restart is usually `Offline`/`Syncing` and clears; the alert needs two consecutive runs. |
| `ALERT: channel capacity dropped by N sat (LSP splice-out?)` | A channel's capacity fell between runs | Confirm in `phoenix.log` (`grep -i splice`). Expect the Inbound Liquidity alert next. Buy liquidity deliberately. |
| `ALERT: phoenixd bought inbound liquidity (automatic, fee N sat)` | phoenixd made an on-the-fly purchase | The mail lists the LNbits deposits charged for it. Refund them (below). |
| `NOTICE: ... (manual, ...)` | A manual purchase was recorded | Expected if you made one. |
| `ALERT: user charged a node fee on a deposit` | A settled LNbits deposit carries a nonzero fee, whatever the cause | Refund (below). A deposit turned entirely into phoenixd fee credit shows a fee equal to its amount. |
| `ALERT: Liquidity Audit failing` | Purchases or deposit fees could not be read | Fix it: until then the two alerts above cannot fire. The message names the failing source. |

Wallet ids and payment hashes in the mail are prefixes. Purchase and deposit mails are
sent once each; the state lives under `liquidity_tracking` in
`/srv/zaps-monitor/state.json`. The first run after deploying this looks back
`LIQUIDITY_LOOKBACK_HOURS` (48 by default), so it reports the 2026-10-07 purchase once.

### Permissions

The liquidity checks read two files:

- `PHOENIX_CONF`: already read every run by the Phoenixd Node check, so nothing new.
  It now prefers `http-password-limited-access` (read-only API access, enough for
  `/getinfo` and listing payments) and falls back to `http-password`.
- `LNBITS_DB_PATH`: opened read-only. `cleanup.py`, run by the same monitor, already
  opens it read-write.

So wherever the monitor runs today it already has the access it needs. In the reference
deployment that is root's crontab (`crontab -l` as root shows the `run-monitor.sh`
line). Check after deploying:

```bash
/srv/zaps-monitor/run-monitor.sh && tail -1 /srv/zaps-monitor/monitor.log | jq '.checks[] | select(.id|startswith("liquidity"))'
```

If you move the monitor to an unprivileged user, grant that user alone what it needs
rather than loosening the files. `phoenix.conf` holds the full-access API password and
must not become group or world readable:

```bash
setfacl -m u:zapsmon:x /home/phoenixd /home/phoenixd/.phoenix
setfacl -m u:zapsmon:r /home/phoenixd/.phoenix/phoenix.conf
setfacl -m u:zapsmon:x /home/lnbits /home/lnbits/lnbits /home/lnbits/lnbits/data
setfacl -m u:zapsmon:r /home/lnbits/lnbits/data/database.sqlite3
```

A read-only SQLite open of a WAL database also needs the `-wal` and `-shm` files
readable; `cleanup.py` needs write access, so an unprivileged monitor user would have
to run cleanup some other way.

### phoenixd liquidity policy

Read this against the installed version (`version` in `/getinfo`); option names have
changed between releases. The following is from phoenixd's source as of v0.9.2
(September 2026) and https://phoenix.acinq.co/server/auto-liquidity. Settings go in
`/home/phoenixd/.phoenix/phoenix.conf` as `name=value` without the leading `--`, and
take effect when phoenixd restarts. Schedule that restart; never fold it into a proxy
deploy.

- `auto-liquidity` (`off`, `2m`, `5m`, `10m`; default `2m`): how much inbound to buy on
  top of what the payment needs.
- `max-mining-fee` (5,000 to 200,000 sat; default 1% of auto-liquidity): caps the
  **mining fee only**. `max-absolute-fee` is gone and phoenixd refuses to start with it.
  phoenixd hardcodes `considerOnlyMiningFeeForAbsoluteFeeCheck=true`; no conf option
  makes the absolute cap cover the service fee. phoenixd logs this cap as
  `maxAbsoluteFee`, which is why a 20,000 sat "max absolute fee" still allowed a
  21,476 sat charge.
- `max-relative-fee-percent` (1 to 50; default 30, not shown in `--help`): the only cap
  on the **total** fee, as a percentage of the incoming payment that triggers the
  purchase. The 21,476 sat fee was over 20% of the deposit, under the default.
- `max-fee-credit` (`off`, `50k`, `125k`, `250k`; default 2.5% of auto-liquidity): small
  payments that cannot cover a purchase are kept as fee credit instead.

Recommendation: set `max-relative-fee-percent` low, for example `5`. A deposit that
does not fit and cannot pay a purchase within 5% of its own amount is then rejected:
the payer sees a failed payment and retries later, instead of a user silently losing a
fifth of their deposit. Pair it with the monitor's Inbound Liquidity floor so you buy
liquidity before that happens. Consider `max-fee-credit=off` too, so a small deposit
is never swallowed as fee credit. Rejections appear in `phoenix.log` as
`lightning payment rejected ... over relative fee`.

### Buying liquidity deliberately

phoenixd's API has no "buy liquidity" call; a purchase happens when an incoming payment
does not fit. So make the operator, not a user, send that payment, straight to phoenixd
rather than to an LNbits wallet:

```bash
PASS=$(grep '^http-password=' /home/phoenixd/.phoenix/phoenix.conf | head -1 | cut -d= -f2)
# 1. What a purchase of the auto-liquidity size costs right now
curl -s -u ":$PASS" "http://127.0.0.1:9740/estimateliquidityfees?amountSat=2000000"
# 2. An invoice on the node itself, bigger than the inbound left and than the fee
curl -s -u ":$PASS" -X POST http://127.0.0.1:9740/createinvoice \
  -d amountSat=150000 -d description='operator liquidity top-up'
```

The `phoenix-cli estimateliquidityfees` and `phoenix-cli createinvoice` commands do the
same. Pay the invoice from an operator wallet outside this node (a hosted LNbits wallet
here would be paying itself). The amount must exceed the remaining
inbound (so it does not fit), and the fee must stay within `max-relative-fee-percent`
of it: with the setting at 5% and a ~21,000 sat fee, send at least ~430,000 sat, or
raise the setting for the top-up and restore it after. phoenixd buys `auto-liquidity`
plus the payment amount and takes the fee from the operator's payment; what is left
stays as node balance, outside every LNbits wallet. Expect an `ALERT: phoenixd bought
inbound liquidity` mail saying no LNbits deposit carried a fee, and Inbound Liquidity
recovering on the next run.

### Refunding a user charged a liquidity fee

The alert gives the wallet id prefix, the amount, the fee and a payment hash prefix.

```bash
sqlite3 -readonly /home/lnbits/lnbits/data/database.sqlite3 \
  "SELECT wallet_id, amount/1000 AS sat, fee/1000 AS fee_sat,
          datetime(COALESCE(updated_at, created_at), 'unixepoch') AS settled
     FROM apipayments WHERE payment_hash LIKE '<hash prefix>%' AND amount > 0"
```

Credit the fee back to that wallet as the LNbits super user: the admin UI (Users, the
wallet, credit) or `PUT /users/api/v1/balance` with `{"id":"<wallet id>","amount":<fee in
sat>,"memo":"Refund of node liquidity fee"}` under a super-user session. Amounts there
are sats. The credit is backed by the node's own balance: the operator absorbs the fee,
so check the node balance still covers every LNbits wallet afterwards. Do not edit
`apipayments.fee` by hand.

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

Stop the timer first, or it will redeploy the release you are rolling away from on
its next tick:

```bash
sudo systemctl disable --now zaps-autodeploy.timer
cd /srv/LNbits-proxy && ./deploy.sh --ref <previous-commit>
```

To roll back to the previous release and stay there, mark the bad release a
pre-release on GitHub and re-enable the timer: the deployer skips pre-releases and
will deploy the newest published one instead. Record what you want live in
`deployed-version` if you want the timer to leave the box alone entirely.

### Restoring the wallet mapping

Deploys copy it into `$PROVISION_DIR/backups/provisioning.sqlite3.bak-<stamp>`
(newest ten kept). It is a plain SQLite file; stop the proxy, copy it back over
`provisioning.sqlite3`, `chmod 600` it, and start the proxy. Check it first:

```bash
sqlite3 <backup> 'select count(*) from provisioned;'
```

A mapping restored from a stamp older than the last provisioning leaves the users
provisioned since then looking new, and they will be given fresh wallets. Prefer the
newest backup that opens.

Or restore the dated backups the last deploy left beside the live files and restart the
proxy process. Restore `monitor.mjs` from the **same backup stamp** along with the proxy
modules: the v2 monitor calls a POST challenge endpoint that the legacy proxy does not
serve. Restoring only the old server leaves the new monitor reporting false failures.
The failed-deploy rollback commands printed by `deploy.sh` include the monitor restore.
Cron loads the restored monitor on its next run; it needs no service restart. Never
restart LNbits or phoenixd for a proxy-only change.

## NWC requests accepted by the relay but never answered

The LNbits NWC provider can log `Error parsing event: int() argument must be a string, a bytes-like object or a real number, not 'list'`. Affected versions pass the entire NIP-40 `expiration` tag to `int()` instead of its timestamp value, discarding valid requests before wallet dispatch. Clients without this tag may work while clients that set an expiry time out. Do not remove client expiry protection or retry payments automatically.

The repository carries a narrow, idempotent maintenance repair. It recognizes the exact defective source, saves the original beside it as `nwcp.py.before-expiration-fix`, and changes only extraction of the timestamp. Malformed timestamps are still rejected and expired requests are still dropped. Unknown upstream source aborts for review.

```bash
./deploy.sh --repair-nwc-expiration --dry-run
./deploy.sh --repair-nwc-expiration
```

Set `NWC_PROVIDER_FILE` if the installed provider lives outside the reference path. This explicit mode restarts LNbits only when the file changes; it does not deploy the proxy or restart phoenixd. A failed immediate restart restores the backup. Verify `/healthz`, inspect the NWC listener logs, and send a disposable-key `get_info` request with an expiration tag: the expected response is `UNAUTHORIZED`, demonstrating parsing and response routing without a payment. A provider upgrade may replace the patched file; inspect the new parser rather than blindly reapplying it.

A separate HTTP 429 from the wallet proxy means its 120-request-per-minute per-IP wallet budget was reached. Balance and transaction refreshes share this budget with payment requests. Inspect aggregated access counts and stop excessive polling; do not raise limits to conceal a client refresh loop.

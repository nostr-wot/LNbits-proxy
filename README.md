# LNbits Provisioning Proxy

Sits in front of LNbits and gives Nostr clients a narrow, authenticated surface for
provisioning wallets, claiming Lightning Addresses and managing Nostr Wallet Connect
grants. LNbits' own administrative API is never exposed; only the paths below are served
and everything else returns 404.

Self-hosting guide, written for operators running their own instance:
<https://nostr-wot.com/docs/lnbits-proxy>

## Authentication changes and migration

Authentication v2 is the companion backend protocol for Nostr WoT Extension 0.8.7.
The backend and extension changes form one coordinated release.

Read the community guide on
[backend authentication protections](https://github.com/nostr-wot/nostr-wot-extension/blob/main/docs/guides/backend-authentication.md)
for the website/API trust boundaries and limitations. The separate
[relay authentication guide](https://github.com/nostr-wot/nostr-wot-extension/blob/main/docs/guides/relay-authentication.md)
explains the extension's NIP-42 permissions; this HTTP proxy does not implement
relay connection authentication.

See [CHANGELOG.md](CHANGELOG.md) for the backend changes, the
[wire contract](https://github.com/nostr-wot/nostr-wot-extension/blob/main/docs/wallet-auth-v2.md)
for client integration, and [RUNBOOK.md](RUNBOOK.md) for deployment and rollback.
Stage compatible clients, deploy and verify this backend, then publish the
extension. Legacy authentication routes return 426 after this backend is deployed.

## Endpoints

### Wallet provisioning

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/v2/provision/challenge` | POST | none | Issue a single-use challenge |
| `/api/v2/provision` | POST | NIP-98 | Create or recover a wallet for a pubkey |

### Lightning Address

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/v2/claim-username` | POST | NIP-98 | Claim a username |
| `/api/lightning-address?pubkey=<64 hex>` | GET | none | Look up the address for a pubkey |
| `/api/v2/release-username` | POST | NIP-98 | Release a claimed username |

### Account deletion

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/v2/delete-account` | POST | NIP-98 | Delete the signer's hosted wallet account |

Body: `{"confirm":"delete-account","acknowledgeBalance":<boolean>}`, signed with the
same v2 transaction flow as the routes above. The body names no account: the signed
event's pubkey is the only identity used, so a signer can only ever reach their own.

| Status | Body | Meaning |
|---|---|---|
| 200 | `{"deleted":true}` | Everything below is gone |
| 400 | `{"error":"invalid_request"}` | `confirm` is not `"delete-account"`, or `acknowledgeBalance` is not a boolean |
| 403 | `{"error":"..."}` | Missing, invalid, expired or consumed authentication, as for every v2 route |
| 404 | `{"error":"not_found"}` | No account for this pubkey, including after a completed deletion |
| 409 | `{"error":"balance_not_zero","balanceMsat":<n>}` | Balance above zero and `acknowledgeBalance` is not `true`; nothing deleted |
| 409 | `{"error":"payment_pending"}` | An outgoing payment is still in flight; retry once it settles or fails |
| 409 | `{"error":"in_progress"}` | Another provision or deletion for this pubkey is running |
| 409 | `{"error":"shared_account"}` | The mapping reaches another pubkey's LNbits records; refused, operator must repair |
| 502 | `{"error":"upstream_unavailable"}` | LNbits or the NWC provider failed; safe to retry with a fresh challenge |
| 500 | `{"error":"deletion_failed"}` | A database step failed; safe to retry with a fresh challenge |

A deletion revokes every NWC grant the wallet holds (expired ones included),
releases the Lightning Address, deletes the LNbits wallet, its account and the rows
LNbits keys by them, then removes the proxy's pubkey mapping. With
`acknowledgeBalance: true` any remaining balance is forfeited and stays with the
operator's node. The balance is checked again after the address is released, so a zap
that lands mid-deletion is counted. Each step is idempotent and the mapping is
removed last, so a call that fails part-way is completed by the next one. Clients
should treat 404 after a 200, or after a failed attempt they retried, as "already
deleted". The proxy keeps only an anonymous record: a timestamp and the forfeited
msat, with no pubkey, user or wallet id. See [RUNBOOK.md](RUNBOOK.md#account-deletion)
for what LNbits retains.

### NWC app connections

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/nwc/connections` | GET | wallet admin key | Active connections, budgets, provider metadata |
| `/api/nwc/connections/{clientPubkey}` | PUT | wallet admin key | Register a client-generated key |
| `/api/nwc/connections/{clientPubkey}` | DELETE | wallet admin key | Revoke that wallet's grant |

All three require the wallet's **Admin** API key in `X-Api-Key`; invoice-only keys are
rejected, and any query string returns 404. A repeat `PUT` for the same key is idempotent
and returns 200 rather than editing the existing grant. New grants are fixed to
`pay`/`lookup`/`info`, with a daily budget of 1–9,999,999 sats on a rolling 24 hours and
an expiry of 1–365 days, capped at 50 active connections per wallet. Client secrets are
generated in the client and never sent here.

### Operations

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/healthz` | GET | none | Opens both databases, pings LNbits; 200 healthy, 503 otherwise |

### Proxied LNbits paths

Forwarded verbatim; nothing else is.

```
GET       /.well-known/lnurlp/{username}      public, permissive CORS
GET       /lnurlp/api/v1/lnurl/cb/{id}        public, permissive CORS
GET|POST  /api/v1/wallet                      requires X-Api-Key
GET|POST  /api/v1/payments                    requires X-Api-Key
GET       /api/v1/payments/fee-reserve        requires X-Api-Key, GET only
```

`Host` is rewritten to the public domain on the LNURL paths so LNbits builds correct
callback URLs. Wallet keys must be sent in the `X-Api-Key` header; `?api-key=` in the
query string is rejected so keys stay out of access logs.

`/api/v1/payments/fee-reserve?invoice=<bolt11>` returns `{"fee_reserve": <msat>}`, the
`fee_limit_msat` LNbits hands its funding source, so a client can bound what a payment
may cost before sending it. GET only, and not a payment lookup: `/api/v1/payments/{hash}`
stays unreachable.

## Authentication

Provisioning, account deletion and every Lightning Address mutation require the v2
transaction flow.
Legacy `/api/provision/challenge`, `/api/provision`, `/api/claim-username` and
`/api/release-username` return **426 Upgrade Required**. There is no legacy fallback.
Stage compatible clients before deployment, then deploy and verify the backend before publishing the extension.

1. Serialize the operation body once: `{ "name": "..." }` for provisioning,
   `{ "username": "..." }` for claiming, `{}` for releasing, or
   `{ "confirm": "delete-account", "acknowledgeBalance": <boolean> }` for deleting. Hash the exact UTF-8
   bytes with SHA-256. Extra operation fields are rejected.
2. POST `/api/v2/provision/challenge` with `{ "url": "https://<public-origin>/api/v2/provision",
   "method": "POST", "payload": "<lowercase hex SHA-256>" }` (use the exact target
   mutation URL). Response: `{ "version": 2, "challenge": "<64 hex>",
   "transactionToken": "<64 hex>", "expiresAt": <Unix seconds> }`.
3. Sign kind `27235`, empty content, current integer `created_at`, and exactly one
   two-string tag each: `u` (exact operation URL), `method` (`POST`), `payload`
   (exact body hash), `challenge`, and `transaction` (SHA-256 of the transaction
   token's UTF-8 string, **not** its decoded hex bytes).
4. POST the original serialized operation bytes to the v2 target. Send the signed
   event as base64-encoded JSON in `Authorization: Nostr <base64>` and the separate
   token in `X-Nostr-Transaction`. Do not include the event in the operation body.

Challenges expire after 60 seconds; event timestamps must be within 60 seconds.
The proxy stores challenges in `PROVISION_DB_PATH`, binds their URL, method, payload,
transaction hash and client scope, and consumes them with a single conditional SQLite
DELETE after signature and body validation. This prevents replay across processes sharing
that database. Invalid signatures, changed bodies and mismatched bindings do not burn
challenges. Issuance prunes expired entries and caps outstanding rows at 10,000.
All instances must share the same protected database; independent databases are not a
shared nonce store. Do not place SQLite on unsupported network filesystems.

Fixed v2 paths reject query strings and noncanonical request targets. The audience comes
from `PUBLIC_ORIGIN`, never client-controlled Host or forwarded-host headers.

### Browser client policy

`BROWSER_ORIGINS` is a comma-separated exact HTTPS origin allowlist, empty by default.
A browser Origin outside it (including `null`) is rejected before challenge issuance.
Allowed browser clients must add exactly one `client-origin` tag matching their request
Origin; the challenge is bound to this same value. CORS echoes that origin, varies on
Origin, and permits only POST plus Content-Type, Authorization and X-Nostr-Transaction
(the challenge endpoint permits only Content-Type). No cookies are used.

Missing Origin and native extension scheme origins use the separate native flow, requiring
both the signed event and transaction token and no `client-origin` tag. These values are
not browser or extension attestation: nonbrowser clients can forge Origin, and a holder
of a fresh valid event **and** its transaction token can win first use at the intended
backend. Exact audience/body binding prevents changing or redirecting that authority;
CORS and single-use state cannot eliminate first-use forwarding. Public LNURL endpoints
retain their separate permissive CORS policy. Wallet-key API authentication is unchanged.

## Rate limits

Per client address per minute; over the limit returns 429.

| Route | Limit |
|---|---|
| `/api/nwc/connections` | 60 |
| `/api/v1/wallet`, `/api/v1/payments`, `/api/v1/payments/fee-reserve` | 120 |
| LNURL passthrough | 60 |
| `/api/v2/provision/challenge` | 10 |
| `/api/v2/provision` | 5 |
| `/api/v2/claim-username`, `/api/v2/release-username` | 3 |
| `/api/v2/delete-account` | 3 |

The client address is the rightmost `X-Forwarded-For` entry, appended by your reverse
proxy. **If a CDN sits in front, configure it to restore the real client IP**
(`real_ip_header CF-Connecting-IP` plus `set_real_ip_from` for the CDN's ranges).
Otherwise every visitor behind one edge shares a single bucket.

## Configuration

Copy `.env.example`. Only `LNBITS_ADMIN_KEY` is required.

| Variable | Default | Description |
|---|---|---|
| `LNBITS_URL` | `http://127.0.0.1:5000` | LNbits backend |
| `LNBITS_ADMIN_KEY` | *(required)* | LNbits super-user key, never forwarded to clients |
| `LNBITS_DB_PATH` | `/home/lnbits/lnbits/data/database.sqlite3` | LNbits database |
| `LNURLP_DB_PATH` | `/home/lnbits/lnbits/data/ext_lnurlp.sqlite3` | lnurlp extension database |
| `PROVISION_DB_PATH` | `/srv/zaps-provision/provisioning.sqlite3` | Proxy-owned pubkey to wallet mapping |
| `PUBLIC_ORIGIN` | `https://zaps.nostr-wot.com` | Exact HTTPS audience origin, no trailing slash |
| `BROWSER_ORIGINS` | *(empty)* | Comma-separated exact HTTPS browser origins |
| `PORT` | `3003` | Loopback listen port |

The service binds `127.0.0.1` only, and refuses to start if a database path does not
exist or the admin key is missing.

### Wallet ownership

A pubkey is resolved to its wallet through `PROVISION_DB_PATH`, a database this service
owns. Rows are written only after a NIP-98 signature from that pubkey has been verified.

LNbits' `accounts.pubkey` is mirrored so the LNbits UI shows the association, but is never
read for authorization: LNbits lets any logged-in user set that column on their own
account without proving they hold the Nostr key.

**`PROVISION_DB_PATH` must not be writable by the LNbits user.** That file permission is
what makes wallet ownership trustworthy.

On an instance that predates this file, import the existing mapping:

```bash
node scripts/backfill-provisioned.mjs --dry-run
node scripts/backfill-provisioned.mjs
```

It is idempotent and verifies that every pubkey resolves to the same wallet and keys as
before, exiting non-zero otherwise. `deploy.sh` runs it before restarting and aborts the
deploy if verification fails.

## Running

```bash
npm ci
npm test          # proxy and alert-policy tests
npm run test:cleanup   # invoice cleanup tests (python3)
npm run check     # syntax check every entry point
npm start
```

Node 24+ is required; `node:sqlite` is experimental before it.

## Deployment

`./deploy.sh` treats the git checkout as the source of truth. It refuses to run from a
dirty tree, backs up what it replaces with a dated stamp, migrates the wallet mapping,
installs the proxy, the monitor and the phoenixd watchdog units, restarts only the proxy
process, and verifies the result.

```bash
./deploy.sh --dry-run    # show the plan, change nothing
./deploy.sh              # deploy origin/main
./deploy.sh --ref <ref>  # roll back to a specific ref
```

Put a reverse proxy in front for TLS; see the self-hosting guide for a worked nginx
configuration.

## Monitoring

- **`monitor/monitor.mjs`** — every 5 minutes via cron, through `monitor/run-monitor.sh`,
  which loads `zaps-monitor.env` because cron passes no environment. Checks LNbits, the
  proxy, the LNURL paths, the Lightning backend and end-to-end invoice generation, and
  emails on state change. Alerting requires two consecutive failures
  (`MONITOR_ALERT_AFTER`), so a single blip stays quiet.
- **`monitor/cleanup.py`** — retires the invoice the end-to-end check mints, and can prune
  expired unpaid invoices. It deletes only after the Lightning backend confirms an invoice
  was never paid, takes a dated database backup first, and re-checks its conditions inside
  the `DELETE` so a payment settling mid-prune is never discarded.
- **`monitor/check-phoenixd.*`** — systemd timer that restarts phoenixd when its HTTP API
  stops responding. See [`monitor/PHOENIXD-WATCHDOG.md`](monitor/PHOENIXD-WATCHDOG.md).

## When something breaks

See [`RUNBOOK.md`](RUNBOOK.md).

## Licence

MIT. See [`LICENSE`](LICENSE).

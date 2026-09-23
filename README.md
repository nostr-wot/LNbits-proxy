# LNbits Provisioning Proxy

Sits in front of LNbits and gives Nostr clients a narrow, authenticated surface for
provisioning wallets, claiming Lightning Addresses and managing Nostr Wallet Connect
grants. LNbits' own administrative API is never exposed; only the paths below are served
and everything else returns 404.

Self-hosting guide, written for operators running their own instance:
<https://nostr-wot.com/docs/lnbits-proxy>

## Endpoints

### Wallet provisioning

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/provision/challenge` | GET | none | Issue a single-use challenge |
| `/api/provision` | POST | NIP-98 | Create or recover a wallet for a pubkey |

### Lightning Address

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/claim-username` | POST | NIP-98 | Claim a username |
| `/api/lightning-address?pubkey=<64 hex>` | GET | none | Look up the address for a pubkey |
| `/api/release-username` | POST | NIP-98 | Release a claimed username |

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
```

`Host` is rewritten to the public domain on the LNURL paths so LNbits builds correct
callback URLs. `?api-key=` is rejected: LNbits accepts it, which would put wallet keys in
access logs.

## Authentication

Provisioning and every Lightning Address mutation use NIP-98 challenge-response.

1. `GET /api/provision/challenge` returns `{ "challenge": "<hex>" }`
2. Build a kind `27235` event with **three mandatory tags**, all matched exactly:
   - `u` — the full absolute URL being called, e.g. `https://<your-domain>/api/provision`
   - `method` — the HTTP method, `POST`
   - `challenge` — the challenge from step 1
3. Send it as the `event` field of the POST body
4. The Schnorr signature is verified *before* the challenge is consumed, so a failed
   attempt does not burn it

Two independent windows apply: the challenge expires 60 seconds after it is issued, and
the event's `created_at` must be within 60 seconds of server time. A client with a skewed
clock fails even with a fresh challenge.

## Rate limits

Per client address per minute; over the limit returns 429.

| Route | Limit |
|---|---|
| `/api/nwc/connections` | 60 |
| `/api/v1/wallet`, `/api/v1/payments` | 120 |
| LNURL passthrough | 60 |
| `/api/provision/challenge` | 10 |
| `/api/provision` | 5 |
| `/api/claim-username`, `/api/release-username` | 3 |

The client address is the rightmost `X-Forwarded-For` entry, which your reverse proxy
appends. **If a CDN sits in front, set the real client IP** (`real_ip_header
CF-Connecting-IP` plus `set_real_ip_from` for the CDN's ranges), otherwise every visitor
behind one edge shares a single bucket.

## Configuration

Copy `.env.example`. Only `LNBITS_ADMIN_KEY` is required.

| Variable | Default | Description |
|---|---|---|
| `LNBITS_URL` | `http://127.0.0.1:5000` | LNbits backend |
| `LNBITS_ADMIN_KEY` | *(required)* | LNbits super-user key, never forwarded to clients |
| `LNBITS_DB_PATH` | `/home/lnbits/lnbits/data/database.sqlite3` | LNbits database |
| `LNURLP_DB_PATH` | `/home/lnbits/lnbits/data/ext_lnurlp.sqlite3` | lnurlp extension database |
| `PROVISION_DB_PATH` | `/srv/zaps-provision/provisioning.sqlite3` | Proxy-owned pubkey to wallet mapping |
| `PORT` | `3003` | Loopback listen port |

The service binds `127.0.0.1` only and refuses to start if a database path does not exist
or the admin key is missing, rather than coming up and failing every request.

### Who owns which wallet

Provisioning resolves a Nostr pubkey to a wallet through `PROVISION_DB_PATH`, a database
this service owns. It is written only after a NIP-98 signature from that pubkey has been
verified.

It deliberately does not use LNbits' `accounts.pubkey`. LNbits lets any logged-in user set
that column on their own account with no proof they hold the Nostr key, so anyone able to
reach LNbits could claim an unclaimed npub and be handed the wallet that npub later
provisions. The column is still mirrored for LNbits' own UI, but never read for
authorization. **Keep this file unwritable by the LNbits user** — that is the whole
protection.

Migrating an existing instance:

```bash
node scripts/backfill-provisioned.mjs --dry-run
node scripts/backfill-provisioned.mjs     # copies, then verifies every pubkey
```

It is idempotent and verifies that each pubkey still resolves to the same wallet, with the
same keys, as before. `deploy.sh` runs it before restarting and aborts if verification
fails.

> **The public domain is a constant in `server.js`, not an environment variable.** NIP-98
> rejects any event whose `u` tag does not match it exactly, so an unmodified copy refuses
> every provisioning request on another domain. Edit `DOMAIN` before deploying.

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

`./deploy.sh` treats the checkout as the source of truth. It refuses to run from a dirty
tree, backs up what it replaces with a dated stamp, installs the proxy, the monitor and
the phoenixd watchdog units, restarts only the proxy process, and verifies the result.

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
  emails on state change. Two consecutive failures are required before alerting
  (`MONITOR_ALERT_AFTER`), so a single blip stays quiet.
- **`monitor/cleanup.py`** — retires the invoice the end-to-end check mints, and can prune
  expired unpaid invoices. It deletes only after the Lightning backend confirms an invoice
  was never paid, takes a dated database backup first, and re-checks its conditions inside
  the `DELETE` so a settlement racing the prune is never overwritten.
- **`monitor/check-phoenixd.*`** — systemd timer that restarts phoenixd when its HTTP API
  stops responding. See [`monitor/PHOENIXD-WATCHDOG.md`](monitor/PHOENIXD-WATCHDOG.md).

## When something breaks

See [`RUNBOOK.md`](RUNBOOK.md).

## Licence

MIT. See [`LICENSE`](LICENSE).

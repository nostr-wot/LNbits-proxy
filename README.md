# LNbits Provisioning Proxy

Provisioning proxy for `zaps.nostr-wot.com`. Sits in front of LNbits and handles challenge-response wallet provisioning and Lightning Address management.

## Endpoints

### Wallet Provisioning

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/provision/challenge` | GET | None | Generate a random challenge |
| `/api/provision` | POST | NIP-98 | Create or recover a wallet |

### Lightning Address

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/claim-username` | POST | NIP-98 | Claim a Lightning Address username |
| `/api/lightning-address` | GET | None | Look up address by pubkey |
| `/api/release-username` | POST | NIP-98 | Release a claimed address |

All other requests are proxied through to LNbits.

## Authentication

All authenticated endpoints use NIP-98 challenge-response:

1. `GET /api/provision/challenge` returns `{ challenge: "<hex>" }`
2. Client signs a kind:27235 event with the challenge in tags
3. Client sends the signed event in the POST body
4. Server verifies the Schnorr signature using nostr-tools

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LNBITS_URL` | `http://127.0.0.1:5000` | LNbits backend URL |
| `LNBITS_ADMIN_KEY` | _(required)_ | LNbits super-user API key |
| `LNBITS_DB_PATH` | `/home/lnbits/lnbits/data/database.sqlite3` | LNbits SQLite database |
| `LNURLP_DB_PATH` | `/home/lnbits/lnbits/data/ext_lnurlp.sqlite3` | LNbits lnurlp extension database |
| `PORT` | `3003` | Listen port |

## Setup

```bash
npm install
LNBITS_ADMIN_KEY=your_key node server.js
```

## Deployment

Runs on `46.225.78.116` managed by pm2:

```bash
pm2 restart zaps-provision
pm2 logs zaps-provision
```

Nginx proxies `zaps.nostr-wot.com` to port 3003.

## Username Validation

Lightning Address usernames must match: `^[a-z0-9][a-z0-9._-]{1,28}[a-z0-9]$`

- 3-30 characters
- Lowercase alphanumeric, dots, hyphens, underscores
- Must start and end with alphanumeric
- Reserved names blocked: admin, support, help, info, noreply, postmaster, webmaster, abuse, root, system

## Monitoring

### Email alerts (`monitor/monitor.mjs`)

Cron-based health checker that runs every 5 minutes and emails alerts via Resend when any component fails. Checks LNbits, the provisioning proxy, LNURL endpoints, phoenixd, and end-to-end invoice generation.

### Phoenixd watchdog (`check-phoenixd.timer`)

Systemd timer that checks phoenixd's HTTP API every 2 minutes and auto-restarts it if unresponsive. See [`monitor/PHOENIXD-WATCHDOG.md`](monitor/PHOENIXD-WATCHDOG.md) for details and commands.

## Known Issues

### Phoenixd hangs with unresponsive HTTP API

**Symptom**: Wallets report "problem processing the lnurl" or "payment failed". LNbits logs show `Unable to connect to http://127.0.0.1:9740., Status: pending`. Phoenixd process is alive (`systemctl status phoenixd` shows active) but `curl http://127.0.0.1:9740/getinfo` times out.

**Cause**: Phoenixd gets stuck in a reconnect loop to ACINQ's LSP node, logging repeated `ECONNRESET (104): Connection reset by peer` and `Noise handshake` errors. This blocks the Kotlin coroutine event loop, making the HTTP server unresponsive even though the process is still running and listening on port 9740.

**Fix**: `systemctl restart phoenixd` — service recovers immediately. The `check-phoenixd.timer` watchdog now handles this automatically.

**How to diagnose**:
```bash
# 1. Check if LNbits can reach phoenixd
journalctl -u lnbits --since '10 min ago' | grep 9740

# 2. Check if phoenixd API responds (should return JSON instantly)
PASS=$(grep http-password /home/phoenixd/.phoenix/phoenix.conf | head -1 | cut -d= -f2)
curl -m 5 -u ":$PASS" http://127.0.0.1:9740/getinfo

# 3. Check phoenixd logs for reconnect loop
tail -50 /home/phoenixd/.phoenix/phoenix.log | grep -i 'ECONNRESET\|CLOSED\|ESTABLISHING'

# 4. Restart if confirmed hung
systemctl restart phoenixd
```

**First occurrence**: 2026-04-15, ~11:54 UTC. Phoenixd was stuck for ~5 hours before manual restart.

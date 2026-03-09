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

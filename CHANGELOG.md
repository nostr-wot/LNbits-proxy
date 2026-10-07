# Changelog

## Liquidity monitoring

- The monitor now watches phoenixd's inbound liquidity (`monitor/liquidity.mjs`). It
  alerts when inbound liquidity is below `LIQUIDITY_MIN_INBOUND_SAT` (200,000 sat) or
  `LIQUIDITY_DEPOSIT_MULTIPLE` (2) times the largest deposit of the last 30 days, when
  there is no channel, or when one is not `Normal`; it reminds every 12 hours and mails
  a recovery.
- Mails when a channel's capacity drops by `LIQUIDITY_CAPACITY_DROP_SAT` (100,000 sat)
  or more between runs, which is how an LSP splice-out of leased liquidity shows up.
- Mails every liquidity purchase phoenixd records, with its fee and the LNbits deposits
  charged for it, and every settled LNbits deposit with a nonzero fee, so the affected
  user can be refunded. Wallet ids and hashes appear as prefixes only.
- Event mail is deduplicated in the state file and retried on the next run if the mail
  provider rejects it. A new Liquidity Audit check fails while the data behind these
  alerts cannot be read.
- The monitor prefers phoenixd's `http-password-limited-access` and honours
  `PHOENIX_URL`. It opens the LNbits database read-only and needs no new permissions.
- RUNBOOK documents the alerts, the phoenixd fee settings that actually bound what a
  user can be charged, buying liquidity deliberately and refunding users.

## Account deletion

- Add `POST /api/v2/delete-account` for in-app account deletion (App Store guideline
  5.1.1(v)). It uses the v2 transaction flow, its own 3/min rate limit and the same
  CORS policy as the other v2 routes. The signer's pubkey is the only identity used.
- Body `{"confirm":"delete-account","acknowledgeBalance":<boolean>}`. 404 `not_found`
  without an account; 409 `balance_not_zero` with `balanceMsat` while a balance is
  unacknowledged; 409 `payment_pending` while an outgoing payment is in flight; 200
  `{"deleted":true}` once done.
- Revokes every NWC grant (expired ones included), releases the Lightning Address,
  re-checks the balance, hard-deletes the LNbits wallet, account and their dependent
  rows, then removes the pubkey mapping. Ordered and idempotent, so a failed call is
  completed by a retry.
- Records each deletion in a new `account_deletions` table holding only a timestamp
  and the forfeited msat. It is created automatically; no migration step.
- The orphaned-wallet error log now carries a 16-character pubkey prefix, like every
  other log line, instead of the full pubkey.

Purely additive to the client surface. LNbits limitations and operator checks are in
[RUNBOOK.md](RUNBOOK.md#account-deletion).

## Wallet fee quotes

- Allow `GET /api/v1/payments/fee-reserve` through the wallet API proxy, so a client
  can read the `fee_limit_msat` ceiling LNbits would apply before sending a payment.
  Wallets that refuse to move a balance on an unknown fee can now quote one.
- Give each wallet API allowlist entry its own permitted verbs. The new path is GET
  only and exactly anchored: `POST` to it, `/api/v1/payments/{hash}`, and every other
  neighbouring path stay 404. `/api/v1/wallet` and `/api/v1/payments` are unchanged,
  including their `POST` support and the shared 120/min limit.
- Keys must still arrive in `X-Api-Key`; a key in the query string is still rejected.

Purely additive to the proxy surface. No existing client needs to change.

## Authentication v2

Companion backend changes for the coordinated Nostr WoT Extension 0.8.7 release.

- Add versioned provisioning, address-claim and address-release authentication with signatures in the Authorization header and a SHA-256 commitment to the exact operation body bytes.
- Bind each 60-second challenge to its URL, method, payload, client scope and a separate transaction-token hash. Consume valid challenges atomically in SQLite to reject replay across processes sharing the database.
- Require unique, well-formed authentication tags, valid signatures and bounded integer timestamps. Reject wrong audiences, modified bodies and queries on the fixed authentication endpoints. Use the configured public origin rather than untrusted forwarding headers.
- Enforce an exact configured HTTPS browser-origin allowlist for v2 identity-based mutations. Define a separately proof/token-authenticated native flow. Preserve public LNURL and existing wallet-key API policies.
- Retire unsafe legacy authentication endpoints with HTTP 426; there is no silent fallback. Coordinate compatible clients and deploy this backend before publishing extension 0.8.7.
- Update monitoring, deployment packaging and coordinated server/monitor rollback instructions.
- Add validator, local HTTP integration and cross-process nonce-consumption tests.

The protocol does not attest a browser or stop a holder of a valid proof and
transaction token from forwarding them to the intended backend before first use.
CORS does not authenticate server-to-server callers. Cross-process nonce safety
is not a claim that every wallet operation supports multi-instance deployment.

Read the [community explanation](https://github.com/nostr-wot/nostr-wot-extension/blob/main/docs/guides/backend-authentication.md),
[authentication API](README.md#authentication) and [deployment runbook](RUNBOOK.md).

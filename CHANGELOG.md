# Changelog

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

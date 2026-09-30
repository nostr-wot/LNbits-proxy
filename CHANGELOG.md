# Changelog

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

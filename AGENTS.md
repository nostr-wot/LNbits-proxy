# LNbits-proxy

This repository owns the provisioning service at `zaps.nostr-wot.com`. Host details,
deploy paths and credentials live outside this public repository; see the private ops
notes. Deploy with `./deploy.sh`, never by copying files onto the box by hand.
The extension UI/client lives in [nostr-wot-extension](https://github.com/nostr-wot/nostr-wot-extension)
and its [AGENTS.md](../nostr-wot-extension/AGENTS.md). Keep this API contract and the
extension's wallet documentation/tests in sync. Do not duplicate server code there.

- Author commits solely as the user. No AI attribution, signer or co-author trailers.
- Work in a dedicated worktree; keep the main clone clean and fast-forward it after merge.
- Use Node 24+. Run `npm ci`, `npm test`, and `node --check server.js` before committing.
- NWC management is wallet-scoped. Require the wallet Admin API key, never the instance
  administrator credential from a client. Retain LNbits account/extension restrictions.
- Generate NWC client secrets in the extension. Never send them to this proxy, log
  them, include them in URLs, or write them unencrypted. The provider's dummy-secret
  pairing lookup stays on loopback and only returns public provider/relay information.
- New connections grant pay/lookup/info only, with positive daily budgets and expiry.
  Revoke only the authenticated wallet's connection; do not retry payment requests.
- Production changes require a dated backup and syntax/tests before restarting only
  `zaps-provision`. Check public challenge, wallet auth and NWC management afterward.
  Do not restart LNbits or Phoenixd for proxy-only changes. Never use customer funds
  in tests. Use isolated empty wallets for live connection checks and revoke test grants.
- Compare live `server.js` with Git before deploy. Preserve the existing NIP-57
  double-encoded zap-request fix; production previously contained this untracked change.
- Read [README.md](README.md) for endpoints and configuration, and [RUNBOOK.md](RUNBOOK.md)
  when something is broken. Never commit `.env`, wallet databases, credentials, generated
  operational backups, or host addresses: this repository is public.

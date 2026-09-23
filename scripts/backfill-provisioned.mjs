#!/usr/bin/env node
/**
 * Copy the existing pubkey to wallet mapping out of LNbits and into the proxy's
 * own database, then prove that every pubkey still resolves to exactly the same
 * wallet it did before.
 *
 * Until now the mapping lived in accounts.pubkey, which LNbits lets any
 * logged-in user set on their own account. Running this while LNbits has never
 * been exposed is what makes the copy trustworthy: nothing could have planted a
 * row. Defer it past the day LNbits becomes reachable and the copy inherits
 * whatever an attacker put there.
 *
 *   node scripts/backfill-provisioned.mjs --dry-run
 *   node scripts/backfill-provisioned.mjs
 *   node scripts/backfill-provisioned.mjs --verify-only
 *
 * Idempotent: safe to run repeatedly, including after deploying the new code,
 * to pick up anything provisioned in between.
 */
import { DatabaseSync } from 'node:sqlite';
import { existsSync } from 'node:fs';

const LNBITS_DB_PATH = process.env.LNBITS_DB_PATH || '/home/lnbits/lnbits/data/database.sqlite3';
const PROVISION_DB_PATH = process.env.PROVISION_DB_PATH || '/srv/zaps-provision/provisioning.sqlite3';

const dryRun = process.argv.includes('--dry-run');
const verifyOnly = process.argv.includes('--verify-only');

if (!existsSync(LNBITS_DB_PATH)) {
  console.error(`LNbits database not found: ${LNBITS_DB_PATH}`);
  process.exit(1);
}

const lnbits = new DatabaseSync(LNBITS_DB_PATH, { readOnly: true });
lnbits.exec('PRAGMA busy_timeout = 5000');

const provision = new DatabaseSync(PROVISION_DB_PATH);
provision.exec('PRAGMA busy_timeout = 5000');
provision.exec(`
  CREATE TABLE IF NOT EXISTS provisioned (
    pubkey     TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    wallet_id  TEXT NOT NULL,
    created_at REAL NOT NULL
  )
`);

/** Exactly what the proxy used to return, for one pubkey. */
const legacyLookup = (pubkey) => lnbits.prepare(`
  SELECT w.id, w.name, w.adminkey, w.inkey, w."user"
  FROM accounts a
  JOIN wallets w ON w."user" = a.id
  WHERE a.pubkey = ? AND w.deleted = 0
  ORDER BY w.created_at ASC
  LIMIT 1
`).get(pubkey);

/** Exactly what the proxy returns now, for one pubkey. */
const currentLookup = (pubkey) => {
  const m = provision.prepare('SELECT user_id, wallet_id FROM provisioned WHERE pubkey = ?').get(pubkey);
  if (!m) return undefined;
  return lnbits.prepare(`
    SELECT w.id, w.name, w.adminkey, w.inkey, w."user"
    FROM wallets w
    WHERE w.id = ? AND w."user" = ? AND w.deleted = 0
  `).get(m.wallet_id, m.user_id);
};

const pubkeys = lnbits.prepare(`
  SELECT DISTINCT a.pubkey
  FROM accounts a
  JOIN wallets w ON w."user" = a.id
  WHERE a.pubkey IS NOT NULL AND a.pubkey != '' AND w.deleted = 0
`).all().map(r => r.pubkey);

console.log(`Pubkeys with a live wallet in LNbits: ${pubkeys.length}`);

if (!verifyOnly) {
  let inserted = 0, unchanged = 0;
  const upsert = provision.prepare(`
    INSERT INTO provisioned (pubkey, user_id, wallet_id, created_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(pubkey) DO UPDATE SET user_id = excluded.user_id, wallet_id = excluded.wallet_id
  `);
  const now = Date.now() / 1000;
  for (const pubkey of pubkeys) {
    const legacy = legacyLookup(pubkey);
    if (!legacy) continue;
    const existing = provision.prepare('SELECT user_id, wallet_id FROM provisioned WHERE pubkey = ?').get(pubkey);
    if (existing && existing.wallet_id === legacy.id && existing.user_id === legacy.user) { unchanged++; continue; }
    if (dryRun) { inserted++; continue; }
    upsert.run(pubkey, legacy.user, legacy.id, now);
    inserted++;
  }
  console.log(`${dryRun ? 'Would write' : 'Wrote'}: ${inserted}   already correct: ${unchanged}`);
}

// ── Verification: the part that matters ──
// Every pubkey must resolve to the same wallet, with the same keys, as before.
let ok = 0;
const mismatches = [];
for (const pubkey of pubkeys) {
  const before = legacyLookup(pubkey);
  const after = dryRun ? undefined : currentLookup(pubkey);
  if (dryRun) continue;
  const same = before && after
    && before.id === after.id
    && before.user === after.user
    && before.adminkey === after.adminkey
    && before.inkey === after.inkey;
  if (same) ok++;
  else mismatches.push({ pubkey: pubkey.slice(0, 16) + '...', beforeWallet: before?.id ?? null, afterWallet: after?.id ?? null });
}

if (dryRun) {
  console.log('Dry run: nothing written, so no verification performed.');
  process.exit(0);
}

console.log(`Verified identical before/after: ${ok}/${pubkeys.length}`);
if (mismatches.length) {
  console.error('MISMATCHES - do not deploy:');
  for (const m of mismatches) console.error('  ', JSON.stringify(m));
  process.exit(1);
}

// A mapping pointing at a wallet that no longer exists would silently mint a
// second wallet on next provision, so surface it rather than leaving it.
const orphans = provision.prepare('SELECT pubkey, wallet_id FROM provisioned').all()
  .filter(r => !lnbits.prepare('SELECT 1 FROM wallets WHERE id = ? AND deleted = 0').get(r.wallet_id));
console.log(`Mappings pointing at a missing or deleted wallet: ${orphans.length}`);
for (const o of orphans) console.warn('  orphan:', o.pubkey.slice(0, 16) + '...', '->', o.wallet_id);

lnbits.close();
provision.close();
console.log('OK');

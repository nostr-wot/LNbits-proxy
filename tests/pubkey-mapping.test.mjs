// The proxy must decide whose wallet is whose from its OWN table, never from
// accounts.pubkey, which LNbits lets any logged-in user set on their account.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const BACKFILL = resolve(import.meta.dirname, '../scripts/backfill-provisioned.mjs');

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'pubkeymap-'));
  const lnbitsPath = join(dir, 'lnbits.sqlite3');
  const provisionPath = join(dir, 'provisioning.sqlite3');
  const db = new DatabaseSync(lnbitsPath);
  db.exec(`
    CREATE TABLE accounts (id TEXT PRIMARY KEY, username TEXT, pubkey TEXT);
    CREATE TABLE wallets (id TEXT PRIMARY KEY, name TEXT, "user" TEXT, adminkey TEXT, inkey TEXT, deleted INT, created_at REAL);
  `);
  db.close();
  return { dir, lnbitsPath, provisionPath };
}

function addUser({ lnbitsPath }, { userId, pubkey, walletId, createdAt = 1000 }) {
  const db = new DatabaseSync(lnbitsPath);
  db.prepare('INSERT OR REPLACE INTO accounts VALUES (?,?,?)').run(userId, null, pubkey);
  db.prepare('INSERT OR REPLACE INTO wallets VALUES (?,?,?,?,?,?,?)')
    .run(walletId, 'w', userId, `admin-${walletId}`, `in-${walletId}`, 0, createdAt);
  db.close();
}

function runBackfill(f, args = []) {
  return spawnSync(process.execPath, [BACKFILL, ...args], {
    encoding: 'utf8',
    env: { ...process.env, LNBITS_DB_PATH: f.lnbitsPath, PROVISION_DB_PATH: f.provisionPath },
  });
}

// Mirrors findWalletByPubkey in server.js.
function lookup(f, pubkey) {
  const pdb = new DatabaseSync(f.provisionPath);
  let m;
  try {
    // openProvisionDb creates the schema on first use; mirror that here.
    pdb.exec(`CREATE TABLE IF NOT EXISTS provisioned (
      pubkey TEXT PRIMARY KEY, user_id TEXT NOT NULL, wallet_id TEXT NOT NULL, created_at REAL NOT NULL)`);
    m = pdb.prepare('SELECT user_id, wallet_id FROM provisioned WHERE pubkey = ?').get(pubkey);
  } finally { pdb.close(); }
  if (!m) return null;
  const db = new DatabaseSync(f.lnbitsPath, { readOnly: true });
  try {
    return db.prepare('SELECT id, name, adminkey, inkey, "user" FROM wallets WHERE id = ? AND "user" = ? AND deleted = 0')
      .get(m.wallet_id, m.user_id) || null;
  } finally { db.close(); }
}

test('every existing user keeps the exact wallet they had before the migration', (t) => {
  const f = fixture();
  t.after(() => rmSync(f.dir, { recursive: true, force: true }));

  const users = Array.from({ length: 25 }, (_, i) => ({
    userId: `u${i}`, pubkey: String(i).padStart(2, '0').repeat(32), walletId: `w${i}`,
  }));
  for (const u of users) addUser(f, u);

  const r = runBackfill(f);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /Verified identical before\/after: 25\/25/);

  for (const u of users) {
    const w = lookup(f, u.pubkey);
    assert.ok(w, `pubkey ${u.pubkey.slice(0, 8)} lost its wallet`);
    assert.equal(w.id, u.walletId);
    assert.equal(w.adminkey, `admin-${u.walletId}`, 'admin key must be unchanged: this is fund access');
  }
});

test('an attacker who sets accounts.pubkey to a victim npub gets nothing', (t) => {
  const f = fixture();
  t.after(() => rmSync(f.dir, { recursive: true, force: true }));

  const victim = 'aa'.repeat(32);
  addUser(f, { userId: 'victim', pubkey: victim, walletId: 'victim-wallet' });
  runBackfill(f);

  // The attacker does what LNbits permits: claims an npub on their own account.
  // Under the old join this was enough to be handed that wallet.
  const db = new DatabaseSync(f.lnbitsPath);
  db.prepare('INSERT INTO accounts VALUES (?,?,?)').run('attacker', null, 'unrelated');
  db.prepare('INSERT INTO wallets VALUES (?,?,?,?,?,?,?)')
    .run('attacker-wallet', 'w', 'attacker', 'admin-attacker', 'in-attacker', 0, 1);
  db.prepare('UPDATE accounts SET pubkey = ? WHERE id = ?').run(victim, 'attacker');
  db.close();

  // What the previous implementation did: join wallets through accounts.pubkey.
  const legacy = (() => {
    const d = new DatabaseSync(f.lnbitsPath, { readOnly: true });
    try {
      return d.prepare(`SELECT w.id, w.adminkey FROM accounts a JOIN wallets w ON w."user" = a.id
                        WHERE a.pubkey = ? AND w.deleted = 0 ORDER BY w.created_at ASC LIMIT 1`).get(victim);
    } finally { d.close(); }
  })();
  assert.equal(legacy.id, 'attacker-wallet',
    'precondition: under the old join the attacker would have been handed the wallet');

  const w = lookup(f, victim);
  assert.equal(w.id, 'victim-wallet', 'the victim must still resolve to their own wallet');
  assert.notEqual(w.id, 'attacker-wallet');
  assert.equal(w.adminkey, 'admin-victim-wallet');
});

test('a pubkey never provisioned resolves to nothing, even with accounts.pubkey set', (t) => {
  const f = fixture();
  t.after(() => rmSync(f.dir, { recursive: true, force: true }));

  const target = 'bb'.repeat(32);
  // Squatted in LNbits but never provisioned through this service.
  addUser(f, { userId: 'squatter', pubkey: target, walletId: 'squatter-wallet' });
  // Deliberately no backfill: this models a row appearing after the migration.
  assert.equal(lookup(f, target), null);
});

test('backfill is idempotent and picks up later provisions', (t) => {
  const f = fixture();
  t.after(() => rmSync(f.dir, { recursive: true, force: true }));

  addUser(f, { userId: 'a', pubkey: 'cc'.repeat(32), walletId: 'wa' });
  assert.equal(runBackfill(f).status, 0);
  const first = runBackfill(f);
  assert.equal(first.status, 0);
  assert.match(first.stdout, /already correct: 1/);

  addUser(f, { userId: 'b', pubkey: 'dd'.repeat(32), walletId: 'wb' });
  const second = runBackfill(f);
  assert.equal(second.status, 0);
  assert.match(second.stdout, /Verified identical before\/after: 2\/2/);
  assert.equal(lookup(f, 'dd'.repeat(32)).id, 'wb');
});

test('the oldest wallet wins, matching the previous behaviour', (t) => {
  const f = fixture();
  t.after(() => rmSync(f.dir, { recursive: true, force: true }));

  const pk = 'ee'.repeat(32);
  addUser(f, { userId: 'u', pubkey: pk, walletId: 'newer', createdAt: 2000 });
  addUser(f, { userId: 'u', pubkey: pk, walletId: 'older', createdAt: 1000 });
  assert.equal(runBackfill(f).status, 0);
  assert.equal(lookup(f, pk).id, 'older');
});

test('a deleted wallet is not handed out', (t) => {
  const f = fixture();
  t.after(() => rmSync(f.dir, { recursive: true, force: true }));

  const pk = 'ff'.repeat(32);
  addUser(f, { userId: 'u', pubkey: pk, walletId: 'w1' });
  runBackfill(f);
  const db = new DatabaseSync(f.lnbitsPath);
  db.prepare('UPDATE wallets SET deleted = 1 WHERE id = ?').run('w1');
  db.close();
  assert.equal(lookup(f, pk), null, 'a deleted wallet must look unprovisioned');
});

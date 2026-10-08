// The pubkey-to-wallet mapping is the one file here that cannot be rebuilt. If it
// is lost, every returning user looks unprovisioned and is handed a NEW wallet,
// stranding the funds in their old one. The deploy migrates it, so it is copied
// first.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync, readdirSync, writeFileSync, statSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const BACKUP = resolve(import.meta.dirname, '../scripts/backup-provision-db.mjs');

function fixture({ rows = 3 } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'provision-backup-'));
  const dbPath = join(dir, 'provisioning.sqlite3');
  const db = new DatabaseSync(dbPath);
  db.exec('CREATE TABLE provisioned (pubkey TEXT PRIMARY KEY, user_id TEXT NOT NULL, wallet_id TEXT NOT NULL, created_at REAL NOT NULL)');
  for (let i = 0; i < rows; i++) {
    db.prepare('INSERT INTO provisioned VALUES (?,?,?,?)').run(`${i}`.repeat(4), `u${i}`, `w${i}`, 1000 + i);
  }
  db.close();
  const dest = join(dir, 'backups');
  mkdirSync(dest);
  return { dir, dbPath, dest, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const run = (args, env = {}) =>
  spawnSync(process.execPath, [BACKUP, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });

test('writes a readable copy holding exactly the rows the live mapping had', (t) => {
  const f = fixture(); t.after(f.cleanup);

  const result = run([f.dbPath, f.dest]);

  assert.equal(result.status, 0, result.stderr);
  const [name] = readdirSync(f.dest);
  assert.match(name, /^provisioning\.sqlite3\.bak-\d{8}-\d{6}$/);

  // A file of the right size is not a backup; it has to open and read back.
  const copy = new DatabaseSync(join(f.dest, name), { readOnly: true });
  try {
    const live = copy.prepare('SELECT pubkey, wallet_id FROM provisioned ORDER BY pubkey').all();
    assert.deepEqual(live.map(r => r.wallet_id), ['w0', 'w1', 'w2']);
  } finally { copy.close(); }
});

test('keeps the copy unreadable to other users', (t) => {
  const f = fixture(); t.after(f.cleanup);

  run([f.dbPath, f.dest]);

  const [name] = readdirSync(f.dest);
  assert.equal(statSync(join(f.dest, name)).mode & 0o777, 0o600);
});

test('prunes to the newest few, so unattended deploys cannot fill the disk', (t) => {
  const f = fixture(); t.after(f.cleanup);
  for (let i = 1; i <= 7; i++) {
    writeFileSync(join(f.dest, `provisioning.sqlite3.bak-2026010${i}-000000`), 'old');
  }

  const result = run([f.dbPath, f.dest], { ZAPS_BACKUP_KEEP: '3' });

  assert.equal(result.status, 0, result.stderr);
  const kept = readdirSync(f.dest).sort();
  assert.equal(kept.length, 3);
  // The newest are kept, and the one just written is always among them.
  assert.ok(kept.some(n => /bak-\d{8}-\d{6}$/.test(n) && !n.includes('2026010')), 'dropped the new backup');
  assert.ok(!kept.includes('provisioning.sqlite3.bak-20260101-000000'), 'kept the oldest');
});

test('says there is nothing to copy on a first deploy instead of failing', (t) => {
  const f = fixture(); t.after(f.cleanup);

  const result = run([join(f.dir, 'absent.sqlite3'), f.dest]);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /nothing to back up/i);
  assert.deepEqual(readdirSync(f.dest), []);
});

test('fails rather than reporting success when the mapping cannot be read', (t) => {
  const f = fixture(); t.after(f.cleanup);
  const corrupt = join(f.dir, 'corrupt.sqlite3');
  writeFileSync(corrupt, 'this is not a database');

  const result = run([corrupt, f.dest]);

  assert.notEqual(result.status, 0);
  assert.deepEqual(readdirSync(f.dest), [], 'left a copy that is not a usable backup');
});

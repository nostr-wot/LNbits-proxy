#!/usr/bin/env node
/**
 * Copy the pubkey-to-wallet mapping before anything migrates it.
 *
 * This table is the only state here that cannot be rebuilt from anywhere else. The
 * deploy's migration step writes to it, and `server.js` explains what losing it
 * costs: every returning user resolves as unprovisioned, is given a NEW wallet, and
 * the funds stay in the old one. Backing up the code but not this file was the gap
 * automated deploys would have widened.
 *
 * Uses SQLite's own VACUUM INTO rather than cp, so the copy is a consistent snapshot
 * even while the service is mid-write, and is verified by reading it back before any
 * older copy is pruned.
 *
 * Usage: node scripts/backup-provision-db.mjs <mapping.sqlite3> <backup-dir>
 *   ZAPS_BACKUP_KEEP  how many copies to keep (default 10)
 */
import { DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync, readdirSync, rmSync, chmodSync } from 'node:fs';
import { basename, join } from 'node:path';

const [source, destDir] = process.argv.slice(2);
if (!source || !destDir) {
  console.error('usage: backup-provision-db.mjs <mapping.sqlite3> <backup-dir>');
  process.exit(2);
}
const keep = Number.parseInt(process.env.ZAPS_BACKUP_KEEP ?? '10', 10);
if (!Number.isSafeInteger(keep) || keep < 1) {
  console.error(`backup: ZAPS_BACKUP_KEEP must be a positive whole number, got "${process.env.ZAPS_BACKUP_KEEP}"`);
  process.exit(2);
}

// A first deploy has no mapping yet. That is not a failure, and treating it as one
// would block the very first release.
if (!existsSync(source)) {
  console.log(`backup: ${source} does not exist yet, nothing to back up`);
  process.exit(0);
}

const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
const name = `${basename(source)}.bak-${stamp}`;
const target = join(destDir, name);

mkdirSync(destDir, { recursive: true });
if (existsSync(target)) rmSync(target);

try {
  const db = new DatabaseSync(source, { readOnly: true });
  try {
    // Fails loudly on a file that is not a database, rather than copying the damage.
    db.prepare('SELECT count(*) AS n FROM sqlite_schema').get();
    // A SQL string literal, so single quotes doubled — JSON quoting would make
    // SQLite read the path as an identifier.
    db.exec(`VACUUM INTO '${target.replace(/'/g, "''")}'`);
  } finally {
    db.close();
  }
} catch (e) {
  if (existsSync(target)) rmSync(target, { force: true });
  console.error(`backup: cannot read ${source}: ${e.message}`);
  process.exit(1);
}

// The mapping says which wallet belongs to which pubkey; it is not world-readable
// at the source and must not become so in the backup directory.
chmodSync(target, 0o600);

// Read the copy back before trusting it enough to prune anything older.
try {
  const copy = new DatabaseSync(target, { readOnly: true });
  try { copy.prepare('SELECT count(*) AS n FROM sqlite_schema').get(); }
  finally { copy.close(); }
} catch (e) {
  rmSync(target, { force: true });
  console.error(`backup: the copy of ${source} could not be read back: ${e.message}`);
  process.exit(1);
}

const prefix = `${basename(source)}.bak-`;
const existing = readdirSync(destDir).filter(f => f.startsWith(prefix)).sort();
for (const stale of existing.slice(0, Math.max(0, existing.length - keep))) {
  rmSync(join(destDir, stale), { force: true });
}
console.log(`backup: wrote ${target} (keeping ${keep})`);

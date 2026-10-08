// The inline version of this ran under `set -euo pipefail` and used a glob that
// matches nothing when a file has no backups yet. ls exited non-zero, pipefail
// propagated it, and the deploy died after taking its backups and before installing
// anything. It broke every deploy, so it is a script with tests now.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const PRUNE = resolve(import.meta.dirname, '../scripts/prune-backups.sh');
const run = (...args) => spawnSync('bash', [PRUNE, ...args], { encoding: 'utf8' });

function dirWith(files) {
  const dir = mkdtempSync(join(tmpdir(), 'prune-'));
  for (const f of files) writeFileSync(join(dir, f), 'x');
  return dir;
}
const stamps = (n, base = 'server.js') =>
  Array.from({ length: n }, (_, i) => `${base}.bak-202610${String(i + 1).padStart(2, '0')}-000000`);

test('succeeds and removes nothing when there are no backups at all', (t) => {
  const dir = dirWith(['server.js', 'package.json']);
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const result = run(dir, '10');

  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readdirSync(dir).sort(), ['package.json', 'server.js']);
});

test('keeps everything while there are no more than the limit', (t) => {
  const dir = dirWith(stamps(10));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  assert.equal(run(dir, '10').status, 0);
  assert.equal(readdirSync(dir).length, 10);
});

test('drops the oldest and keeps the newest when over the limit', (t) => {
  const dir = dirWith(stamps(13));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  assert.equal(run(dir, '10').status, 0);

  const left = readdirSync(dir).sort();
  assert.equal(left.length, 10);
  assert.equal(left[0], 'server.js.bak-20261004-000000');
  assert.equal(left.at(-1), 'server.js.bak-20261013-000000');
});

test('prunes each file independently, not the directory as a whole', (t) => {
  // The real directory holds backups of several files at once, and a file with two
  // backups must not lose them because another file has twelve.
  const dir = dirWith([...stamps(12, 'server.js'), ...stamps(2, 'auth-v2.mjs')]);
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  assert.equal(run(dir, '10').status, 0);

  const left = readdirSync(dir);
  assert.equal(left.filter(f => f.startsWith('server.js.')).length, 10);
  assert.equal(left.filter(f => f.startsWith('auth-v2.mjs.')).length, 2, 'pruned an unrelated file');
});

test('succeeds on a directory that does not exist', (t) => {
  const result = run('/nonexistent-prune-target', '10');
  assert.equal(result.status, 0, result.stderr);
});

test('refuses a limit that is not a positive whole number', (t) => {
  const dir = dirWith(stamps(12));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  for (const keep of ['0', '-1', 'ten', '']) {
    assert.notEqual(run(dir, keep).status, 0, `accepted ${JSON.stringify(keep)}`);
  }
  assert.equal(readdirSync(dir).length, 12, 'deleted something on a bad limit');
});

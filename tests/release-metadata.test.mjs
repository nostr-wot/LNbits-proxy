// A release is three things agreeing: the tag, package.json, and a CHANGELOG
// heading. CI runs this checker on the tag, so a release that disagrees with
// itself cannot be published and cannot then be deployed by the box.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const CHECK = resolve(import.meta.dirname, '../scripts/check-release.mjs');

function repo({ version = '1.1.0', changelog = '# Changelog\n\n## 1.1.0 — 2026-10-08\n\n- A change.\n' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'release-check-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'p', version }, null, 2));
  writeFileSync(join(dir, 'CHANGELOG.md'), changelog);
  return dir;
}

const check = (dir, tag) => spawnSync(process.execPath, [CHECK, tag], { cwd: dir, encoding: 'utf8' });

test('accepts a tag whose version matches package.json and has a changelog section', () => {
  const result = check(repo(), 'v1.1.0');
  assert.equal(result.status, 0, result.stderr);
});

test('refuses a tag that does not match package.json', () => {
  const result = check(repo({ version: '1.0.0' }), 'v1.1.0');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /package\.json/);
});

test('refuses a release with no changelog section for that exact version', () => {
  const result = check(repo({ changelog: '# Changelog\n\n## Unreleased\n\n- A change.\n' }), 'v1.1.0');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /CHANGELOG/);
});

test('refuses a changelog section that is only a heading', () => {
  const result = check(repo({ changelog: '# Changelog\n\n## 1.1.0\n\n## 1.0.0\n\n- Older.\n' }), 'v1.1.0');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /empty/i);
});

test('refuses a tag that is not a plain version', () => {
  for (const tag of ['1.1.0', 'v1.1', 'v1.1.0-rc1', 'release-1.1.0', 'v1.1.0 ']) {
    assert.equal(check(repo(), tag).status, 1, `accepted ${tag}`);
  }
});

test('--notes prints the changelog section for the tag, and nothing else', () => {
  const dir = repo({ changelog: '# Changelog\n\n## 1.1.0 — 2026-10-08\n\n- A change.\n- Another.\n\n## 1.0.0\n\n- Older.\n' });
  const result = spawnSync(process.execPath, [CHECK, 'v1.1.0', '--notes'], { cwd: dir, encoding: 'utf8' });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), '- A change.\n- Another.');
});

test('--notes refuses the same releases the check refuses', () => {
  const dir = repo({ version: '1.0.0' });
  assert.notEqual(spawnSync(process.execPath, [CHECK, 'v1.1.0', '--notes'], { cwd: dir, encoding: 'utf8' }).status, 0);
});

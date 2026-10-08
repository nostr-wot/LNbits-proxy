// The box pulls releases rather than being pushed to, so this script is what
// decides, unattended and as root, that production should restart onto new code.
// Everything it refuses matters more than what it accepts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, chmodSync, mkdirSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';

const AUTO_DEPLOY = resolve(import.meta.dirname, '../scripts/auto-deploy.sh');

/**
 * A checkout with a trusted history (refs/remotes/origin/main), an optional tag on
 * it, a stub deploy.sh that records its arguments, and a stub release feed.
 */
function box({ release, tag = 'v1.1.0', tagOnSideBranch = false, deployExit = 0, recorded } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'autodeploy-'));
  // The script runs from the checkout it deploys, so the fixture is that checkout.
  mkdirSync(join(dir, 'scripts'), { recursive: true });
  const script = join(dir, 'scripts', 'auto-deploy.sh');
  copyFileSync(AUTO_DEPLOY, script);
  chmodSync(script, 0o755);
  const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' });
  git('init', '-q', '-b', 'main');
  git('config', 'user.email', 't@t.test');
  git('config', 'user.name', 'T');
  writeFileSync(join(dir, 'server.js'), '// v1\n');
  git('add', '-A');
  git('commit', '-qm', 'first');
  const trusted = git('rev-parse', 'HEAD').trim();

  if (tagOnSideBranch) {
    // A commit that exists in the repository but is not in the trusted history:
    // what a tag pushed onto someone's branch would look like.
    git('checkout', '-q', '-b', 'side');
    writeFileSync(join(dir, 'server.js'), '// unreviewed\n');
    git('commit', '-qam', 'side');
    git('tag', tag);
    git('checkout', '-q', 'main');
  } else if (tag) {
    git('tag', tag);
  }
  // The box's checkout tracks a remote; the fixture fakes that ref directly.
  git('update-ref', 'refs/remotes/origin/main', trusted);

  const deployLog = join(dir, 'deploy-calls.log');
  writeFileSync(join(dir, 'stub-deploy.sh'),
    `#!/usr/bin/env bash\necho "$@" >> ${JSON.stringify(deployLog)}\nexit ${deployExit}\n`);
  chmodSync(join(dir, 'stub-deploy.sh'), 0o755);

  const state = join(dir, 'deployed-version');
  if (recorded) writeFileSync(state, `${recorded}\n`);

  const feed = join(dir, 'release.json');
  writeFileSync(feed, JSON.stringify(release ?? { tag_name: tag, draft: false, prerelease: false }));

  return {
    dir, state, deployLog,
    run() {
      return spawnSync('bash', [script], {
        cwd: dir, encoding: 'utf8',
        env: {
          ...process.env,
          ZAPS_RELEASE_FETCH: `cat ${JSON.stringify(feed)}`,
          ZAPS_DEPLOY_CMD: join(dir, 'stub-deploy.sh'),
          ZAPS_STATE_FILE: state,
          ZAPS_SKIP_FETCH: '1',
        },
      });
    },
    deployedWith() {
      return existsSync(deployLog) ? readFileSync(deployLog, 'utf8').trim() : null;
    },
    recordedVersion() {
      return existsSync(state) ? readFileSync(state, 'utf8').trim() : null;
    },
    cleanup() { rmSync(dir, { recursive: true, force: true }); },
  };
}

test('deploys a published release at the tag it names, and records it', (t) => {
  const b = box(); t.after(() => b.cleanup());

  const result = b.run();

  assert.equal(result.status, 0, result.stderr);
  assert.equal(b.deployedWith(), '--ref v1.1.0');
  assert.equal(b.recordedVersion(), 'v1.1.0');
});

test('does nothing when the recorded version is already the current release', (t) => {
  const b = box({ recorded: 'v1.1.0' }); t.after(() => b.cleanup());

  const result = b.run();

  assert.equal(result.status, 0, result.stderr);
  assert.equal(b.deployedWith(), null, 'redeployed code that was already live');
});

test('refuses a draft or a prerelease', (t) => {
  for (const release of [
    { tag_name: 'v1.1.0', draft: true, prerelease: false },
    { tag_name: 'v1.1.0', draft: false, prerelease: true },
  ]) {
    const b = box({ release });
    try {
      assert.notEqual(b.run().status, 0);
      assert.equal(b.deployedWith(), null, `deployed ${JSON.stringify(release)}`);
    } finally { b.cleanup(); }
  }
});

test('refuses a tag that is not in the trusted history', (t) => {
  // Anyone who can push a tag could otherwise point production at any commit.
  const b = box({ tagOnSideBranch: true }); t.after(() => b.cleanup());

  const result = b.run();

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /origin\/main|trusted/i);
  assert.equal(b.deployedWith(), null);
});

test('refuses a tag name that is not a plain version', (t) => {
  for (const tag_name of ['1.1.0', 'v1.1', 'v1.1.0-rc1', 'latest', '', 'v1.1.0; rm -rf /']) {
    const b = box({ release: { tag_name, draft: false, prerelease: false }, tag: 'v1.1.0' });
    try {
      assert.notEqual(b.run().status, 0, `accepted ${tag_name}`);
      assert.equal(b.deployedWith(), null, `deployed ${tag_name}`);
    } finally { b.cleanup(); }
  }
});

test('does not record a version whose deploy failed, so the next tick retries', (t) => {
  const b = box({ deployExit: 1 }); t.after(() => b.cleanup());

  const result = b.run();

  assert.notEqual(result.status, 0);
  assert.equal(b.deployedWith(), '--ref v1.1.0', 'deploy was never attempted');
  assert.equal(b.recordedVersion(), null, 'recorded a release that did not deploy');
});

test('refuses a release whose tag does not exist in the repository', (t) => {
  const b = box({ release: { tag_name: 'v9.9.9', draft: false, prerelease: false } });
  t.after(() => b.cleanup());

  const result = b.run();

  assert.notEqual(result.status, 0);
  assert.equal(b.deployedWith(), null);
});

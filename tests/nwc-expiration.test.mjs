import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

test('NWC expiration repair preserves expiry checks, rejects malformed tags and is idempotent', () => {
  execFileSync('python3', ['-c', `
import importlib.util, pathlib, tempfile
spec = importlib.util.spec_from_file_location('repair', ${JSON.stringify(resolve('scripts/repair-nwc-expiration.py'))})
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
# Reproduce the production crash on a valid NIP-40 tag.
try:
    exec(m.OLD, {'tags': [['expiration', '123']]})
    raise AssertionError('original parser should reject this valid tag')
except TypeError:
    pass
for tags, expected in [([], -1), ([['p', 'wallet']], -1), ([['expiration','123']],123), ([[],['expiration','0']],0)]:
    scope = {'tags': tags}
    exec(m.NEW, scope)
    assert scope['expiration'] == expected
for tags in [[['expiration']], [['expiration','bad']], [['expiration',[]]]]:
    try:
        exec(m.NEW, {'tags': tags})
        raise AssertionError('malformed expiry must not reach payment dispatch')
    except (ValueError, TypeError):
        pass
# The repair changes only tag extraction; existing expired-event rejection stays intact.
source = 'def parse(tags, now):\\n    ' + m.OLD + '\\n    return expiration > 0 and expiration < now\\n'
with tempfile.TemporaryDirectory() as directory:
    p = pathlib.Path(directory) / 'nwcp.py'
    p.write_text(source)
    assert m.repair(p, True) == 'would-change' and p.read_text() == source
    assert m.repair(p) == 'changed'
    assert p.with_name(p.name+'.before-expiration-fix').read_text() == source
    assert m.repair(p) == 'unchanged'
    scope = {}
    exec(p.read_text(), scope)
    assert scope['parse']([['expiration','123']],124)
    assert not scope['parse']([['expiration','125']],124)
    assert not scope['parse']([],124)
    p.write_text('upstream changed')
    try:
        m.repair(p)
        raise AssertionError('unknown source must not be patched')
    except ValueError:
        pass
`], { stdio: 'pipe' });
});

import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('maintenance deployment dry-runs, restarts only LNbits once and restores on restart failure', () => {
  const root = mkdtempSync(join(tmpdir(), 'nwc-maintenance-'));
  try {
    mkdirSync(join(root, 'scripts'));
    mkdirSync(join(root, 'bin'));
    copyFileSync('deploy.sh', join(root, 'deploy.sh'));
    copyFileSync('scripts/repair-nwc-expiration.py', join(root, 'scripts/repair-nwc-expiration.py'));
    writeFileSync(join(root, 'bin/git'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    writeFileSync(join(root, 'bin/systemctl'), '#!/bin/sh\necho "$*" >> "$SERVICE_LOG"\n[ "$FAIL_RESTART" != 1 ]\n', { mode: 0o755 });
    const provider = join(root, 'nwcp.py');
    const original = 'expiration = int(next((tag for tag in tags if tag[0] == "expiration"), -1))\n';
    writeFileSync(provider, original);
    const env = { ...process.env, PATH: `${join(root,'bin')}:${process.env.PATH}`, NWC_PROVIDER_FILE: provider, SERVICE_LOG: join(root,'services.log') };
    const deploy = (args = [], extra = {}) => spawnSync('bash', [join(root,'deploy.sh'), '--repair-nwc-expiration', ...args], { env: { ...env, ...extra }, encoding: 'utf8' });
    assert.equal(deploy(['--dry-run']).status, 0);
    assert.equal(readFileSync(provider,'utf8'), original);
    assert.equal(deploy().status, 0);
    assert.equal(deploy().status, 0);
    const commands = readFileSync(env.SERVICE_LOG,'utf8').trim().split('\n');
    assert.equal(commands.filter(s => s === 'restart lnbits').length, 1);
    assert.ok(commands.every(s => s.endsWith(' lnbits')));
    writeFileSync(provider, original);
    assert.notEqual(deploy([], { FAIL_RESTART: '1' }).status, 0);
    assert.equal(readFileSync(provider,'utf8'), original);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

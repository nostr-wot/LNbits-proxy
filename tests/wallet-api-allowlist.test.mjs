// The wallet API allowlist is the only thing standing between the public
// internet and LNbits' authenticated API. Every path it opens must be opened
// for exactly one set of verbs, so these tests boot the real server and check
// what the allowlist lets through AND what it still refuses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createServer as createSocketServer } from 'node:net';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const SERVER = resolve(import.meta.dirname, '../server.js');
const KEY = 'wallet-key-under-test';

async function freePort() {
  const probe = createSocketServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address();
  await new Promise(r => probe.close(r));
  return port;
}

// Boots the real server.js in front of a stub LNbits that records every
// request it is handed, so "did this reach the backend?" is answerable.
async function startProxy(t) {
  const seen = [];
  const lnbits = createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, key: req.headers['x-api-key'] ?? null });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ fee_reserve: 2000 }));
  });
  lnbits.listen(0, '127.0.0.1');
  await once(lnbits, 'listening');

  const dir = mkdtempSync(join(tmpdir(), 'wallet-allowlist-'));
  // Only their existence is checked at startup; the wallet proxy never reads them.
  writeFileSync(join(dir, 'lnbits.sqlite3'), '');
  writeFileSync(join(dir, 'ext_lnurlp.sqlite3'), '');

  const port = await freePort();
  const child = spawn(process.execPath, [SERVER], {
    env: {
      ...process.env,
      PORT: String(port),
      LNBITS_URL: `http://127.0.0.1:${lnbits.address().port}`,
      LNBITS_ADMIN_KEY: 'admin-key-not-forwarded',
      LNBITS_DB_PATH: join(dir, 'lnbits.sqlite3'),
      LNURLP_DB_PATH: join(dir, 'ext_lnurlp.sqlite3'),
      PROVISION_DB_PATH: join(dir, 'provisioning.sqlite3'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const stderr = [];
  child.stderr.on('data', b => stderr.push(b.toString()));
  await new Promise((resolveReady, rejectReady) => {
    child.stdout.on('data', b => { if (b.toString().includes('listening')) resolveReady(); });
    child.once('exit', code =>
      rejectReady(new Error(`server exited early (${code}): ${stderr.join('')}`)));
  });

  t.after(async () => {
    child.kill('SIGKILL');
    await once(child, 'exit');
    lnbits.closeAllConnections();
    await new Promise(r => lnbits.close(r));
    rmSync(dir, { recursive: true, force: true });
  });

  const call = (path, { method = 'GET', key = KEY } = {}) =>
    fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: key === null ? {} : { 'X-Api-Key': key },
    });

  return { call, seen };
}

const INVOICE = 'lnbc10u1p3pj257pp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq';
const FEE_RESERVE = `/api/v1/payments/fee-reserve?invoice=${INVOICE}`;

test('the fee-reserve path is reachable with a wallet key, query string intact', async (t) => {
  const { call, seen } = await startProxy(t);

  const res = await call(FEE_RESERVE);

  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { fee_reserve: 2000 });
  assert.deepEqual(seen, [{ method: 'GET', url: FEE_RESERVE, key: KEY }]);
});

test('the fee-reserve path is refused without a wallet key, and never forwarded', async (t) => {
  const { call, seen } = await startProxy(t);

  const res = await call(FEE_RESERVE, { key: null });

  assert.equal(res.status, 401);
  assert.deepEqual(seen, []);
});

// Keys in the query string end up in this service's logs and the reverse
// proxy's, so the header form is the only accepted one — on this path too.
test('the fee-reserve path still refuses a key passed in the query string', async (t) => {
  const { call, seen } = await startProxy(t);

  const res = await call(`${FEE_RESERVE}&api-key=${KEY}`);

  assert.equal(res.status, 400);
  assert.deepEqual(seen, []);
});

test('no neighbouring payments path became reachable', async (t) => {
  const { call, seen } = await startProxy(t);
  const paymentHash = 'a'.repeat(64);

  const refused = {
    'POST to fee-reserve': await call(FEE_RESERVE, { method: 'POST' }),
    'payment lookup by hash': await call(`/api/v1/payments/${paymentHash}`),
    'fee-reserve with a trailing segment': await call('/api/v1/payments/fee-reserve/x'),
    'a sibling payments subpath': await call('/api/v1/payments/decode'),
  };

  for (const [what, res] of Object.entries(refused)) {
    assert.equal(res.status, 404, `${what} should be 404, got ${res.status}`);
  }
  assert.deepEqual(seen, []);
});

test('the wallet paths that were already allowlisted keep working', async (t) => {
  const { call, seen } = await startProxy(t);

  assert.equal((await call('/api/v1/wallet')).status, 200);
  assert.equal((await call('/api/v1/wallet', { method: 'POST' })).status, 200);
  assert.equal((await call('/api/v1/payments')).status, 200);
  assert.equal((await call('/api/v1/payments', { method: 'POST' })).status, 200);

  assert.deepEqual(seen.map(r => `${r.method} ${r.url}`), [
    'GET /api/v1/wallet',
    'POST /api/v1/wallet',
    'GET /api/v1/payments',
    'POST /api/v1/payments',
  ]);
});

// Per-entry verbs replaced a single shared GET-or-POST gate, so the verbs those
// two paths never accepted must still be refused.
test('the pre-existing paths still refuse the verbs they never accepted', async (t) => {
  const { call, seen } = await startProxy(t);

  for (const path of ['/api/v1/wallet', '/api/v1/payments']) {
    for (const method of ['PUT', 'DELETE', 'PATCH']) {
      const res = await call(path, { method });
      assert.equal(res.status, 404, `${method} ${path} should be 404, got ${res.status}`);
    }
  }
  assert.deepEqual(seen, []);
});

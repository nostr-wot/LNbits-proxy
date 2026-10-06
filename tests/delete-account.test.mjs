// POST /api/v2/delete-account against the real server.js, in front of a stub
// LNbits that serves wallet balances and the NWC provider API, with throwaway
// copies of the LNbits, lnurlp and proxy databases.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createServer as createSocketServer } from 'node:net';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { sha256 } from '../auth-v2.mjs';

const SERVER = resolve(import.meta.dirname, '../server.js');
const ORIGIN = 'https://wallet.test';
const PATH = '/api/v2/delete-account';
const NWC_A = '12'.repeat(32), NWC_B = '34'.repeat(32);

async function freePort() {
  const probe = createSocketServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address();
  await new Promise(r => probe.close(r));
  return port;
}

function person(name) {
  const key = generateSecretKey();
  return { name, key, pubkey: getPublicKey(key), user: `user-${name}`, wallet: `wallet-${name}`, adminkey: `admin-${name}` };
}

async function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'delete-account-'));
  const lnbitsPath = join(dir, 'lnbits.sqlite3');
  const lnurlpPath = join(dir, 'ext_lnurlp.sqlite3');
  const provisionPath = join(dir, 'provisioning.sqlite3');
  const people = Object.fromEntries(['alice', 'bob', 'carol', 'dave', 'erin', 'mallory'].map(n => [n, person(n)]));

  const lnbits = new DatabaseSync(lnbitsPath);
  lnbits.exec(`
    CREATE TABLE accounts (id TEXT PRIMARY KEY, username TEXT, pubkey TEXT);
    CREATE TABLE wallets (id TEXT PRIMARY KEY, name TEXT, adminkey TEXT, inkey TEXT, "user" TEXT, deleted INTEGER);
    CREATE TABLE extensions ("user" TEXT, extension TEXT, active INTEGER, UNIQUE("user", extension));
    CREATE TABLE installed_extensions (id TEXT, active INTEGER);
    CREATE TABLE apipayments (checking_id TEXT, wallet_id TEXT, amount INTEGER, fee INTEGER, status TEXT);
    CREATE TABLE audit (user_id TEXT, path TEXT);
    CREATE TABLE webpush_subscriptions (endpoint TEXT, "user" TEXT, data TEXT, host TEXT);
    CREATE TABLE balance_notify (wallet TEXT, url TEXT);
    INSERT INTO installed_extensions VALUES ('nwcprovider', 1);
  `);
  const lnurlp = new DatabaseSync(lnurlpPath);
  lnurlp.exec('CREATE TABLE pay_links (id TEXT PRIMARY KEY, wallet TEXT, username TEXT)');
  const proxy = new DatabaseSync(provisionPath);
  proxy.exec('CREATE TABLE provisioned (pubkey TEXT PRIMARY KEY, user_id TEXT NOT NULL, wallet_id TEXT NOT NULL, created_at REAL NOT NULL)');

  for (const p of Object.values(people)) {
    if (p.name === 'mallory') continue; // never provisioned
    lnbits.prepare('INSERT INTO accounts VALUES (?, ?, ?)').run(p.user, p.name, p.pubkey);
    lnbits.prepare('INSERT INTO wallets VALUES (?, ?, ?, ?, ?, 0)').run(p.wallet, p.name, p.adminkey, `in-${p.name}`, p.user);
    lnbits.prepare("INSERT INTO extensions VALUES (?, 'nwcprovider', 1)").run(p.user);
    lnbits.prepare('INSERT INTO audit VALUES (?, ?)').run(p.user, '/api/v1/wallet');
    lnbits.prepare('INSERT INTO webpush_subscriptions VALUES (?, ?, ?, ?)').run(`https://push.test/${p.name}`, p.user, '{}', 'wallet.test');
    lnbits.prepare('INSERT INTO balance_notify VALUES (?, ?)').run(p.wallet, 'https://notify.test');
    lnurlp.prepare('INSERT INTO pay_links VALUES (?, ?, ?)').run(`link-${p.name}`, p.wallet, p.name);
    proxy.prepare('INSERT INTO provisioned VALUES (?, ?, ?, 0)').run(p.pubkey, p.user, p.wallet);
  }
  // carol has an outgoing payment still in flight.
  lnbits.prepare("INSERT INTO apipayments VALUES ('out-1', ?, -1000, 0, 'pending')").run(people.carol.wallet);
  // erin's extension was switched off after registering a grant.
  lnbits.prepare("UPDATE extensions SET active = 0 WHERE \"user\" = ?").run(people.erin.user);
  lnbits.close(); lnurlp.close(); proxy.close();

  // Stub LNbits: balances per admin key and the NWC provider's per-wallet grants.
  const balances = new Map(Object.values(people).map(p => [p.adminkey, 0]));
  balances.set(people.bob.adminkey, 5000);
  balances.delete(people.mallory.adminkey);
  const grants = new Map(Object.values(people).map(p => [p.adminkey, new Set()]));
  grants.get(people.alice.adminkey).add(NWC_A).add(NWC_B);   // one of these is expired upstream
  grants.get(people.erin.adminkey).add(NWC_A);
  const failures = { nwcDelete: 0 };
  const seen = [];
  const stub = createServer((req, res) => {
    const key = req.headers['x-api-key'];
    const url = new URL(req.url, 'http://x');
    seen.push({ method: req.method, path: url.pathname, search: url.search, key });
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (!balances.has(key)) return send(404, { detail: 'Wallet not found.' });
    if (url.pathname === '/api/v1/wallet' && req.method === 'GET') return send(200, { name: 'w', balance: balances.get(key) });
    if (url.pathname === '/nwcprovider/api/v1/nwc' && req.method === 'GET') {
      if (url.searchParams.get('include_expired') !== 'true') return send(400, {});
      return send(200, [...grants.get(key)].map(pubkey => ({ data: { pubkey } })));
    }
    const m = url.pathname.match(/^\/nwcprovider\/api\/v1\/nwc\/([0-9a-f]{64})$/);
    if (m && req.method === 'DELETE') {
      if (failures.nwcDelete > 0) { failures.nwcDelete--; return send(500, {}); }
      grants.get(key).delete(m[1]);
      return send(200, {});
    }
    return send(404, {});
  });
  stub.listen(0, '127.0.0.1');
  await once(stub, 'listening');

  const port = await freePort();
  const child = spawn(process.execPath, [SERVER], {
    env: {
      ...process.env, PORT: String(port), PUBLIC_ORIGIN: ORIGIN, BROWSER_ORIGINS: 'https://client.test',
      LNBITS_URL: `http://127.0.0.1:${stub.address().port}`, LNBITS_ADMIN_KEY: 'test-only',
      LNBITS_DB_PATH: lnbitsPath, LNURLP_DB_PATH: lnurlpPath, PROVISION_DB_PATH: provisionPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const output = [];
  child.stdout.on('data', b => output.push(b.toString()));
  child.stderr.on('data', b => output.push(b.toString()));
  await new Promise((ready, fail) => {
    child.stdout.on('data', b => { if (b.toString().includes('listening')) ready(); });
    child.once('exit', code => fail(new Error(`server exited early (${code}): ${output.join('')}`)));
  });
  t.after(async () => {
    child.kill('SIGKILL');
    await once(child, 'exit');
    stub.closeAllConnections();
    await new Promise(r => stub.close(r));
    rmSync(dir, { recursive: true, force: true });
  });

  // Every call gets its own client address so the per-IP limits do not couple
  // unrelated assertions; the rate-limit test reuses one on purpose.
  let ip = 0;
  const call = (path, body, headers = {}) => fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': `10.0.0.${++ip % 250}`, ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  async function signed(who, body, { forIp } = {}) {
    const raw = JSON.stringify(body), payload = sha256(raw), target = ORIGIN + PATH;
    const extra = forIp ? { 'X-Forwarded-For': forIp } : {};
    const issued = await (await call('/api/v2/provision/challenge', { url: target, method: 'POST', payload }, extra)).json();
    const event = finalizeEvent({
      kind: 27235, created_at: Math.floor(Date.now() / 1000), content: '',
      tags: [['u', target], ['method', 'POST'], ['payload', payload], ['challenge', issued.challenge], ['transaction', sha256(issued.transactionToken)]],
    }, who.key);
    return { event, headers: { Authorization: 'Nostr ' + Buffer.from(JSON.stringify(event)).toString('base64'), 'X-Nostr-Transaction': issued.transactionToken } };
  }
  const del = async (who, body = { confirm: 'delete-account', acknowledgeBalance: false }) => {
    const { headers } = await signed(who, body);
    return call(PATH, body, headers);
  };

  const read = (path, sql, ...args) => {
    const db = new DatabaseSync(path, { readOnly: true });
    try { return db.prepare(sql).all(...args); } finally { db.close(); }
  };
  const artefacts = (p) => ({
    mapping: read(provisionPath, 'SELECT 1 FROM provisioned WHERE pubkey = ?', p.pubkey).length,
    account: read(lnbitsPath, 'SELECT 1 FROM accounts WHERE id = ?', p.user).length,
    wallets: read(lnbitsPath, 'SELECT 1 FROM wallets WHERE "user" = ?', p.user).length,
    extensions: read(lnbitsPath, 'SELECT 1 FROM extensions WHERE "user" = ?', p.user).length,
    audit: read(lnbitsPath, 'SELECT 1 FROM audit WHERE user_id = ?', p.user).length,
    webpush: read(lnbitsPath, 'SELECT 1 FROM webpush_subscriptions WHERE "user" = ?', p.user).length,
    notify: read(lnbitsPath, 'SELECT 1 FROM balance_notify WHERE wallet = ?', p.wallet).length,
    payLinks: read(lnurlpPath, 'SELECT 1 FROM pay_links WHERE wallet = ?', p.wallet).length,
    grants: grants.get(p.adminkey)?.size ?? 0,
  });
  const deletions = () => read(provisionPath, 'SELECT * FROM account_deletions ORDER BY id');
  const lightningAddress = async (p) =>
    (await (await fetch(`http://127.0.0.1:${port}/api/lightning-address?pubkey=${p.pubkey}`)).json()).address;

  return { people, call, signed, del, artefacts, deletions, lightningAddress, grants, failures, seen, output, lnbitsPath, provisionPath, port };
}

const intact = { mapping: 1, account: 1, wallets: 1, extensions: 1, audit: 1, webpush: 1, notify: 1, payLinks: 1 };
const gone = { mapping: 0, account: 0, wallets: 0, extensions: 0, audit: 0, webpush: 0, notify: 0, payLinks: 0, grants: 0 };
const pick = (a) => Object.fromEntries(Object.keys(intact).map(k => [k, a[k]]));

test('authentication is required and bound to the exact body', async (t) => {
  const s = await setup(t);
  const { alice } = s.people;
  const body = { confirm: 'delete-account', acknowledgeBalance: false };

  assert.equal((await s.call(PATH, body)).status, 403, 'no signature');
  const { headers } = await s.signed(alice, body);
  assert.equal((await s.call(PATH, body, { 'X-Nostr-Transaction': headers['X-Nostr-Transaction'] })).status, 403, 'token without event');
  assert.equal((await s.call(PATH, body, { Authorization: headers.Authorization })).status, 403, 'event without token');
  assert.equal((await s.call(PATH, { ...body, acknowledgeBalance: true }, headers)).status, 403, 'body changed after signing');
  assert.equal((await s.call(PATH + '?x=1', body, headers)).status, 400, 'query string');
  assert.equal((await fetch(`http://127.0.0.1:${s.port}${PATH}`)).status, 405, 'GET');
  assert.deepEqual(pick(s.artefacts(alice)), intact);

  for (const bad of [{ confirm: 'yes', acknowledgeBalance: false }, { confirm: 'delete-account', acknowledgeBalance: 'true' },
    { confirm: 'delete-account' }, { confirm: 'delete-account', acknowledgeBalance: false, pubkey: alice.pubkey }]) {
    const signed = await s.signed(alice, bad);
    assert.equal((await s.call(PATH, bad, signed.headers)).status, 400, JSON.stringify(bad));
  }
  assert.deepEqual(pick(s.artefacts(alice)), intact);

  const preflight = await fetch(`http://127.0.0.1:${s.port}${PATH}`, { method: 'OPTIONS', headers: {
    Origin: 'https://client.test', 'Access-Control-Request-Method': 'POST',
    'Access-Control-Request-Headers': 'authorization,x-nostr-transaction,content-type' } });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), 'https://client.test');
  assert.equal((await fetch(`http://127.0.0.1:${s.port}${PATH}`, { method: 'OPTIONS', headers: {
    Origin: 'https://evil.test', 'Access-Control-Request-Method': 'POST' } })).status, 403);
});

test('a signer can only ever reach their own account', async (t) => {
  const s = await setup(t);
  const { alice, mallory } = s.people;
  const body = { confirm: 'delete-account', acknowledgeBalance: true };

  // Mallory signs for herself: she has no account, and nothing names Alice's.
  const res = await s.del(mallory, body);
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: 'not_found' });

  // Mallory takes Alice's signed request and swaps in her own pubkey: the
  // signature no longer verifies, and the challenge is not consumed.
  const { event, headers } = await s.signed(alice, body);
  const forged = { ...event, pubkey: mallory.pubkey };
  const forgedHeaders = { ...headers, Authorization: 'Nostr ' + Buffer.from(JSON.stringify(forged)).toString('base64') };
  assert.equal((await s.call(PATH, body, forgedHeaders)).status, 403);
  assert.deepEqual(pick(s.artefacts(alice)), intact);
  assert.equal(s.artefacts(alice).grants, 2);
  assert.equal(s.deletions().length, 0);
});

test('a mapping that reaches into another account is refused, not followed', async (t) => {
  const s = await setup(t);
  const { alice, dave, mallory } = s.people;
  const db = new DatabaseSync(s.provisionPath);
  // Mallory mapped onto Alice's LNbits account: two pubkeys, one account.
  db.prepare('INSERT INTO provisioned VALUES (?, ?, ?, 0)').run(mallory.pubkey, alice.user, alice.wallet);
  // Dave's mapping names Alice's wallet under Dave's own account.
  db.prepare('UPDATE provisioned SET wallet_id = ? WHERE pubkey = ?').run(alice.wallet, dave.pubkey);
  db.close();
  for (const who of [mallory, dave]) {
    const res = await s.del(who, { confirm: 'delete-account', acknowledgeBalance: true });
    assert.equal(res.status, 409);
    assert.deepEqual(await res.json(), { error: 'shared_account' });
  }
  assert.deepEqual(pick(s.artefacts(alice)), intact);
  assert.equal(s.artefacts(alice).grants, 2);
});

test('a balance blocks deletion until acknowledged, then is recorded as forfeited', async (t) => {
  const s = await setup(t);
  const { bob } = s.people;

  const refused = await s.del(bob);
  assert.equal(refused.status, 409);
  assert.deepEqual(await refused.json(), { error: 'balance_not_zero', balanceMsat: 5000 });
  assert.deepEqual(pick(s.artefacts(bob)), intact, 'a 409 deletes nothing');
  assert.equal(await s.lightningAddress(bob), 'bob@wallet.test');

  const accepted = await s.del(bob, { confirm: 'delete-account', acknowledgeBalance: true });
  assert.equal(accepted.status, 200);
  assert.deepEqual(await accepted.json(), { deleted: true });
  assert.deepEqual(s.artefacts(bob), gone);
  const [record] = s.deletions();
  assert.equal(record.forfeited_msat, 5000);
  assert.deepEqual(Object.keys(record).sort(), ['deleted_at', 'forfeited_msat', 'id'], 'no pubkey, user or wallet id');
});

test('an outgoing payment in flight blocks deletion even when acknowledged', async (t) => {
  const s = await setup(t);
  const { carol } = s.people;
  const res = await s.del(carol, { confirm: 'delete-account', acknowledgeBalance: true });
  assert.equal(res.status, 409);
  assert.deepEqual(await res.json(), { error: 'payment_pending' });
  assert.deepEqual(pick(s.artefacts(carol)), intact);
});

test('a zero-balance account is deleted completely, and a repeat finds nothing', async (t) => {
  const s = await setup(t);
  const { alice, bob } = s.people;
  assert.equal(await s.lightningAddress(alice), 'alice@wallet.test');

  const res = await s.del(alice);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { deleted: true });
  assert.deepEqual(s.artefacts(alice), gone);
  assert.equal(await s.lightningAddress(alice), null);
  assert.equal(s.deletions().length, 1);
  assert.equal(s.deletions()[0].forfeited_msat, 0);
  // Expired grants were listed and revoked too.
  assert.ok(s.seen.some(c => c.key === alice.adminkey && c.search === '?include_expired=true'));

  // Someone else's account is untouched.
  assert.deepEqual(pick(s.artefacts(bob)), intact);
  assert.equal(s.artefacts(bob).grants, 0);

  const again = await s.del(alice);
  assert.equal(again.status, 404);
  assert.deepEqual(await again.json(), { error: 'not_found' });
  assert.equal(s.deletions().length, 1, 'a repeat writes no second record');
});

test('grants are revoked even when the user had switched the provider off', async (t) => {
  const s = await setup(t);
  const { erin } = s.people;
  assert.equal(s.artefacts(erin).grants, 1);
  assert.equal((await s.del(erin)).status, 200);
  assert.deepEqual(s.artefacts(erin), gone);
});

test('a failure part-way deletes nothing past it, and a retry completes', async (t) => {
  const s = await setup(t);
  const { alice, dave } = s.people;

  // The provider fails to revoke Alice's grant: nothing else may be touched.
  s.failures.nwcDelete = 1;
  const failed = await s.del(alice);
  assert.equal(failed.status, 502);
  assert.deepEqual(await failed.json(), { error: 'upstream_unavailable' });
  assert.deepEqual(pick(s.artefacts(alice)), intact);
  assert.ok(s.artefacts(alice).grants > 0);
  assert.equal(s.deletions().length, 0);

  const retried = await s.del(alice);
  assert.equal(retried.status, 200);
  assert.deepEqual(s.artefacts(alice), gone);

  // A crash after the LNbits records went but before the mapping did.
  const db = new DatabaseSync(s.lnbitsPath);
  db.prepare('DELETE FROM wallets WHERE "user" = ?').run(dave.user);
  db.prepare('DELETE FROM accounts WHERE id = ?').run(dave.user);
  db.close();
  const resumed = await s.del(dave);
  assert.equal(resumed.status, 200);
  assert.deepEqual(s.artefacts(dave), gone);
  assert.equal(s.deletions().length, 2);
});

test('deletion has its own strict rate limit', async (t) => {
  const s = await setup(t);
  const { mallory } = s.people;
  const body = { confirm: 'delete-account', acknowledgeBalance: false };
  const statuses = [];
  for (let i = 0; i < 4; i++) {
    const { headers } = await s.signed(mallory, body, { forIp: `10.9.0.${i}` });
    statuses.push((await s.call(PATH, body, { ...headers, 'X-Forwarded-For': '10.9.9.9' })).status);
  }
  assert.deepEqual(statuses, [404, 404, 404, 429]);
});

test('no log line carries a full pubkey', async (t) => {
  const s = await setup(t);
  const { alice, bob, mallory } = s.people;
  await s.del(alice);
  await s.del(bob);
  await s.del(mallory);
  s.failures.nwcDelete = 1;
  await s.del(s.people.erin);
  const logs = s.output.join('');
  assert.match(logs, /\[delete-account\]/);
  for (const p of Object.values(s.people)) {
    assert.ok(!logs.includes(p.pubkey), `${p.name}'s pubkey was logged`);
    assert.ok(!logs.includes(p.user) && !logs.includes(p.wallet), `${p.name}'s LNbits ids were logged`);
  }
});

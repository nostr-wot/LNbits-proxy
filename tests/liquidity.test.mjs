// Liquidity monitoring: inbound floor, LSP splice-out detection, liquidity
// purchases and fees charged to deposits. The scenarios replay the shape of the 2026-10-07
// incident against mocked phoenixd and LNbits.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { decide } from '../monitor/alert-policy.mjs';
import {
  LIQUIDITY_DEFAULTS, detectCapacityDrops, evaluateInbound, liquidityConfig,
  openLnbitsReader, phoenixdClient, readPhoenixPassword, runLiquidity,
} from '../monitor/liquidity.mjs';

const MONITOR = resolve(import.meta.dirname, '../monitor/monitor.mjs');
const T0 = Date.parse('2026-10-07T12:00:00Z');
const MIN = 60_000;
const HOUR = 60 * MIN;
const config = { ...LIQUIDITY_DEFAULTS };

const CHANNEL = 'c0ffee'.repeat(10) + 'abcd';           // 64 hex
const WALLET = '5f3a9c0e7b2d4e1f8a6c3b9d0e2f4a7c';      // 32 hex
const HASH = 'ab'.repeat(32);

const channel = (over = {}) => ({
  state: 'Normal', channelId: CHANNEL, balanceSat: 30_000,
  inboundLiquiditySat: 2_030_000, capacitySat: 2_064_000, fundingTxId: 'f'.repeat(64), ...over,
});
const info = (...channels) => ({ nodeId: '02' + '11'.repeat(32), channels });

// The purchase phoenixd made on 2026-10-07: 21,476 sat, reported in msat.
const purchase = (over = {}) => ({
  type: 'outgoing_payment', subType: 'auto_liquidity', paymentId: '6f1c2d3e-0000-4000-8000-000000000001',
  paymentHash: null, preimage: null, txId: 'e'.repeat(64), isPaid: true, sent: 21_476,
  fees: 21_476_000, invoice: null, createdAt: T0 - 2 * MIN, completedAt: T0 - MIN, ...over,
});
// The LNbits row for the deposit it was charged to: msat amounts, seconds.
const depositRow = (over = {}) => ({
  checking_id: HASH, payment_hash: HASH, wallet_id: WALLET,
  amount: 100_000_000, fee: 21_476_000, ts: Math.floor((T0 - MIN) / 1000), ...over,
});

function lnbitsMock({ deposits = [], largest = 0, fail = null } = {}) {
  return async () => {
    if (fail) throw new Error(fail);
    return {
      largestDepositSat: () => largest,
      chargedDeposits: sinceSec => deposits.filter(d => d.ts >= sinceSec),
      close() {},
    };
  };
}
const phoenixdMock = (payments = []) => ({ listOutgoing: async (from, to) => payments.filter(p => p.createdAt >= from && p.createdAt <= to) });

async function run({ getinfo = info(channel()), payments = [], lnbits = lnbitsMock(), state, now = T0, cfg = config } = {}) {
  return runLiquidity({ info: getinfo, phoenixd: getinfo ? phoenixdMock(payments) : null, openLnbits: lnbits, state, now, config: cfg });
}
const check = (r, id) => r.checks.find(c => c.id === id);

// ── Inbound threshold ──────────────────────────────────────────────────────

test('inbound liquidity below the floor fails the inbound check', async () => {
  // What was left after the LSP splice-out: ~40k inbound.
  const r = await run({ getinfo: info(channel({ capacitySat: 69_775, inboundLiquiditySat: 40_000 })) });
  const c = check(r, 'liquidity_inbound');
  assert.equal(c.ok, false);
  assert.match(c.msg, /inbound liquidity 40,000 sat is below 200,000 sat \(LIQUIDITY_MIN_INBOUND_SAT\)/);
  assert.equal(c.reminderMs, 12 * HOUR);
});

test('healthy inbound liquidity passes', async () => {
  const c = check(await run(), 'liquidity_inbound');
  assert.equal(c.ok, true);
  assert.match(c.msg, /^inbound 2,030,000 sat, capacity 2,064,000 sat, balance 30,000 sat, threshold 200,000 sat$/);
});

test('the threshold rises to a multiple of the largest recent deposit', async () => {
  const getinfo = info(channel({ inboundLiquiditySat: 250_000 }));
  const r = await run({ getinfo, lnbits: lnbitsMock({ largest: 150_000 }) });
  const c = check(r, 'liquidity_inbound');
  assert.equal(c.ok, false);
  assert.match(c.msg, /below 300,000 sat \(2x the largest deposit in 30 days \(150,000 sat\)\)/);
  // A multiple of 0 disables the deposit-based threshold.
  const off = await run({ getinfo, lnbits: lnbitsMock({ largest: 150_000 }), cfg: { ...config, depositMultiple: 0 } });
  assert.equal(check(off, 'liquidity_inbound').ok, true);
});

test('no channel, or a channel that is not Normal, fails the inbound check', () => {
  const none = evaluateInbound(info(), { ...config });
  assert.equal(none.ok, false);
  assert.match(none.msg, /no channel at all/);

  const offline = evaluateInbound(info(channel(), { state: 'Offline' }), { ...config });
  assert.equal(offline.ok, false);
  assert.match(offline.msg, /channel unknown is Offline/);

  const closing = evaluateInbound(info(channel({ state: 'Closing' })), { ...config });
  assert.match(closing.msg, new RegExp(`channel ${CHANNEL.slice(0, 16)} is Closing`));
  assert.match(closing.msg, /inbound liquidity 0 sat/, 'a Closing channel cannot receive');
});

test('phoenixd unreachable leaves the inbound check undecided', async () => {
  const r = await run({ getinfo: null });
  assert.equal(check(r, 'liquidity_inbound').ok, null);
  assert.equal(check(r, 'liquidity_audit').ok, true, 'the Phoenixd Node check owns that failure');
  assert.equal(r.state.purchasesSinceMs, undefined, 'purchases are re-read once phoenixd is back');
});

// ── Capacity drop (LSP splice-out) ─────────────────────────────────────────

test('a capacity drop between runs alerts with the amount and a truncated channel id', async () => {
  const first = await run();
  assert.deepEqual(first.emails, [], 'the first run only records a baseline');
  assert.equal(first.state.channels[CHANNEL], 2_064_000);

  // 2026-09-30: SpliceInit fundingContribution=-1994225, capacity 69,775.
  const second = await run({
    getinfo: info(channel({ capacitySat: 69_775, inboundLiquiditySat: 40_000 })),
    state: first.state, now: T0 + 5 * MIN,
  });
  assert.equal(second.emails.length, 1);
  const [mail] = second.emails;
  assert.equal(mail.subject, 'ALERT: channel capacity dropped by 1,994,225 sat (LSP splice-out?)');
  assert.match(mail.body, new RegExp(`channel ${CHANNEL.slice(0, 16)}: 2,064,000 -> 69,775 sat \\(dropped 1,994,225 sat\\)`));
  assert.ok(!mail.body.includes(CHANNEL), 'full channel id must not be in the mail');
  assert.match(mail.body, /inbound liquidity 40,000 sat is below 200,000 sat/);

  // The new capacity is the baseline now: no repeat.
  const third = await run({ getinfo: info(channel({ capacitySat: 69_775, inboundLiquiditySat: 40_000 })), state: second.state, now: T0 + 10 * MIN });
  assert.deepEqual(third.emails, []);
});

test('small capacity changes and channels without an id do not alert', () => {
  const prev = { [CHANNEL]: 2_064_000 };
  assert.deepEqual(detectCapacityDrops(info(channel({ capacitySat: 2_000_000 })), prev, config).drops, []);
  // After a restart phoenixd lists the channel as Offline with no id or capacity.
  const offline = detectCapacityDrops(info({ state: 'Offline' }), prev, config);
  assert.deepEqual(offline.drops, []);
  assert.equal(offline.channels[CHANNEL], 2_064_000, 'the previous capacity is carried forward');
  // A channel that is really gone is a drop to zero.
  const gone = detectCapacityDrops(info(), prev, config);
  assert.equal(gone.drops[0].dropSat, 2_064_000);
  assert.equal(gone.drops[0].vanished, true);
});

// ── Liquidity purchases ────────────────────────────────────────────────────

test('a new auto_liquidity purchase alerts with its fee and the deposit it was charged to', async () => {
  const r = await run({
    payments: [purchase(), { ...purchase(), subType: 'lightning', paymentId: 'other', fees: 1000 }],
    lnbits: lnbitsMock({ deposits: [depositRow()] }),
  });
  assert.equal(r.emails.length, 1, 'one mail: the deposit is named in the purchase alert, not twice');
  const [mail] = r.emails;
  assert.equal(mail.subject, 'ALERT: phoenixd bought inbound liquidity (automatic, fee 21,476 sat)');
  assert.match(mail.body, /Payment id: 6f1c2d3e-0000-4000-8000-000000000001/);
  assert.match(mail.body, /Refund these users/);
  assert.match(mail.body, new RegExp(
    `wallet ${WALLET.slice(0, 12)}, invoice 100,000 sat, fee 21,476 sat, credited 78,524 sat, ` +
    `settled 2026-10-07T11:59:00.000Z, payment hash ${HASH.slice(0, 16)}`));
  assert.ok(!mail.body.includes(WALLET), 'full wallet id must not be in the mail');
  assert.ok(!mail.body.includes(HASH), 'full payment hash must not be in the mail');
  assert.ok(!mail.body.includes('e'.repeat(64)), 'full txid must not be in the mail');

  // Next run: the same purchase and deposit are not reported again.
  const again = await run({ payments: [purchase()], lnbits: lnbitsMock({ deposits: [depositRow()] }), state: r.state, now: T0 + 5 * MIN });
  assert.deepEqual(again.emails, []);
});

test('a purchase with no charged deposit says so', async () => {
  const r = await run({ payments: [purchase()] });
  assert.match(r.emails[0].body, /No LNbits deposit carried a fee within 30 minutes/);
  const manual = await run({ payments: [purchase({ subType: 'manual_liquidity', paymentId: 'm1' })] });
  assert.equal(manual.emails[0].subject, 'NOTICE: phoenixd bought inbound liquidity (manual, fee 21,476 sat)');
});

test('deposits outside the match window are not attributed to a purchase', async () => {
  const old = depositRow({ checking_id: 'cd'.repeat(32), payment_hash: 'cd'.repeat(32), ts: Math.floor((T0 - 3 * HOUR) / 1000) });
  const r = await run({ payments: [purchase()], lnbits: lnbitsMock({ deposits: [old] }) });
  assert.equal(r.emails.length, 2);
  assert.match(r.emails[0].body, /No LNbits deposit carried a fee/);
  assert.match(r.emails[1].subject, /user charged a node fee/);
});

test('purchases older than the first-run lookback are ignored', async () => {
  const r = await run({ payments: [purchase({ createdAt: T0 - 72 * HOUR, completedAt: T0 - 72 * HOUR })] });
  assert.deepEqual(r.emails, []);
  assert.equal(r.state.purchasesSinceMs, T0);
});

// ── Fees charged to deposits ───────────────────────────────────────────────

test('an incoming payment with a fee alerts as a user charged a node fee, once', async () => {
  const r = await run({ lnbits: lnbitsMock({ deposits: [depositRow()] }) });
  assert.equal(r.emails.length, 1);
  assert.equal(r.emails[0].subject, 'ALERT: user charged a node fee on a deposit (21,476 sat)');
  assert.match(r.emails[0].body, new RegExp(`wallet ${WALLET.slice(0, 12)}, invoice 100,000 sat, fee 21,476 sat, credited 78,524 sat`));
  assert.ok(!r.emails[0].body.includes(WALLET));

  const again = await run({ lnbits: lnbitsMock({ deposits: [depositRow()] }), state: r.state, now: T0 + 5 * MIN });
  assert.deepEqual(again.emails, []);

  // A later one is reported on its own.
  const second = depositRow({ checking_id: 'ef'.repeat(32), payment_hash: 'ef'.repeat(32), fee: 1_000_000, ts: Math.floor((T0 + 6 * MIN) / 1000) });
  const later = await run({ lnbits: lnbitsMock({ deposits: [depositRow(), second] }), state: again.state, now: T0 + 10 * MIN });
  assert.equal(later.emails.length, 1);
  assert.equal(later.emails[0].subject, 'ALERT: user charged a node fee on a deposit (1,000 sat)');
});

test('an unreadable LNbits database fails the audit check but not the inbound check', async () => {
  const r = await run({ lnbits: lnbitsMock({ fail: 'database not found: /nope' }) });
  assert.equal(check(r, 'liquidity_inbound').ok, true);
  const audit = check(r, 'liquidity_audit');
  assert.equal(audit.ok, false);
  assert.match(audit.msg, /LNbits database: database not found/);
  assert.equal(r.state.depositsSinceMs, undefined, 'deposits are re-read once the database is back');
});

// ── Alert policy: dedupe, reminders, recovery ──────────────────────────────

test('persistent low liquidity alerts once, reminds at the liquidity interval, and recovers', async () => {
  const low = info(channel({ capacitySat: 69_775, inboundLiquiditySat: 40_000 }));
  const sent = [];
  let policy, tracking;
  const step = 5 * MIN;
  const tick = async (getinfo, i) => {
    const r = await run({ getinfo, state: tracking, now: T0 + i * step });
    tracking = r.state;
    const c = check(r, 'liquidity_inbound');
    const d = decide(policy, c.ok, T0 + i * step, { alertAfter: 2, reminderMs: c.reminderMs });
    policy = d.state;
    if (d.email) sent.push(d.email.kind);
  };
  let i = 0;
  for (; i < 12 * 12 + 2; i++) await tick(low, i);      // a little over 12 hours low
  await tick(info(channel()), i);                        // liquidity bought
  assert.deepEqual(sent, ['alert', 'reminder', 'recovered']);
});

// ── Configuration ──────────────────────────────────────────────────────────

test('configuration reads the environment and falls back to defaults', () => {
  assert.deepEqual(liquidityConfig({}), { ...LIQUIDITY_DEFAULTS });
  const c = liquidityConfig({
    LIQUIDITY_MIN_INBOUND_SAT: '500000', LIQUIDITY_DEPOSIT_MULTIPLE: '3', LIQUIDITY_CAPACITY_DROP_SAT: 'junk',
    LIQUIDITY_REMINDER_HOURS: '6', LIQUIDITY_CHECKS: 'off',
  });
  assert.equal(c.minInboundSat, 500_000);
  assert.equal(c.depositMultiple, 3);
  assert.equal(c.capacityDropSat, LIQUIDITY_DEFAULTS.capacityDropSat, 'invalid values fall back');
  assert.equal(c.reminderHours, 6);
  assert.equal(c.enabled, false);
});

test('the limited-access phoenixd password is preferred', t => {
  const dir = mkdtempSync(join(tmpdir(), 'phoenix-conf-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const conf = join(dir, 'phoenix.conf');
  writeFileSync(conf, 'http-password=fullpw\nhttp-password-limited-access=limitedpw\n');
  assert.equal(readPhoenixPassword(conf), 'limitedpw');
  writeFileSync(conf, 'auto-liquidity=2m\nhttp-password=fullpw\n');
  assert.equal(readPhoenixPassword(conf), 'fullpw');
  writeFileSync(conf, 'auto-liquidity=2m\n');
  assert.throws(() => readPhoenixPassword(conf), /http-password not found/);
});

// ── Adapters, against a mock phoenixd and a real SQLite file ───────────────

async function mockPhoenixd(t, outgoing, password = 'limitedpw') {
  const requests = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    requests.push(url);
    if (req.headers.authorization !== 'Basic ' + Buffer.from(':' + password).toString('base64')) {
      res.writeHead(401); return res.end('Invalid authentication');
    }
    let body;
    if (url.pathname === '/getinfo') body = info(channel());
    else if (url.pathname === '/payments/outgoing') {
      const offset = Number(url.searchParams.get('offset')), limit = Number(url.searchParams.get('limit'));
      body = outgoing.slice(offset, offset + limit);
    } else { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  return { url: `http://127.0.0.1:${server.address().port}`, requests };
}

test('phoenixd client pages /payments/outgoing with all=true and millisecond bounds', async t => {
  const payments = Array.from({ length: 5 }, (_, i) => purchase({ paymentId: `p${i}` }));
  const { url, requests } = await mockPhoenixd(t, payments);
  const client = phoenixdClient({ url, password: 'limitedpw', pageSize: 2 });
  const got = await client.listOutgoing(T0 - HOUR, T0);
  assert.deepEqual(got.map(p => p.paymentId), ['p0', 'p1', 'p2', 'p3', 'p4']);
  assert.equal(requests.length, 3);
  const q = requests[0].searchParams;
  assert.equal(q.get('from'), String(T0 - HOUR));
  assert.equal(q.get('to'), String(T0));
  assert.equal(q.get('all'), 'true');
  assert.deepEqual(requests.map(r => r.searchParams.get('offset')), ['0', '2', '4']);
  assert.equal((await client.getinfo()).channels[0].capacitySat, 2_064_000);

  const wrong = phoenixdClient({ url, password: 'nope' });
  await assert.rejects(wrong.getinfo(), /HTTP 401 from \/getinfo/);
});

function lnbitsDb(t) {
  const dir = mkdtempSync(join(tmpdir(), 'lnbits-liquidity-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'database.sqlite3');
  const db = new DatabaseSync(path);
  db.exec(`CREATE TABLE apipayments (checking_id TEXT PRIMARY KEY, payment_hash TEXT, wallet_id TEXT,
    amount INTEGER, fee INTEGER, status TEXT, memo TEXT, created_at TIMESTAMP, updated_at TIMESTAMP)`);
  const add = db.prepare('INSERT INTO apipayments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
  const s = ms => Math.floor(ms / 1000);
  add.run(HASH, HASH, WALLET, 100_000_000, 21_476_000, 'success', 'zap', s(T0 - 10 * MIN), s(T0 - MIN));
  add.run('11'.repeat(32), '11'.repeat(32), WALLET, 300_000_000, 0, 'success', '', s(T0 - 2 * HOUR), s(T0 - 2 * HOUR));
  add.run('internal_x', '22'.repeat(32), WALLET, 900_000_000, 0, 'success', '', s(T0 - HOUR), s(T0 - HOUR));
  add.run('33'.repeat(32), '33'.repeat(32), WALLET, 5_000_000, 1_000, 'pending', '', s(T0), null);
  add.run('44'.repeat(32), '44'.repeat(32), WALLET, -5_000_000, -2_000, 'success', '', s(T0), s(T0));
  add.run('55'.repeat(32), '55'.repeat(32), WALLET, 7_000_000, 3_000_000, 'success', '', s(T0 - 90 * 86_400_000), null);
  db.close();
  return path;
}

test('LNbits reader finds settled deposits with a fee and the largest external deposit', async t => {
  const path = lnbitsDb(t);
  const reader = await openLnbitsReader(path);
  try {
    const rows = reader.chargedDeposits(Math.floor((T0 - 48 * HOUR) / 1000));
    assert.deepEqual(rows.map(r => r.checking_id), [HASH], 'only settled incoming rows with a fee, in the window');
    assert.equal(rows[0].amount, 100_000_000);
    assert.equal(reader.largestDepositSat(Math.floor((T0 - 30 * 86_400_000) / 1000)), 300_000, 'internal transfers excluded');
  } finally { reader.close(); }
  await assert.rejects(openLnbitsReader(join(path, '..', 'missing.sqlite3')), /database not found/);
});

test('the whole incident end to end through the real adapters', async t => {
  const { url } = await mockPhoenixd(t, [purchase()]);
  const r = await runLiquidity({
    info: await phoenixdClient({ url, password: 'limitedpw' }).getinfo(),
    phoenixd: phoenixdClient({ url, password: 'limitedpw' }),
    openLnbits: () => openLnbitsReader(lnbitsDb(t)),
    state: {}, now: T0, config,
  });
  assert.equal(check(r, 'liquidity_audit').ok, true, check(r, 'liquidity_audit').msg);
  assert.equal(r.emails.length, 1);
  assert.match(r.emails[0].body, /invoice 100,000 sat, fee 21,476 sat, credited 78,524 sat/);
});

// ── monitor.mjs wiring ─────────────────────────────────────────────────────

test('monitor.mjs mails liquidity events and retries them when the mail provider fails', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'monitor-liquidity-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const conf = join(dir, 'phoenix.conf');
  writeFileSync(conf, 'http-password=fullpw\nhttp-password-limited-access=limitedpw\n');
  const { url: phoenixUrl } = await mockPhoenixd(t, [purchase({ createdAt: Date.now() - 2 * MIN, completedAt: Date.now() - MIN })]);
  const dbPath = lnbitsDb(t);
  // Move the charged deposit to "now" so it falls inside the real clock's window.
  const db = new DatabaseSync(dbPath);
  db.prepare('UPDATE apipayments SET updated_at = ? WHERE checking_id = ?').run(Math.floor(Date.now() / 1000) - 60, HASH);
  db.close();

  let accept = false;
  const mails = [];
  const resend = createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    mails.push({ ...JSON.parse(raw), accepted: accept });
    res.writeHead(accept ? 200 : 500); res.end('{}');
  });
  resend.listen(0, '127.0.0.1');
  await once(resend, 'listening');
  t.after(() => resend.close());

  const stateFile = join(dir, 'state.json');
  const env = {
    PATH: process.env.PATH, RESEND_API_KEY: 'test', RESEND_URL: `http://127.0.0.1:${resend.address().port}/emails`,
    STATE_FILE: stateFile, LOG_FILE: join(dir, 'monitor.log'), PHOENIX_CONF: conf, PHOENIX_URL: phoenixUrl,
    LNBITS_DB_PATH: dbPath, MONITOR_BASE_URL: 'http://127.0.0.1:9', MONITOR_LNURL_NAMES: 'x',
    MONITOR_PYTHON: '/usr/bin/false', MONITOR_ALERT_AFTER: '50',
  };
  const runMonitor = async () => {
    const child = spawn(process.execPath, [MONITOR], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { out += d; });
    const [code] = await once(child, 'exit');
    assert.equal(code, 0, out);
    return out;
  };

  await runMonitor();
  const purchaseMails = () => mails.filter(m => /bought inbound liquidity/.test(m.subject));
  assert.equal(purchaseMails().length, 1, 'the event was attempted');
  assert.equal(JSON.parse(readFileSync(stateFile, 'utf8')).liquidity_tracking, undefined, 'not committed while mail failed');

  accept = true;
  await runMonitor();
  assert.equal(purchaseMails().length, 2, 'retried on the next run');
  assert.match(purchaseMails()[1].text, /invoice 100,000 sat, fee 21,476 sat/);
  assert.ok(!purchaseMails()[1].text.includes(WALLET));
  const state = JSON.parse(readFileSync(stateFile, 'utf8'));
  assert.equal(state.liquidity_tracking.seenPurchases.length, 1);
  assert.equal(state.liquidity_inbound.ok, true);

  await runMonitor();
  assert.equal(purchaseMails().length, 2, 'not sent a third time');
  const log = readFileSync(join(dir, 'monitor.log'), 'utf8');
  assert.ok(!log.includes('limitedpw') && !log.includes('fullpw'), 'no password in the log');
  assert.ok(!log.includes(WALLET), 'no full wallet id in the log');
});

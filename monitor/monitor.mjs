#!/usr/bin/env node

// /srv/zaps-monitor/monitor.mjs
// Cron health check for zaps.nostr-wot.com Lightning stack
// Zero npm dependencies — uses Node built-ins only

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { decide } from './alert-policy.mjs';
import {
  liquidityConfig, openLnbitsReader, phoenixdClient, readPhoenixPassword, runLiquidity,
} from './liquidity.mjs';
import { readFileSync, writeFileSync, statSync, renameSync, appendFileSync } from 'node:fs';

// ── Config ──────────────────────────────────────────────────────────────────

const STATE_FILE     = process.env.STATE_FILE || '/srv/zaps-monitor/state.json';
const LOG_FILE       = process.env.LOG_FILE   || '/srv/zaps-monitor/monitor.log';
const MAX_LOG_BYTES  = 10 * 1024 * 1024; // 10 MB
const REMINDER_MS    = 60 * 60 * 1000;   // 60 min
// Consecutive failures required before alerting. Three of these checks go
// through the public edge, so a brief network hiccup used to fire three alerts
// at once and three recoveries five minutes later.
const ALERT_AFTER    = Math.max(1, Number(process.env.MONITOR_ALERT_AFTER || 2));
// Overridable so the alerting behaviour can be tested without sending mail.
const RESEND_URL     = process.env.RESEND_URL || 'https://api.resend.com/emails';
const TIMEOUT_MS     = 10_000;

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM     = process.env.EMAIL_FROM || 'Zaps Monitor <alarms@dandelionlabs.io>';
const EMAIL_TO       = process.env.EMAIL_TO   || 'leon@nostr-wot.com';
const PHOENIX_CONF   = process.env.PHOENIX_CONF || '/home/phoenixd/.phoenix/phoenix.conf';
const PHOENIX_URL    = process.env.PHOENIX_URL  || 'http://127.0.0.1:9740';
const LNBITS_DB_PATH = process.env.LNBITS_DB_PATH || '/home/lnbits/lnbits/data/database.sqlite3';
// Inbound liquidity, LSP splice-outs, liquidity purchases and fees charged to
// deposits. See monitor/liquidity.mjs and the LIQUIDITY_* variables in README.
const LIQUIDITY      = liquidityConfig(process.env);

// End-to-end check. It mints a real invoice on every run, so it needs its own
// address, a short expiry, and the cleanup helper to retire what it created.
const BASE_URL       = process.env.MONITOR_BASE_URL || 'https://zaps.nostr-wot.com';
const MONITOR_ADDRESS = process.env.MONITOR_ADDRESS || 'robert';
// Lightning Addresses to probe for reachability, comma separated.
const LNURL_NAMES    = (process.env.MONITOR_LNURL_NAMES || 'robert,leon')
  .split(',').map(n => n.trim()).filter(Boolean);
const INVOICE_EXPIRY = process.env.MONITOR_INVOICE_EXPIRY || '30';
const CLEANUP_BIN    = process.env.MONITOR_CLEANUP || '/srv/zaps-monitor/cleanup.py';
const PYTHON_BIN     = process.env.MONITOR_PYTHON || '/usr/bin/python3';

if (!RESEND_API_KEY) {
  console.error('RESEND_API_KEY env var is required');
  process.exit(1);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function loadState() {
  try { return JSON.parse(readFileSync(STATE_FILE, 'utf8')); }
  catch { return {}; }
}

function saveState(state) {
  const tmp = STATE_FILE + '.tmp';
  writeFileSync(tmp, JSON.stringify(state, null, 2));
  renameSync(tmp, STATE_FILE);
}

function rotateIfNeeded() {
  try {
    if (statSync(LOG_FILE).size > MAX_LOG_BYTES)
      renameSync(LOG_FILE, LOG_FILE + '.1');
  } catch {}
}

function log(entry) {
  rotateIfNeeded();
  appendFileSync(LOG_FILE, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n');
}

// The last /getinfo body this run read, shared with the liquidity checks so
// they do not query phoenixd a second time.
let phoenixdInfo = null;

function phoenixd() {
  return phoenixdClient({ url: PHOENIX_URL, password: readPhoenixPassword(PHOENIX_CONF), timeoutMs: TIMEOUT_MS });
}

async function f(url, opts = {}) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...opts, signal: ac.signal });
  } finally { clearTimeout(t); }
}

// ── Checks ──────────────────────────────────────────────────────────────────

async function checkLnbits() {
  const r = await f('http://127.0.0.1:5000/api/v1/health');
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return 'healthy';
}

async function checkProvision() {
  const r = await f('http://127.0.0.1:3003/api/v2/provision/challenge', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({url:`${BASE_URL}/api/v2/release-username`,method:'POST',payload:createHash('sha256').update('{}').digest('hex')}),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const d = await r.json();
  if (d.version !== 2 || !/^[0-9a-f]{64}$/.test(d.challenge) || !/^[0-9a-f]{64}$/.test(d.transactionToken)) throw new Error('invalid v2 challenge response');
  return 'v2 challenge OK';
}

async function checkLnurl(name) {
  const r = await f(`${BASE_URL}/.well-known/lnurlp/${name}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const d = await r.json();
  if (!d.callback) throw new Error('no callback in response');
  const host = new URL(d.callback).hostname;
  if (host === 'localhost' || host === '127.0.0.1')
    throw new Error(`callback points to ${host}`);
  return `callback → ${d.callback}`;
}

async function checkPhoenixd() {
  const d = await phoenixd().getinfo();
  phoenixdInfo = d;
  const channels = (d.channels || []).filter(c => c.state === 'Normal');
  if (channels.length === 0) throw new Error('no channels in Normal state');
  const bal = channels.reduce((sum, c) => sum + (c.balanceSat || 0), 0);
  return `${channels.length} channel(s), ${bal} sat`;
}

async function checkCallbackE2E() {
  // Step 1: get LNURL metadata
  const r = await f(`${BASE_URL}/.well-known/lnurlp/${MONITOR_ADDRESS}`);
  if (!r.ok) throw new Error(`LNURL fetch HTTP ${r.status}`);
  const d = await r.json();
  if (!d.callback) throw new Error('no callback URL');

  // Step 2: request a minimum-amount, short-lived invoice
  const amount = d.minSendable || 1000; // millisats
  const url = new URL(d.callback);
  url.searchParams.set('amount', String(amount));
  url.searchParams.set('expiry', INVOICE_EXPIRY);
  const ir = await f(url.toString());
  if (!ir.ok) throw new Error(`callback HTTP ${ir.status}`);
  const inv = await ir.json();
  if (!inv.pr) throw new Error('no payment request in response');
  if (!inv.pr.startsWith('lnbc')) throw new Error(`bad invoice prefix: ${inv.pr.slice(0, 8)}`);

  // Step 3: retire what we just minted. Without this the check leaves ~288
  // unpaid invoices a day in LNbits and the backend, and fills the monitored
  // account's payment history with invoices nobody will ever pay. cleanup.py
  // only retires after the backend confirms the invoice was not paid.
  const retired = spawnSync(PYTHON_BIN, [CLEANUP_BIN, '--retire-monitor'], {
    input: inv.pr, encoding: 'utf8', timeout: 30000,
  });
  if (retired.error || retired.status !== 0)
    throw new Error('invoice generated, but monitor retirement failed; retained for cleanup');
  const result = JSON.parse(retired.stdout);
  if (result.retired !== 1) throw new Error('monitor retirement not confirmed');
  return `invoice OK; ${INVOICE_EXPIRY}s expiry; retired locally`;
}

// ── Alerting ────────────────────────────────────────────────────────────────

// Returns whether the provider accepted the mail.
async function sendEmail(subject, body) {
  try {
    const r = await fetch(RESEND_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: EMAIL_FROM,
        to: [EMAIL_TO],
        subject,
        text: body,
      }),
    });
    if (!r.ok) console.error('email send failed:', await r.text());
    return r.ok;
  } catch (err) {
    console.error('email send error:', err.message);
    return false;
  }
}

// ── Main ────────────────────────────────────────────────────────────────────

const CHECKS = [
  { id: 'lnbits',       label: 'LNbits Health',       fn: checkLnbits },
  { id: 'provision',    label: 'Zaps Provision',       fn: checkProvision },
  ...LNURL_NAMES.map(name => (
    { id: `lnurl_${name}`, label: `LNURL ${name}`, fn: () => checkLnurl(name) }
  )),
  { id: 'phoenixd',     label: 'Phoenixd Node',        fn: checkPhoenixd },
  { id: 'callback_e2e', label: 'LNURL Callback E2E',   fn: checkCallbackE2E },
];

async function main() {
  const state = loadState();
  const now = Date.now();
  const results = [];

  for (const check of CHECKS) {
    let ok = false, msg = '';
    try   { msg = await check.fn(); ok = true; }
    catch (e) { msg = e.message; }
    results.push({ id: check.id, label: check.label, ok, msg });
  }

  // Liquidity: persistent conditions join the results below; one-off events
  // (splice-outs, purchases, fees charged to deposits) come back as mail.
  let liquidity = { checks: [], emails: [], state: state.liquidity_tracking };
  if (LIQUIDITY.enabled) {
    try {
      liquidity = await runLiquidity({
        info: phoenixdInfo,
        phoenixd: phoenixdInfo ? phoenixd() : null,
        openLnbits: () => openLnbitsReader(LNBITS_DB_PATH),
        state: state.liquidity_tracking,
        now,
        config: LIQUIDITY,
      });
    } catch (e) {
      // A bug here must not take the other checks' alerting down with it.
      liquidity.checks = [{ id: 'liquidity_audit', label: 'Liquidity Audit', ok: false, msg: `liquidity checks crashed: ${e.message}` }];
    }
    results.push(...liquidity.checks);
  }

  for (const r of results) {
    // ok === null: this run could not tell (its source was unreachable and has
    // its own check). Leave the state alone rather than count a pass or a failure.
    if (r.ok === null) continue;
    const { state: next, email } = decide(state[r.id], r.ok, now, {
      alertAfter: r.alertAfter ?? ALERT_AFTER, reminderMs: r.reminderMs ?? REMINDER_MS,
    });
    state[r.id] = next;
    const hint = r.hint ? `\n\n${r.hint}` : '';

    if (email?.kind === 'recovered') {
      await sendEmail(
        `RECOVERED: ${r.label}`,
        `${r.label} has recovered.\n\nDowntime: ~${email.minutes} minutes\nDetail: ${r.msg}\nTime: ${new Date().toISOString()}`
      );
    } else if (email?.kind === 'alert') {
      await sendEmail(
        `ALERT: ${r.label} failing`,
        `${r.label} is failing!\n\nError: ${r.msg}\nConsecutive failures: ${email.fails}\nTime: ${new Date().toISOString()}${hint}`
      );
    } else if (email?.kind === 'reminder') {
      await sendEmail(
        `STILL FAILING: ${r.label} (${email.minutes} min)`,
        `${r.label} is still failing.\n\nError: ${r.msg}\nDowntime: ~${email.minutes} minutes\nTime: ${new Date().toISOString()}${hint}`
      );
    }
  }

  // Event mail is deduped through the tracking state, so that state only moves
  // forward once every event mail was accepted. Otherwise the next run sends again.
  let eventsSent = true;
  for (const e of liquidity.emails) {
    if (!(await sendEmail(e.subject, `${e.body}\n\nTime: ${new Date().toISOString()}`))) eventsSent = false;
  }
  if (eventsSent) state.liquidity_tracking = liquidity.state;

  saveState(state);

  const mark = ok => (ok === null ? '?' : ok ? '✓' : '✗');
  const summary = results.map(r => `${mark(r.ok)} ${r.label}`).join(', ');
  const allOk = results.every(r => r.ok !== false);
  log({
    status: allOk ? 'OK' : 'FAIL',
    checks: results.map(({ id, ok, msg }) => ({ id, ok, msg })),
    ...(liquidity.emails.length ? { events: liquidity.emails.map(e => e.subject), eventsSent } : {}),
  });
  console.log(`[${new Date().toISOString()}] ${allOk ? 'ALL OK' : 'FAILURES'}: ${summary}`);
}

main().catch(err => {
  console.error('Monitor fatal:', err);
  process.exit(1);
});

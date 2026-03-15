#!/usr/bin/env node

// /srv/zaps-monitor/monitor.mjs
// Cron health check for zaps.nostr-wot.com Lightning stack
// Zero npm dependencies — uses Node built-ins only

import { readFileSync, writeFileSync, statSync, renameSync, appendFileSync } from 'node:fs';

// ── Config ──────────────────────────────────────────────────────────────────

const STATE_FILE     = process.env.STATE_FILE || '/srv/zaps-monitor/state.json';
const LOG_FILE       = process.env.LOG_FILE   || '/srv/zaps-monitor/monitor.log';
const MAX_LOG_BYTES  = 10 * 1024 * 1024; // 10 MB
const REMINDER_MS    = 60 * 60 * 1000;   // 60 min
const TIMEOUT_MS     = 10_000;

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM     = process.env.EMAIL_FROM || 'Zaps Monitor <alarms@dandelionlabs.io>';
const EMAIL_TO       = process.env.EMAIL_TO   || 'leon@nostr-wot.com';
const PHOENIX_CONF   = process.env.PHOENIX_CONF || '/home/phoenixd/.phoenix/phoenix.conf';

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

function getPhoenixdPassword() {
  const conf = readFileSync(PHOENIX_CONF, 'utf8');
  const m = conf.match(/^http-password=(\S+)/m);
  if (!m) throw new Error('http-password not found in phoenix.conf');
  return m[1];
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
  const r = await f('http://127.0.0.1:3003/api/provision/challenge');
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const d = await r.json();
  if (!d.challenge) throw new Error('no challenge in response');
  return `challenge OK (${d.challenge.slice(0, 8)}…)`;
}

async function checkLnurl(name) {
  const r = await f(`https://zaps.nostr-wot.com/.well-known/lnurlp/${name}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const d = await r.json();
  if (!d.callback) throw new Error('no callback in response');
  const host = new URL(d.callback).hostname;
  if (host === 'localhost' || host === '127.0.0.1')
    throw new Error(`callback points to ${host}`);
  return `callback → ${d.callback}`;
}

async function checkPhoenixd() {
  const pw = getPhoenixdPassword();
  const auth = 'Basic ' + Buffer.from(':' + pw).toString('base64');
  const r = await f('http://127.0.0.1:9740/getinfo', {
    headers: { Authorization: auth },
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const d = await r.json();
  const channels = (d.channels || []).filter(c => c.state === 'Normal');
  if (channels.length === 0) throw new Error('no channels in Normal state');
  const bal = channels.reduce((sum, c) => sum + (c.balanceSat || 0), 0);
  return `${channels.length} channel(s), ${bal} sat`;
}

async function checkCallbackE2E() {
  // Step 1: get LNURL metadata
  const r = await f('https://zaps.nostr-wot.com/.well-known/lnurlp/robert');
  if (!r.ok) throw new Error(`LNURL fetch HTTP ${r.status}`);
  const d = await r.json();
  if (!d.callback) throw new Error('no callback URL');

  // Step 2: request a minimum-amount invoice
  const amount = d.minSendable || 1000; // millisats
  const url = new URL(d.callback);
  url.searchParams.set('amount', String(amount));
  const ir = await f(url.toString());
  if (!ir.ok) throw new Error(`callback HTTP ${ir.status}`);
  const inv = await ir.json();
  if (!inv.pr) throw new Error('no payment request in response');
  if (!inv.pr.startsWith('lnbc')) throw new Error(`bad invoice prefix: ${inv.pr.slice(0, 8)}`);
  return `invoice OK (${inv.pr.slice(0, 20)}…)`;
}

// ── Alerting ────────────────────────────────────────────────────────────────

async function sendEmail(subject, body) {
  try {
    const r = await fetch('https://api.resend.com/emails', {
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
  } catch (err) {
    console.error('email send error:', err.message);
  }
}

// ── Main ────────────────────────────────────────────────────────────────────

const CHECKS = [
  { id: 'lnbits',       label: 'LNbits Health',       fn: checkLnbits },
  { id: 'provision',    label: 'Zaps Provision',       fn: checkProvision },
  { id: 'lnurl_robert', label: 'LNURL robert',        fn: () => checkLnurl('robert') },
  { id: 'lnurl_leon',   label: 'LNURL leon',          fn: () => checkLnurl('leon') },
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

  for (const r of results) {
    const prev = state[r.id] || { ok: true, since: null, lastReminder: null };

    if (r.ok && !prev.ok) {
      // ── Recovery ──
      const mins = prev.since ? Math.round((now - prev.since) / 60000) : '?';
      await sendEmail(
        `RECOVERED: ${r.label}`,
        `${r.label} has recovered.\n\nDowntime: ~${mins} minutes\nDetail: ${r.msg}\nTime: ${new Date().toISOString()}`
      );
      state[r.id] = { ok: true, since: null, lastReminder: null };

    } else if (!r.ok && prev.ok) {
      // ── New failure ──
      await sendEmail(
        `ALERT: ${r.label} failing`,
        `${r.label} is failing!\n\nError: ${r.msg}\nTime: ${new Date().toISOString()}`
      );
      state[r.id] = { ok: false, since: now, lastReminder: now };

    } else if (!r.ok && !prev.ok) {
      // ── Still failing — remind every 60 min ──
      if (now - (prev.lastReminder || 0) >= REMINDER_MS) {
        const mins = prev.since ? Math.round((now - prev.since) / 60000) : '?';
        await sendEmail(
          `STILL FAILING: ${r.label} (${mins} min)`,
          `${r.label} is still failing.\n\nError: ${r.msg}\nDowntime: ~${mins} minutes\nTime: ${new Date().toISOString()}`
        );
        state[r.id] = { ...prev, lastReminder: now };
      } else {
        state[r.id] = prev;
      }

    } else {
      // ── Still OK ──
      state[r.id] = { ok: true, since: null, lastReminder: null };
    }
  }

  saveState(state);

  const summary = results.map(r => `${r.ok ? '✓' : '✗'} ${r.label}`).join(', ');
  const allOk = results.every(r => r.ok);
  log({ status: allOk ? 'OK' : 'FAIL', checks: results.map(({ id, ok, msg }) => ({ id, ok, msg })) });
  console.log(`[${new Date().toISOString()}] ${allOk ? 'ALL OK' : 'FAILURES'}: ${summary}`);
}

main().catch(err => {
  console.error('Monitor fatal:', err);
  process.exit(1);
});

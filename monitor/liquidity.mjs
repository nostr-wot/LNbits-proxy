/**
 * Inbound liquidity and node-fee monitoring for phoenixd behind LNbits.
 *
 * Why this exists. phoenixd buys inbound liquidity on the fly when a deposit does
 * not fit the channel, and takes the fee out of that deposit. Its absolute fee cap
 * only covers the mining fee (phoenixd hardcodes
 * considerOnlyMiningFeeForAbsoluteFeeCheck=true), so the LSP service fee is
 * uncapped. On 2026-09-30 the LSP spliced its unused leased liquidity back out of
 * the channel and nobody noticed. A week later one user's sub-100k sat deposit paid
 * a 21,476 sat liquidity fee. The operator should hear about every step of that,
 * before a user pays for it:
 *
 *   - inbound liquidity below a floor, or below a multiple of recent deposits
 *   - no channel, or a channel that is not Normal
 *   - a channel whose capacity dropped between runs (the LSP splice-out signature)
 *   - every liquidity purchase phoenixd made, with the deposit it was charged to
 *   - every LNbits deposit that was credited less than it received
 *
 * Kept out of monitor.mjs, which runs on import, so the decisions are testable
 * with mocked phoenixd and LNbits. runLiquidity() is the whole flow; the adapters
 * below it are the only code that talks to phoenixd or reads the LNbits database.
 *
 * Never put keys, passwords or full pubkeys in an alert or a log line. Channel ids,
 * wallet ids and payment hashes are truncated as well, so an alert identifies a row
 * for the operator without carrying the whole identifier around in mail.
 */

import { existsSync, readFileSync } from 'node:fs';

export const LIQUIDITY_DEFAULTS = Object.freeze({
  enabled: true,
  minInboundSat: 200_000,
  depositMultiple: 2,
  depositWindowDays: 30,
  capacityDropSat: 100_000,
  reminderHours: 12,
  lookbackHours: 48,
  matchWindowMinutes: 30,
});

// How far back each run re-reads, on top of the last successful run. Covers a
// purchase or settlement that is recorded a little after its own timestamp.
const OVERLAP_MS = 60 * 60 * 1000;
// Remembered event ids. Enough to dedupe the overlap; the oldest fall off.
const SEEN_MAX = 500;
const ID_PREFIX = 16;
const WALLET_PREFIX = 12;
const PURCHASE_TYPES = { auto_liquidity: 'automatic', manual_liquidity: 'manual' };

export const RUNBOOK_HINT = 'See RUNBOOK.md, "Inbound liquidity", for buying liquidity deliberately and refunding users.';

// ── Configuration ───────────────────────────────────────────────────────────

function num(value, fallback) {
  if (value === undefined || value === null || String(value).trim() === '') return fallback;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

export function liquidityConfig(env = process.env) {
  const d = LIQUIDITY_DEFAULTS;
  return {
    enabled: !/^(0|false|off|no)$/i.test(String(env.LIQUIDITY_CHECKS ?? '1').trim()),
    minInboundSat: num(env.LIQUIDITY_MIN_INBOUND_SAT, d.minInboundSat),
    depositMultiple: num(env.LIQUIDITY_DEPOSIT_MULTIPLE, d.depositMultiple),
    depositWindowDays: num(env.LIQUIDITY_DEPOSIT_WINDOW_DAYS, d.depositWindowDays),
    capacityDropSat: num(env.LIQUIDITY_CAPACITY_DROP_SAT, d.capacityDropSat),
    reminderHours: num(env.LIQUIDITY_REMINDER_HOURS, d.reminderHours),
    lookbackHours: num(env.LIQUIDITY_LOOKBACK_HOURS, d.lookbackHours),
    matchWindowMinutes: num(env.LIQUIDITY_MATCH_WINDOW_MINUTES, d.matchWindowMinutes),
  };
}

// ── Formatting ──────────────────────────────────────────────────────────────

export function short(id, n = ID_PREFIX) {
  return id ? String(id).slice(0, n) : 'unknown';
}

export function fmt(n) {
  return Math.round(Number(n) || 0).toLocaleString('en-US');
}

const msatToSat = msat => Math.floor(Math.abs(Number(msat) || 0) / 1000);
const iso = ms => (Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : 'unknown');

// ── Pure decisions ──────────────────────────────────────────────────────────

/**
 * Sum the channels phoenixd reports and decide whether inbound liquidity is
 * healthy. Only Normal channels count towards inbound: an Offline or Closing
 * channel cannot receive.
 */
export function evaluateInbound(info, { minInboundSat, depositMultiple, depositWindowDays, largestDepositSat = 0 }) {
  const channels = Array.isArray(info?.channels) ? info.channels : [];
  const normal = channels.filter(c => c.state === 'Normal');
  const total = key => normal.reduce((s, c) => s + (Number(c[key]) || 0), 0);
  const inboundSat = total('inboundLiquiditySat');
  const capacitySat = total('capacitySat');
  const balanceSat = total('balanceSat');

  const depositFloor = depositMultiple > 0 ? Math.ceil(depositMultiple * largestDepositSat) : 0;
  const thresholdSat = Math.max(minInboundSat, depositFloor);
  const basis = depositFloor > minInboundSat
    ? `${depositMultiple}x the largest deposit in ${depositWindowDays} days (${fmt(largestDepositSat)} sat)`
    : 'LIQUIDITY_MIN_INBOUND_SAT';

  const problems = [];
  if (channels.length === 0) problems.push('no channel at all');
  for (const c of channels) {
    if (c.state !== 'Normal') problems.push(`channel ${short(c.channelId)} is ${c.state || 'in an unknown state'}`);
  }
  if (channels.length > 0 && inboundSat < thresholdSat) {
    problems.push(`inbound liquidity ${fmt(inboundSat)} sat is below ${fmt(thresholdSat)} sat (${basis})`);
  }

  const totals = `inbound ${fmt(inboundSat)} sat, capacity ${fmt(capacitySat)} sat, balance ${fmt(balanceSat)} sat, threshold ${fmt(thresholdSat)} sat`;
  return {
    ok: problems.length === 0,
    msg: problems.length ? `${problems.join('; ')} [${totals}]` : totals,
    inboundSat, capacitySat, balanceSat, thresholdSat,
  };
}

/**
 * Compare each channel's capacity with the previous run. A drop is what an LSP
 * reclaiming leased liquidity with a splice-out looks like; it is not a payment,
 * so nothing else in phoenixd's API records it.
 *
 * A channel phoenixd reports without an id or capacity (Offline or Syncing right
 * after a restart) keeps its previous capacity, and while any channel is in that
 * state a missing id is not treated as a vanished channel.
 */
export function detectCapacityDrops(info, previous = {}, { capacityDropSat }) {
  const channels = Array.isArray(info?.channels) ? info.channels : [];
  const known = channels.filter(c => c.channelId && Number.isFinite(Number(c.capacitySat)));
  const allIdentified = known.length === channels.length;

  const next = {};
  for (const c of known) next[c.channelId] = Number(c.capacitySat);

  const drops = [];
  for (const [channelId, previousSat] of Object.entries(previous || {})) {
    if (!(channelId in next)) {
      if (!allIdentified) { next[channelId] = previousSat; continue; }
      if (previousSat >= capacityDropSat) drops.push({ channelId, previousSat, currentSat: 0, dropSat: previousSat, vanished: true });
      continue;
    }
    const dropSat = previousSat - next[channelId];
    if (dropSat >= capacityDropSat) drops.push({ channelId, previousSat, currentSat: next[channelId], dropSat, vanished: false });
  }
  return { drops, channels: next };
}

/** Liquidity purchases in a phoenixd outgoing payment list not seen before. */
export function newPurchases(payments, seen = []) {
  const known = new Set(seen);
  return (Array.isArray(payments) ? payments : [])
    .filter(p => p && PURCHASE_TYPES[p.subType] && p.paymentId && !known.has(p.paymentId))
    .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
}

/**
 * LNbits deposits that settled near a purchase. The purchase is created while the
 * deposit's HTLC is held, and LNbits records the fee when it marks the deposit
 * paid, so the window opens before the purchase and closes after it completes.
 */
export function matchDeposits(purchase, deposits, windowMinutes) {
  const w = windowMinutes * 60_000;
  const start = (purchase.createdAt || 0) - w;
  const end = (purchase.completedAt || purchase.createdAt || 0) + w;
  return deposits.filter(d => d.tsMs >= start && d.tsMs <= end);
}

function remember(list, ids) {
  const merged = [...(list || []), ...ids.filter(id => !(list || []).includes(id))];
  return merged.slice(-SEEN_MAX);
}

/** Normalise an LNbits apipayments row. Amounts are msat; timestamps are seconds. */
export function toDeposit(row) {
  const ts = Number(row.ts);
  return {
    id: String(row.checking_id),
    paymentHash: row.payment_hash || row.checking_id,
    walletId: row.wallet_id,
    amountSat: msatToSat(row.amount),
    feeSat: msatToSat(row.fee),
    tsMs: Number.isFinite(ts) ? ts * 1000 : 0,
  };
}

function depositLine(d) {
  return `- wallet ${short(d.walletId, WALLET_PREFIX)}, invoice ${fmt(d.amountSat)} sat, fee ${fmt(d.feeSat)} sat, ` +
    `credited ${fmt(d.amountSat - d.feeSat)} sat, settled ${iso(d.tsMs)}, payment hash ${short(d.paymentHash)}`;
}

// ── Emails ──────────────────────────────────────────────────────────────────

export function capacityDropEmail(drops, inbound) {
  const total = drops.reduce((s, d) => s + d.dropSat, 0);
  const lines = drops.map(d => d.vanished
    ? `- channel ${short(d.channelId)} is gone (was ${fmt(d.previousSat)} sat)`
    : `- channel ${short(d.channelId)}: ${fmt(d.previousSat)} -> ${fmt(d.currentSat)} sat (dropped ${fmt(d.dropSat)} sat)`);
  return {
    subject: `ALERT: channel capacity dropped by ${fmt(total)} sat (LSP splice-out?)`,
    body: [
      'Channel capacity fell since the last monitor run.',
      '',
      ...lines,
      '',
      'This is what the LSP reclaiming unused leased liquidity with a splice-out looks like.',
      'The next deposit that does not fit the remaining inbound liquidity makes phoenixd buy',
      'liquidity on the fly and charge the whole fee to that one deposit.',
      '',
      `Now: ${inbound.msg}`,
      '',
      RUNBOOK_HINT,
    ].join('\n'),
  };
}

export function purchaseEmail(purchase, matched, { matchWindowMinutes }, inbound) {
  const kind = PURCHASE_TYPES[purchase.subType];
  const feeSat = msatToSat(purchase.fees);
  const lines = [
    `phoenixd made a${kind === 'automatic' ? 'n automatic' : ' manual'} inbound liquidity purchase.`,
    '',
    `Payment id: ${purchase.paymentId}`,
    `Fee: ${fmt(feeSat)} sat (mining plus LSP service fee, as phoenixd reports it)`,
    `Created: ${iso(purchase.createdAt)}`,
    `Completed: ${purchase.completedAt ? iso(purchase.completedAt) : 'not yet'}`,
    `Funding tx: ${short(purchase.txId)}`,
  ];
  if (inbound) lines.push(`Now: ${inbound.msg}`);
  lines.push('');
  if (matched.length) {
    lines.push(`LNbits deposits charged a fee within ${matchWindowMinutes} minutes of it. Refund these users:`, '', ...matched.map(depositLine));
  } else if (kind === 'automatic') {
    lines.push(
      `No LNbits deposit carried a fee within ${matchWindowMinutes} minutes of it, so the fee was`,
      'probably paid from the node balance or fee credit. If a deposit settles with a fee',
      'later, a separate "user charged a node fee" alert follows.',
    );
  } else {
    lines.push('No LNbits deposit was charged for it.');
  }
  lines.push('', RUNBOOK_HINT);
  return {
    subject: `${kind === 'automatic' ? 'ALERT' : 'NOTICE'}: phoenixd bought inbound liquidity (${kind}, fee ${fmt(feeSat)} sat)`,
    body: lines.join('\n'),
  };
}

export function chargedDepositEmail(deposits) {
  const total = deposits.reduce((s, d) => s + d.feeSat, 0);
  return {
    subject: `ALERT: user charged a node fee on a deposit (${fmt(total)} sat)`,
    body: [
      `${deposits.length === 1 ? 'A deposit' : `${deposits.length} deposits`} to a hosted wallet ` +
        `${deposits.length === 1 ? 'was' : 'were'} credited less than the invoice amount:`,
      'LNbits recorded a node fee on an incoming payment.',
      '',
      ...deposits.map(depositLine),
      '',
      'The usual cause is phoenixd buying inbound liquidity on the fly and taking the fee',
      'out of this deposit. The user paid for the node\'s liquidity; refund them.',
      '',
      RUNBOOK_HINT,
    ].join('\n'),
  };
}

// ── The run ─────────────────────────────────────────────────────────────────

/**
 * One monitor run's worth of liquidity checks.
 *
 * @param {object} args
 * @param {object|null} args.info       phoenixd /getinfo body, or null if it could not be read
 * @param {object|null} args.phoenixd   { listOutgoing(fromMs, toMs) }, null if phoenixd is unreachable
 * @param {function} args.openLnbits    async () => { largestDepositSat(sinceSec), chargedDeposits(sinceSec), close() }
 * @param {object} args.state           previous liquidity tracking state
 * @param {number} args.now             current time in ms
 * @param {object} args.config          liquidityConfig()
 * @returns {Promise<{checks: object[], emails: {subject: string, body: string}[], state: object}>}
 *
 * checks go through alert-policy decide(), so a persistent condition alerts once,
 * reminds, and recovers. ok === null means "could not tell this run": the caller
 * leaves that check's state alone. emails are one-off events, deduped here.
 */
export async function runLiquidity({ info, phoenixd, openLnbits, state = {}, now, config }) {
  const prev = state || {};
  const next = { ...prev };
  const emails = [];
  const errors = [];
  const reminderMs = config.reminderHours * 3_600_000;
  const lookbackMs = config.lookbackHours * 3_600_000;

  let lnbits = null;
  try { lnbits = await openLnbits(); }
  catch (e) { errors.push(`LNbits database: ${e.message}`); }

  try {
    // Inbound liquidity, against the floor or recent deposits, whichever is higher.
    let largestDepositSat = 0;
    if (lnbits && config.depositMultiple > 0) {
      try {
        largestDepositSat = await lnbits.largestDepositSat(Math.floor((now - config.depositWindowDays * 86_400_000) / 1000));
      } catch (e) { errors.push(`largest deposit: ${e.message}`); }
    }
    const inbound = info ? evaluateInbound(info, { ...config, largestDepositSat }) : null;

    // Capacity drops between runs. The first run only records a baseline.
    if (info) {
      const { drops, channels } = detectCapacityDrops(info, prev.channels, config);
      next.channels = channels;
      if (prev.channels && drops.length) emails.push(capacityDropEmail(drops, inbound));
    }

    // Deposits charged a fee, read once and shared with purchase matching below.
    let deposits = [];
    let depositsRead = false;
    const purchasesSinceMs = prev.purchasesSinceMs ?? now - lookbackMs;
    const depositsSinceMs = prev.depositsSinceMs ?? now - lookbackMs;
    if (lnbits) {
      const matchMs = config.matchWindowMinutes * 60_000;
      const fromMs = Math.min(depositsSinceMs, purchasesSinceMs - matchMs) - OVERLAP_MS;
      try {
        deposits = (await lnbits.chargedDeposits(Math.floor(fromMs / 1000))).map(toDeposit);
        depositsRead = true;
      } catch (e) { errors.push(`charged deposits: ${e.message}`); }
    }

    // Liquidity purchases since the last run, each with the deposits it was charged to.
    const reported = new Set();
    if (phoenixd) {
      try {
        const payments = await phoenixd.listOutgoing(Math.max(0, purchasesSinceMs - OVERLAP_MS), now);
        const fresh = newPurchases(payments, prev.seenPurchases);
        for (const p of fresh) {
          // Listed even if an earlier deposit alert already named them: this mail is
          // where the operator connects the fee to the purchase.
          const matched = matchDeposits(p, deposits, config.matchWindowMinutes);
          matched.forEach(d => reported.add(d.id));
          emails.push(purchaseEmail(p, matched, config, inbound));
        }
        next.seenPurchases = remember(prev.seenPurchases, fresh.map(p => p.paymentId));
        next.purchasesSinceMs = now;
      } catch (e) { errors.push(`phoenixd outgoing payments: ${e.message}`); }
    }

    // Every other deposit that was charged a fee, whatever the cause.
    if (depositsRead) {
      const charged = deposits.filter(d => !reported.has(d.id) && !(prev.seenDeposits || []).includes(d.id));
      if (charged.length) emails.push(chargedDepositEmail(charged));
      next.seenDeposits = remember(prev.seenDeposits, [...reported, ...charged.map(d => d.id)]);
      next.depositsSinceMs = now;
    }

    const checks = [
      {
        id: 'liquidity_inbound', label: 'Inbound Liquidity',
        ok: inbound ? inbound.ok : null,
        msg: inbound ? inbound.msg : 'phoenixd /getinfo unavailable; see the Phoenixd Node check',
        reminderMs,
        hint: 'A deposit that does not fit makes phoenixd buy liquidity on the fly and charge the\n' +
          'whole fee to that depositor. ' + RUNBOOK_HINT,
      },
      {
        id: 'liquidity_audit', label: 'Liquidity Audit',
        ok: errors.length === 0,
        msg: errors.length ? errors.join('; ') : 'phoenixd purchases and LNbits deposit fees readable',
        reminderMs,
        hint: 'While this fails, liquidity purchases and fees charged to users are not being reported.',
      },
    ];
    return { checks, emails, state: next };
  } finally {
    try { lnbits?.close(); } catch {}
  }
}

// ── Adapters ────────────────────────────────────────────────────────────────

/**
 * The phoenixd API password. The limited-access password is preferred: it can
 * read /getinfo and list payments but cannot spend, which is all the monitor needs.
 */
export function readPhoenixPassword(confPath) {
  const conf = readFileSync(confPath, 'utf8');
  const limited = conf.match(/^http-password-limited-access\s*=\s*(\S+)/m);
  if (limited) return limited[1];
  const full = conf.match(/^http-password\s*=\s*(\S+)/m);
  if (!full) throw new Error('http-password not found in phoenix.conf');
  return full[1];
}

export function phoenixdClient({ url, password, timeoutMs = 10_000, fetchImpl = fetch, pageSize = 100, maxPages = 20 }) {
  const auth = 'Basic ' + Buffer.from(':' + password).toString('base64');
  async function get(path, params) {
    const target = new URL(path, url);
    for (const [k, v] of Object.entries(params || {})) target.searchParams.set(k, String(v));
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const r = await fetchImpl(target, { headers: { Authorization: auth }, signal: ac.signal });
      // Never echo the response body: phoenixd error text is not ours to log.
      if (!r.ok) throw new Error(`HTTP ${r.status} from ${target.pathname}`);
      return await r.json();
    } finally { clearTimeout(t); }
  }
  return {
    getinfo: () => get('/getinfo'),
    // GET /payments/outgoing filters on created_at when all=true (otherwise on
    // succeeded_at) and pages with limit/offset. Timestamps are milliseconds.
    async listOutgoing(fromMs, toMs) {
      const out = [];
      for (let page = 0; page < maxPages; page++) {
        const batch = await get('/payments/outgoing', {
          from: Math.floor(fromMs), to: Math.floor(toMs), limit: pageSize, offset: page * pageSize, all: true,
        });
        if (!Array.isArray(batch)) throw new Error('unexpected /payments/outgoing response');
        out.push(...batch);
        if (batch.length < pageSize) return out;
      }
      throw new Error(`more than ${pageSize * maxPages} outgoing payments in the window`);
    },
  };
}

/**
 * Read-only access to the LNbits database. LNbits stores amounts and fees in msat
 * and, on SQLite, timestamps as Unix seconds. An incoming payment's balance is
 * amount minus |fee|, so a nonzero fee on a deposit is money the user did not get.
 */
export async function openLnbitsReader(path) {
  // node:sqlite is loaded here rather than at the top so that a Node without it
  // fails this check alone instead of the whole monitor.
  const { DatabaseSync } = await import('node:sqlite');
  if (!existsSync(path)) throw new Error(`database not found: ${path}`);
  const db = new DatabaseSync(path, { readOnly: true });
  try { db.exec('PRAGMA busy_timeout = 5000'); }
  catch (e) { db.close(); throw e; }
  const settled = "amount > 0 AND status = 'success' AND COALESCE(updated_at, created_at) >= ?";
  return {
    largestDepositSat(sinceSec) {
      // Internal transfers never touch the channel, so they do not need inbound liquidity.
      const row = db.prepare(`SELECT MAX(amount) AS m FROM apipayments WHERE ${settled} AND checking_id NOT LIKE 'internal_%'`).get(sinceSec);
      return msatToSat(row?.m || 0);
    },
    chargedDeposits(sinceSec) {
      return db.prepare(
        `SELECT checking_id, payment_hash, wallet_id, amount, fee, COALESCE(updated_at, created_at) AS ts
           FROM apipayments WHERE ${settled} AND fee <> 0 ORDER BY ts LIMIT 500`,
      ).all(sinceSec);
    },
    close() { db.close(); },
  };
}

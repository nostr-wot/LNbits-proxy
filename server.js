/**
 * Provisioning proxy for zaps.nostr-wot.com
 *
 * Sits in front of LNbits. Handles challenge-response wallet provisioning.
 * Only allowlisted LNURL callback paths are proxied through to LNbits;
 * all other unrecognized paths return 404.
 *
 * On provision, checks if a wallet already exists for the pubkey (via SQLite).
 * If so, returns the existing wallet. Otherwise creates a new one.
 *
 * Endpoints:
 *   POST /api/v2/provision/challenge - Issue a body-bound transaction
 *   POST /api/v2/provision            - Verify signed event, create or recover wallet
 *   POST /api/v2/claim-username       - Claim a Lightning Address username
 *   GET  /api/lightning-address    - Look up Lightning Address by pubkey
 *   POST /api/v2/release-username     - Release a claimed Lightning Address
 *   POST /api/v2/delete-account       - Delete the signer's hosted wallet account
 *
 * Proxied LNURL paths (GET-only, needed for LNURL callbacks):
 *   GET /.well-known/lnurlp/:username
 *   GET /lnurlp/api/v1/lnurl/cb/:id
 *
 * Proxied wallet API paths (requires X-Api-Key, used by extension):
 *   GET/POST /api/v1/wallet
 *   GET/POST /api/v1/payments
 *   GET      /api/v1/payments/fee-reserve
 *
 * Environment variables:
 *   LNBITS_URL       - LNbits backend URL (default: http://127.0.0.1:5000)
 *   LNBITS_ADMIN_KEY - LNbits super-user API key for wallet creation
 *   LNBITS_DB_PATH   - Path to LNbits SQLite database
 *   LNURLP_DB_PATH   - Path to LNbits lnurlp extension database
 *   PROVISION_DB_PATH - Proxy-owned pubkey to wallet mapping (not LNbits')
 *   PORT             - Listen port (default: 3003)
 */

import { createServer, request as httpRequest } from 'node:http';
import { createNwcRoutes } from './nwc-connections.mjs';
import { existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createAuth, publicOrigin, allowedOrigins, clientScope, AUTH_PATHS, CHALLENGE_PATH } from './auth-v2.mjs';

const LNBITS_URL = process.env.LNBITS_URL || 'http://127.0.0.1:5000';
const LNBITS_ADMIN_KEY = process.env.LNBITS_ADMIN_KEY;
const LNBITS_DB_PATH = process.env.LNBITS_DB_PATH || '/home/lnbits/lnbits/data/database.sqlite3';
const LNURLP_DB_PATH = process.env.LNURLP_DB_PATH || '/home/lnbits/lnbits/data/ext_lnurlp.sqlite3';
// Proxy-owned mapping of Nostr pubkey to wallet. Deliberately NOT inside the
// LNbits database: LNbits lets any logged-in user set accounts.pubkey on their
// own account with no proof they hold the key, so that column cannot be the
// thing that decides whose wallet is whose. This file must be writable only by
// the user this service runs as.
const PROVISION_DB_PATH = process.env.PROVISION_DB_PATH || '/srv/zaps-provision/provisioning.sqlite3';
const nwcRoutes = createNwcRoutes({backend:LNBITS_URL,dbPath:LNBITS_DB_PATH});
const PORT = parseInt(process.env.PORT || '3003', 10);
const BASE_URL = publicOrigin(process.env.PUBLIC_ORIGIN || 'https://zaps.nostr-wot.com');
const DOMAIN = new URL(BASE_URL).host;
const BROWSER_ORIGINS = allowedOrigins(process.env.BROWSER_ORIGINS);
const auth = createAuth({dbPath: PROVISION_DB_PATH, publicOrigin: BASE_URL});
const MAX_BODY_BYTES = 65_536;   // 64KB body limit
const WALLET_NAME_MAX = 50;
const PUBKEY_RE = /^[0-9a-f]{64}$/;
const DB_BUSY_TIMEOUT_MS = 5_000;  // wait out concurrent LNbits writes
const UPSTREAM_TIMEOUT_MS = 30_000;

/**
 * Open an LNbits SQLite database with a busy timeout.
 * node:sqlite defaults to 0, so any concurrent LNbits write makes the very next
 * statement throw SQLITE_BUSY. Every caller here shares live LNbits databases.
 */
function openDb(path, options = {}) {
  // node:sqlite creates an empty file when the path does not exist, so a typo in
  // a configured path turns into "no such table" on every request plus a stray
  // database on disk. Refuse instead.
  if (!existsSync(path)) throw new Error(`Database not found: ${path}`);
  const db = new DatabaseSync(path, options);
  try {
    db.exec(`PRAGMA busy_timeout = ${DB_BUSY_TIMEOUT_MS}`);
  } catch (e) {
    db.close();
    throw e;
  }
  return db;
}

/**
 * Open the proxy's own database, creating it and its schema on first use.
 * Unlike the LNbits databases, this one is ours to create.
 */
function openProvisionDb() {
  const db = new DatabaseSync(PROVISION_DB_PATH);
  try {
    db.exec(`PRAGMA busy_timeout = ${DB_BUSY_TIMEOUT_MS}`);
    db.exec(`
      CREATE TABLE IF NOT EXISTS provisioned (
        pubkey     TEXT PRIMARY KEY,
        user_id    TEXT NOT NULL,
        wallet_id  TEXT NOT NULL,
        created_at REAL NOT NULL
      );
      -- One row per completed account deletion. Deliberately carries no pubkey,
      -- user or wallet id: only when it happened and what balance was forfeited.
      CREATE TABLE IF NOT EXISTS account_deletions (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        deleted_at     INTEGER NOT NULL,
        forfeited_msat INTEGER NOT NULL DEFAULT 0
      );
    `);
  } catch (e) {
    db.close();
    throw e;
  }
  return db;
}

// Each v2 operation: its rate-limit bucket and the exact, sorted set of body fields.
const AUTH_ROUTES = {
  '/api/v2/provision':        { bucket: 'provision',     fields: 'name' },
  '/api/v2/claim-username':   { bucket: 'claim',         fields: 'username' },
  '/api/v2/release-username': { bucket: 'release',       fields: '' },
  '/api/v2/delete-account':   { bucket: 'deleteAccount', fields: 'acknowledgeBalance,confirm' },
};
for (const path of AUTH_PATHS) {
  if (!AUTH_ROUTES[path]) throw new Error(`No route configuration for ${path}`);
}

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{1,28}[a-z0-9]$/;
const RESERVED_USERNAMES = new Set([
  'admin', 'support', 'help', 'info', 'noreply', 'postmaster',
  'webmaster', 'abuse', 'root', 'system',
]);

// CORS headers for LNURL proxy responses only (wallets call cross-origin)
const LNURL_CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// Tightened proxy allowlist: only exact LNURL callback patterns
const PROXY_ALLOWLIST = [
  /^\/\.well-known\/lnurlp\/[a-z0-9._-]+$/,
  /^\/lnurlp\/api\/v1\/lnurl\/cb\/[a-zA-Z0-9]+$/,
];

// Wallet API paths that require X-Api-Key authentication (used by extension).
// Matched against the normalized pathname only; `methods` is exhaustive, so a
// path is reachable by the verbs listed for it and by nothing else.
const WALLET_API_ALLOWLIST = [
  { methods: ['GET', 'POST'], pathname: /^\/api\/v1\/wallet$/ },
  { methods: ['GET', 'POST'], pathname: /^\/api\/v1\/payments$/ },
  // GET /api/v1/payments/fee-reserve?invoice=<bolt11> returns the fee_limit_msat
  // LNbits hands the funding source, so the extension can compare a sweep's
  // ceiling against the balance instead of refusing to sweep on an unknown fee.
  // Read-only, and anchored so it cannot widen into /api/v1/payments/<hash>.
  { methods: ['GET'], pathname: /^\/api\/v1\/payments\/fee-reserve$/ },
];

// ── Per-IP rate limiting ──

const rateLimitBuckets = {
  nwc:        { maxPerMin: 60, entries: new Map() },
  challenge:  { maxPerMin: 10, entries: new Map() },
  provision:  { maxPerMin: 5,  entries: new Map() },
  claim:      { maxPerMin: 3,  entries: new Map() },
  release:    { maxPerMin: 3,  entries: new Map() },
  deleteAccount: { maxPerMin: 3, entries: new Map() },
  // Unauthenticated LNURL callbacks create a real invoice in LNbits and the
  // Lightning backend on every hit. A real wallet calls once per zap, so this
  // is generous while still bounding invoice-flooding from a single host.
  lnurl:      { maxPerMin: 60, entries: new Map() },
  wallet:     { maxPerMin: 120, entries: new Map() },
};

function checkRateLimit(ip, bucket) {
  const config = rateLimitBuckets[bucket];
  if (!config) return true;
  const now = Date.now();
  const windowMs = 60_000;
  let entry = config.entries.get(ip);
  if (!entry) {
    entry = { timestamps: [] };
    config.entries.set(ip, entry);
  }
  entry.timestamps = entry.timestamps.filter(t => now - t < windowMs);
  if (entry.timestamps.length >= config.maxPerMin) return false;
  entry.timestamps.push(now);
  return true;
}

// Cleanup stale rate limit entries every 5 minutes
const _rlCleanup = setInterval(() => {
  const now = Date.now();
  for (const bucket of Object.values(rateLimitBuckets)) {
    for (const [ip, entry] of bucket.entries) {
      entry.timestamps = entry.timestamps.filter(t => now - t < 60_000);
      if (entry.timestamps.length === 0) bucket.entries.delete(ip);
    }
  }
}, 300_000);
_rlCleanup.unref();

// In-memory mutex sets to prevent race conditions on provisioning/claiming.
// Provisioning and account deletion share one set, so a pubkey can never be
// provisioned while its account is being deleted, or deleted twice at once.
const _busyPubkeys = new Set();
const _claimingUsernames = new Set();

// ── Helpers ──

function getClientIp(req) {
  // Trust only the rightmost X-Forwarded-For entry (set by our nginx)
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const parts = forwarded.split(',').map(s => s.trim());
    return parts[parts.length - 1];
  }
  return req.socket?.remoteAddress || '0.0.0.0';
}

/** JSON response with Cache-Control and nosniff headers */
function jsonResponse(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(JSON.stringify(data));
}

/**
 * Read body with size limit.
 *
 * Over the limit we stop buffering and reject, but leave the socket alive so
 * the caller's 413 actually reaches the client. Destroying here made every
 * oversize request surface as ECONNRESET instead. A body far past the limit is
 * an abusive client, so that one does get cut off.
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        if (!tooLarge) {
          tooLarge = true;
          reject(new Error('BODY_TOO_LARGE'));
        }
        if (size > MAX_BODY_BYTES * 4) req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!tooLarge) resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

/** Strip control characters from a string */
function sanitizeString(str) {
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\x00-\x1f\x7f]/g, '');
}

/**
 * Proxy a request to LNbits backend (LNURL paths only).
 * Builds a minimal header set — strips auth/cookie headers.
 * CORS headers added since LNURL callbacks are called by wallets cross-origin.
 */
function proxyToLnbits(clientReq, clientRes, proxiedPath) {
  const url = new URL(LNBITS_URL);
  const opts = {
    hostname: url.hostname,
    port: url.port || 80,
    path: proxiedPath,
    method: 'GET',
    headers: {
      'accept': clientReq.headers['accept'] || '*/*',
      'accept-encoding': clientReq.headers['accept-encoding'] || '',
      'host': DOMAIN,
      'x-forwarded-proto': 'https',
      'x-forwarded-host': DOMAIN,
    },
  };

  // pathname only: the query carries the NIP-57 zap request and payer comment
  console.log(`[proxy] GET ${new URL(proxiedPath, 'http://x').pathname}`);

  const proxy = httpRequest(opts, (proxyRes) => {
    const headers = { ...proxyRes.headers, ...LNURL_CORS_HEADERS };
    clientRes.writeHead(proxyRes.statusCode, headers);
    // If LNbits dies mid-body the reset lands here, not on the request object.
    // Without this the client waits out its own timeout on a response that
    // announced a Content-Length it will never receive.
    const abandon = (err) => {
      console.error('[proxy] LNbits aborted mid-response:', err?.message || 'aborted');
      clientRes.destroy();
    };
    proxyRes.on('aborted', abandon);
    proxyRes.on('error', abandon);
    proxyRes.pipe(clientRes, { end: true });
  });

  proxy.on('error', (err) => {
    console.error('[proxy] LNbits error:', err.message);
    // If LNbits resets after we already relayed its headers, writeHead throws
    // ERR_HTTP_HEADERS_SENT from inside this handler, outside any try/catch:
    // an uncaught exception that kills the process and wipes every challenge.
    if (clientRes.headersSent) {
      clientRes.destroy();
      return;
    }
    clientRes.writeHead(502, { 'Content-Type': 'application/json', ...LNURL_CORS_HEADERS });
    clientRes.end(JSON.stringify({ error: 'LNbits backend unavailable' }));
  });

  // Do not hold a socket open while LNbits hangs, and drop the upstream request
  // if the client gave up first.
  proxy.setTimeout(UPSTREAM_TIMEOUT_MS, () => proxy.destroy(new Error('Upstream timeout')));
  clientReq.on('close', () => {
    if (!clientRes.writableEnded) proxy.destroy();
  });

  // LNURL callbacks are GET-only, no body to pipe
  proxy.end();
}

/**
 * Proxy authenticated wallet API requests to LNbits.
 * Forwards X-Api-Key for user wallet auth. Supports GET and POST.
 */
function proxyWalletApi(clientReq, clientRes, proxiedPath, body) {
  const url = new URL(LNBITS_URL);
  const headers = {
    'host': url.host,
    'content-type': 'application/json',
    'x-forwarded-proto': 'https',
    'x-forwarded-host': DOMAIN,
  };
  // Forward X-Api-Key (user's wallet key, not admin key)
  if (clientReq.headers['x-api-key']) {
    headers['x-api-key'] = clientReq.headers['x-api-key'];
  }
  if (body) {
    headers['content-length'] = Buffer.byteLength(body);
  }

  const opts = {
    hostname: url.hostname,
    port: url.port || 80,
    path: proxiedPath,
    method: clientReq.method,
    headers,
  };

  console.log(`[wallet-proxy] ${clientReq.method} ${new URL(proxiedPath, 'http://x').pathname}`);

  const proxy = httpRequest(opts, (proxyRes) => {
    clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
    const abandon = (err) => {
      console.error('[wallet-proxy] LNbits aborted mid-response:', err?.message || 'aborted');
      clientRes.destroy();
    };
    proxyRes.on('aborted', abandon);
    proxyRes.on('error', abandon);
    proxyRes.pipe(clientRes, { end: true });
  });

  proxy.on('error', (err) => {
    console.error('[wallet-proxy] LNbits error:', err.message);
    if (clientRes.headersSent) {
      clientRes.destroy();
      return;
    }
    jsonResponse(clientRes, 502, { error: 'LNbits backend unavailable' });
  });

  proxy.setTimeout(UPSTREAM_TIMEOUT_MS, () => proxy.destroy(new Error('Upstream timeout')));
  clientReq.on('close', () => {
    if (!clientRes.writableEnded) proxy.destroy();
  });

  if (body) {
    proxy.end(body);
  } else {
    proxy.end();
  }
}

/**
 * Look up an existing wallet for a Nostr pubkey in the LNbits database.
 * Returns { id, adminkey, name, user, ... } or null if not found.
 */
function findWalletByPubkey(pubkey) {
  // Step 1: which wallet did THIS service record for this pubkey, after
  // verifying a NIP-98 signature from it. accounts.pubkey is never consulted.
  let mapping;
  const pdb = openProvisionDb();
  try {
    mapping = pdb.prepare('SELECT user_id, wallet_id FROM provisioned WHERE pubkey = ?').get(pubkey);
  } catch (e) {
    console.error('[provision] provisioning lookup error:', e.message);
    throw new Error('Database lookup failed');
  } finally {
    pdb.close();
  }
  if (!mapping) return null;

  // Step 2: read that specific wallet out of LNbits.
  const db = openDb(LNBITS_DB_PATH, { readOnly: true });
  try {
    const row = db.prepare(`
      SELECT w.id, w.name, w.adminkey, w.inkey, w."user"
      FROM wallets w
      WHERE w.id = ?
        AND w."user" = ?
        AND w.deleted = 0
    `).get(mapping.wallet_id, mapping.user_id);
    if (!row) {
      // Mapped wallet is gone. Report unprovisioned so a new one is created;
      // the insert below upserts, so the stale row is replaced rather than
      // blocking on the primary key.
      console.warn(`[provision] mapped wallet ${mapping.wallet_id} missing or deleted for pubkey ${pubkey.slice(0, 16)}...`);
      return null;
    }
    return row;
  } catch (e) {
    console.error('[provision] SQLite lookup error:', e.message);
    throw new Error('Database lookup failed');
  } finally {
    db.close();
  }
}

/**
 * Create a wallet via LNbits admin API.
 */
async function createLnbitsWallet(walletName) {
  const res = await fetch(`${LNBITS_URL}/api/v1/account`, {
    method: 'POST',
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    headers: {
      'Content-Type': 'application/json',
      'X-Api-Key': LNBITS_ADMIN_KEY,
    },
    body: JSON.stringify({ name: walletName }),
  });
  if (!res.ok) {
    const text = await res.text();
    console.error(`[provision] LNbits API error: ${res.status} ${text}`);
    throw new Error('LNbits wallet creation failed');
  }
  return res.json();
}

/**
 * Record that a Nostr pubkey owns a wallet.
 *
 * The row in the proxy's own database is the authoritative one: it is written
 * only here, only after the v2 verifier has checked a signature from this
 * pubkey, and the file is not writable by LNbits or its users. accounts.pubkey
 * is mirrored afterwards purely so LNbits' own UI shows the association; it is
 * never read back for authorization.
 *
 * Throws if the authoritative write fails, so the caller can refuse to hand out
 * keys for a wallet it would not be able to find again.
 */
function linkWalletToPubkey(userId, walletId, pubkey) {
  let lastError = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const pdb = openProvisionDb();
    try {
      pdb.prepare(`
        INSERT INTO provisioned (pubkey, user_id, wallet_id, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(pubkey) DO UPDATE SET user_id = excluded.user_id, wallet_id = excluded.wallet_id
      `).run(pubkey, userId, walletId, Date.now() / 1000);
      lastError = null;
      break;
    } catch (e) {
      lastError = e;
      console.error(`[provision] mapping attempt ${attempt}/3 for user ${userId} failed:`, e.message);
    } finally {
      pdb.close();
    }
  }
  if (lastError) throw new Error(`PUBKEY_LINK_FAILED: ${lastError.message}`);
  console.log(`[provision] mapped pubkey ${pubkey.slice(0, 16)}... to wallet ${walletId}`);

  // Cosmetic mirror into LNbits. A failure here costs nothing: nothing reads it.
  try {
    const db = openDb(LNBITS_DB_PATH);
    try {
      db.prepare('UPDATE accounts SET pubkey = ? WHERE id = ?').run(pubkey, userId);
    } finally {
      db.close();
    }
  } catch (e) {
    console.warn(`[provision] could not mirror pubkey into LNbits accounts (harmless):`, e.message);
  }
}

// ── Account deletion ──
//
// Deletes everything this proxy and LNbits hold for one pubkey's hosted account.
// The steps are ordered so a failure part-way leaves a state the next call
// finishes, and so that nothing is deleted while it could still strand funds:
//
//   1. refuse if the account holds a balance the caller did not acknowledge, or
//      has an outgoing payment in flight (a failed one would refund a wallet
//      that no longer exists)
//   2. revoke every NWC grant, through the provider's API, while the wallet
//      keys still work
//   3. release the Lightning Address, so no new zap can land
//   4. check the balance again, now that nothing can pay in
//   5. delete the LNbits records in one transaction
//   6. delete the mapping and write the anonymous audit row in one transaction
//
// The mapping goes last: while it exists a retry can find the account, and once
// it is gone the account is unreachable by design. No log line here carries the
// pubkey, the LNbits user id or the wallet id.

const DELETE_CONFIRMATION = 'delete-account';

// LNbits rows tied to the account, purged after the wallets' own dependants and
// before the wallets and the account itself. Tables or columns this LNbits
// version does not have are skipped. The apipayments ledger is deliberately not
// in this list: see RUNBOOK.md.
const LNBITS_ACCOUNT_ROWS = [
  ['balance_check', 'wallet', 'wallet'],
  ['balance_notify', 'wallet', 'wallet'],
  ['tiny_url', 'wallet', 'wallet'],
  ['wasm_invocations', 'wallet_id', 'wallet'],
  ['wasm_invocations', 'user_id', 'user'],
  ['extensions', 'user', 'user'],
  ['webpush_subscriptions', 'user', 'user'],
  ['assets', 'user_id', 'user'],
  ['audit', 'user_id', 'user'],
  ['wallets', 'user', 'user'],
  ['accounts', 'id', 'user'],
];

class DeletionError extends Error {
  constructor(step, message, { upstream = false } = {}) {
    super(message);
    this.step = step;
    this.upstream = upstream;
  }
}

function tableColumns(db, table) {
  return new Set(db.prepare(`PRAGMA table_info(${JSON.stringify(table)})`).all().map(c => c.name));
}

const placeholders = (values) => values.map(() => '?').join(',');

/** The apipayments filters for this LNbits schema (status column since 1.0, pending flag before). */
function paymentStateSql(db) {
  const columns = tableColumns(db, 'apipayments');
  if (columns.has('status')) {
    return {
      pendingOut: `status = 'pending' AND amount < 0`,
      counted: `(status = 'success' AND amount > 0) OR (status IN ('success', 'pending') AND amount < 0)`,
    };
  }
  if (columns.has('pending')) {
    return { pendingOut: `pending = 1 AND amount < 0`, counted: `(pending = 0 AND amount > 0) OR amount < 0` };
  }
  // Fail closed: without a ledger we cannot tell whether deleting strands funds.
  throw new Error('apipayments ledger not readable');
}

/** Balance of one wallet, in msat, as LNbits itself reports it to the wallet's own key. */
async function readWalletBalance(adminKey) {
  let res;
  try {
    res = await fetch(`${LNBITS_URL}/api/v1/wallet`, {
      redirect: 'error',
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      headers: { 'X-Api-Key': adminKey },
    });
  } catch (e) {
    throw new DeletionError('balance', `LNbits unreachable: ${e.message}`, { upstream: true });
  }
  if (!res.ok) throw new DeletionError('balance', `LNbits wallet read HTTP ${res.status}`, { upstream: true });
  let body;
  try { body = await res.json(); } catch { body = null; }
  if (!Number.isFinite(body?.balance)) throw new DeletionError('balance', 'LNbits wallet read returned no balance', { upstream: true });
  return Math.trunc(body.balance);
}

/**
 * Funds still attached to the account: the balance of every wallet the LNbits
 * user owns, and whether any outgoing payment is still in flight. Live wallets
 * are read through LNbits' API; a wallet LNbits already soft-deleted has no
 * working key, so its balance is summed from the ledger with LNbits' own rule.
 */
async function assessAccountFunds(userId) {
  let wallets, softDeletedMsat = 0, pendingOut = 0;
  const db = openDb(LNBITS_DB_PATH, { readOnly: true });
  try {
    wallets = db.prepare('SELECT id, adminkey, deleted FROM wallets WHERE "user" = ?').all(userId);
    if (wallets.length) {
      const ids = wallets.map(w => w.id);
      const sql = paymentStateSql(db);
      pendingOut = db.prepare(
        `SELECT COUNT(*) AS n FROM apipayments WHERE wallet_id IN (${placeholders(ids)}) AND ${sql.pendingOut}`
      ).get(...ids).n;
      const deletedIds = wallets.filter(w => w.deleted).map(w => w.id);
      if (deletedIds.length) {
        softDeletedMsat = Number(db.prepare(
          `SELECT COALESCE(SUM(amount - ABS(COALESCE(fee, 0))), 0) AS msat FROM apipayments
           WHERE wallet_id IN (${placeholders(deletedIds)}) AND (${sql.counted})`
        ).get(...deletedIds).msat);
      }
    }
  } catch (e) {
    throw new DeletionError('assess', e.message);
  } finally {
    db.close();
  }
  let balanceMsat = softDeletedMsat;
  for (const wallet of wallets.filter(w => !w.deleted)) balanceMsat += await readWalletBalance(wallet.adminkey);
  return { wallets, balanceMsat, pendingOut };
}

function refuseDeletion(funds, acknowledgeBalance) {
  if (funds.pendingOut > 0) return { status: 409, body: { error: 'payment_pending' } };
  if (funds.balanceMsat > 0 && acknowledgeBalance !== true) {
    return { status: 409, body: { error: 'balance_not_zero', balanceMsat: funds.balanceMsat } };
  }
  return null;
}

async function deleteAccount(pubkey, acknowledgeBalance) {
  let mapping, sharers;
  const pdb = openProvisionDb();
  try {
    mapping = pdb.prepare('SELECT user_id, wallet_id FROM provisioned WHERE pubkey = ?').get(pubkey);
    if (mapping) {
      sharers = pdb.prepare('SELECT COUNT(*) AS n FROM provisioned WHERE user_id = ? AND pubkey != ?')
        .get(mapping.user_id, pubkey).n;
    }
  } catch (e) {
    throw new DeletionError('mapping', e.message);
  } finally {
    pdb.close();
  }
  if (!mapping) return { status: 404, body: { error: 'not_found' } };
  // One LNbits account per pubkey is the invariant provisioning keeps. If it is
  // ever broken, deleting would take another pubkey's wallet with it.
  if (sharers > 0) return { status: 409, body: { error: 'shared_account' } };
  const userId = mapping.user_id;
  // Equally, the mapped wallet must belong to the mapped LNbits account, or the
  // steps below that key on the wallet id would reach someone else's records.
  let owner;
  const ownerDb = openDb(LNBITS_DB_PATH, { readOnly: true });
  try {
    owner = ownerDb.prepare('SELECT "user" AS user_id FROM wallets WHERE id = ?').get(mapping.wallet_id);
  } catch (e) {
    throw new DeletionError('mapping', e.message);
  } finally {
    ownerDb.close();
  }
  if (owner && owner.user_id !== userId) return { status: 409, body: { error: 'shared_account' } };

  // 1. Nothing has changed yet; refusing here leaves the account untouched.
  const before = await assessAccountFunds(userId);
  const refused = refuseDeletion(before, acknowledgeBalance);
  if (refused) return refused;

  // 2. Revoke NWC grants while the wallet keys still authenticate.
  let revoked = 0;
  for (const wallet of before.wallets.filter(w => !w.deleted)) {
    try {
      revoked += (await nwcRoutes.revokeAll(wallet.adminkey, userId)).revoked;
    } catch (e) {
      throw new DeletionError('nwc', `status=${e.status ?? '-'} ${e.message}`, { upstream: true });
    }
  }

  // 3. Release the Lightning Address. The mapped wallet is included even if
  // LNbits no longer lists it, so a stray pay link cannot outlive the account.
  const walletIds = [...new Set([mapping.wallet_id, ...before.wallets.map(w => w.id)])];
  let lnurlpDb;
  try {
    lnurlpDb = openDb(LNURLP_DB_PATH);
    lnurlpDb.prepare(`DELETE FROM pay_links WHERE wallet IN (${placeholders(walletIds)})`).run(...walletIds);
  } catch (e) {
    throw new DeletionError('lightning-address', e.message);
  } finally {
    lnurlpDb?.close();
  }

  // 4. Nothing new can pay in now. Anything that landed since step 1 counts.
  const after = await assessAccountFunds(userId);
  const refusedAfter = refuseDeletion(after, acknowledgeBalance);
  if (refusedAfter) {
    console.warn('[delete-account] funds arrived during deletion; address released, account kept');
    return refusedAfter;
  }

  // 5. LNbits records, in one transaction on one file.
  const db = openDb(LNBITS_DB_PATH);
  try {
    db.exec('BEGIN IMMEDIATE');
    // The mapped wallet is included even if its row is already gone, so rows
    // keyed by it are still cleared when LNbits lost the wallet some other way.
    const ids = [...new Set([mapping.wallet_id,
      ...db.prepare('SELECT id FROM wallets WHERE "user" = ?').all(userId).map(w => w.id)])];
    for (const [table, column, key] of LNBITS_ACCOUNT_ROWS) {
      if (!tableColumns(db, table).has(column)) continue;
      const values = key === 'user' ? [userId] : ids;
      if (!values.length) continue;
      db.prepare(`DELETE FROM ${JSON.stringify(table)} WHERE ${JSON.stringify(column)} IN (${placeholders(values)})`).run(...values);
    }
    db.exec('COMMIT');
  } catch (e) {
    if (db.isTransaction) db.exec('ROLLBACK');
    throw new DeletionError('lnbits', e.message);
  } finally {
    db.close();
  }

  // 6. The mapping, and the anonymous record that a deletion happened.
  const forfeitedMsat = Math.max(0, after.balanceMsat);
  const proxyDb = openProvisionDb();
  try {
    proxyDb.exec('BEGIN IMMEDIATE');
    const removed = proxyDb.prepare('DELETE FROM provisioned WHERE pubkey = ?').run(pubkey).changes;
    if (removed) {
      proxyDb.prepare('INSERT INTO account_deletions (deleted_at, forfeited_msat) VALUES (?, ?)')
        .run(Math.floor(Date.now() / 1000), forfeitedMsat);
    }
    proxyDb.exec('COMMIT');
  } catch (e) {
    if (proxyDb.isTransaction) proxyDb.exec('ROLLBACK');
    throw new DeletionError('mapping', e.message);
  } finally {
    proxyDb.close();
  }

  console.log(`[delete-account] account deleted: nwc_revoked=${revoked} forfeited_msat=${forfeitedMsat}`);
  return { status: 200, body: { deleted: true } };
}

// ── Request handler ──

const server = createServer(async (req, res) => {
  try {
    const clientIp = getClientIp(req);

    // Use a configured audience, never Host or forwarded host headers.
    const parsedUrl = new URL(req.url, BASE_URL);
    const legacyPaths = ['/api/provision/challenge','/api/provision','/api/claim-username','/api/release-username'];
    if (legacyPaths.includes(parsedUrl.pathname)) {
      return jsonResponse(res, 426, {error:'Upgrade required: use the body-bound v2 authentication flow', version:2});
    }
    const isAuthPath = AUTH_PATHS.includes(parsedUrl.pathname) || parsedUrl.pathname === CHALLENGE_PATH;
    let scope;
    if (isAuthPath) {
      res.setHeader('Vary', 'Origin');
      if (req.url !== parsedUrl.pathname) return jsonResponse(res, 400, {error:'Exact path required; queries are not supported'});
      try { scope = clientScope(req.headers.origin, BROWSER_ORIGINS); }
      catch { return jsonResponse(res, 403, {error:'Browser origin denied'}); }
      if (scope !== 'native') res.setHeader('Access-Control-Allow-Origin', scope);
      if (req.method === 'OPTIONS') {
        const requested = (req.headers['access-control-request-headers'] || '').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
        const headers = parsedUrl.pathname === CHALLENGE_PATH ? ['content-type'] : ['content-type','authorization','x-nostr-transaction'];
        if (scope === 'native' || req.headers['access-control-request-method'] !== 'POST' || requested.some(h=>!headers.includes(h))) {
          return jsonResponse(res,403,{error:'Preflight denied'});
        }
        res.setHeader('Vary','Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
        res.writeHead(204, {'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':headers.join(', ')});
        return res.end();
      }
      if (req.method !== 'POST') return jsonResponse(res,405,{error:'POST required'});
    }
    if (req.method === 'OPTIONS') {
      if (PROXY_ALLOWLIST.some(re => re.test(parsedUrl.pathname))) res.writeHead(204, LNURL_CORS_HEADERS);
      else res.writeHead(204);
      return res.end();
    }
    let operationBody, operationRaw;
    if (isAuthPath) {
      const bucket = parsedUrl.pathname === CHALLENGE_PATH ? 'challenge' : AUTH_ROUTES[parsedUrl.pathname].bucket;
      if (!checkRateLimit(clientIp,bucket)) return jsonResponse(res,429,{error:'Too many requests'});
      try {
        operationRaw = await readBody(req);
        operationBody = JSON.parse(operationRaw.toString('utf8'));
        if (!operationBody || typeof operationBody !== 'object' || Array.isArray(operationBody)) throw new Error('Invalid JSON object');
      } catch(e) { return jsonResponse(res,e.message==='BODY_TOO_LARGE'?413:400,{error:'Invalid or oversized JSON body'}); }
      if (parsedUrl.pathname === CHALLENGE_PATH) {
        try { return jsonResponse(res,200,auth.issue(operationBody,scope)); }
        catch(e) { return jsonResponse(res,e.message.startsWith('Server busy')?503:400,{error:e.message}); }
      }
      const keys = Object.keys(operationBody).sort().join(',');
      if (keys !== AUTH_ROUTES[parsedUrl.pathname].fields) return jsonResponse(res,400,{error:'Unexpected operation fields'});
    }
    const verifyOperation = () => {
      try { return auth.verify({authorization:req.headers.authorization,token:req.headers['x-nostr-transaction'],raw:operationRaw,url:BASE_URL+req.url,scope}); }
      catch { jsonResponse(res,403,{error:'Invalid, expired or consumed authentication'}); return null; }
    };

    if (parsedUrl.pathname === '/api/nwc/connections' || parsedUrl.pathname.startsWith('/api/nwc/connections/')) {
      if (!checkRateLimit(clientIp, 'nwc')) return jsonResponse(res, 429, { error: 'Too many requests' });
      if (await nwcRoutes(req, res, parsedUrl)) return;
    }

    // POST /api/v2/provision
    if (req.method === 'POST' && parsedUrl.pathname === '/api/v2/provision') {
      if (!LNBITS_ADMIN_KEY) {
        return jsonResponse(res, 500, { error: 'Server not configured: missing LNBITS_ADMIN_KEY' });
      }

      const body = operationBody;

      const { name } = body;
      if (!name || typeof name !== 'string') {
        return jsonResponse(res, 400, { error: 'Missing or invalid "name" field' });
      }

      const sanitizedName = sanitizeString(name).slice(0, WALLET_NAME_MAX);
      if (!sanitizedName) {
        return jsonResponse(res, 400, { error: 'Invalid wallet name' });
      }

      const verified = verifyOperation();
      if (!verified) return;

      // C2: Mutex to prevent duplicate wallet provisioning for the same pubkey
      if (_busyPubkeys.has(verified.pubkey)) {
        return jsonResponse(res, 409, { error: 'Provisioning already in progress for this pubkey' });
      }
      _busyPubkeys.add(verified.pubkey);
      try {
        // Check if this pubkey already has a wallet
        const existing = findWalletByPubkey(verified.pubkey);
        if (existing) {
          return jsonResponse(res, 200, existing);
        }

        // Create new wallet via LNbits
        const wallet = await createLnbitsWallet(sanitizedName);
        try {
          linkWalletToPubkey(wallet.user, wallet.id, verified.pubkey);
        } catch (e) {
          // The wallet exists but is not reachable by pubkey. Returning its keys
          // would let it receive sats that no later provision could ever find.
          console.error(
            `[provision] ORPHANED WALLET user=${wallet.user} wallet=${wallet.id} ` +
            `pubkey=${verified.pubkey.slice(0, 16)}...: created but not linked: ${e.message}`
          );
          return jsonResponse(res, 503, {
            error: 'Wallet created but could not be linked to your key. Do not retry; contact the operator.',
          });
        }
        return jsonResponse(res, 201, wallet);
      } catch (e) {
        console.error(`[provision] error: ${e.message}`);
        return jsonResponse(res, 502, { error: 'Failed to create wallet on LNbits backend' });
      } finally {
        _busyPubkeys.delete(verified.pubkey);
      }
    }

    // POST /api/v2/claim-username — Claim a Lightning Address
    if (req.method === 'POST' && parsedUrl.pathname === '/api/v2/claim-username') {

      const body = operationBody;

      const { username } = body;
      if (!username || typeof username !== 'string') {
        return jsonResponse(res, 400, { error: 'Missing or invalid "username" field' });
      }

      const sanitizedUsername = sanitizeString(username);
      if (!USERNAME_RE.test(sanitizedUsername)) {
        return jsonResponse(res, 400, { error: '3-30 characters, lowercase letters, numbers, dots, hyphens, underscores. Must start and end with alphanumeric.' });
      }
      if (RESERVED_USERNAMES.has(sanitizedUsername)) {
        return jsonResponse(res, 400, { error: 'This username is reserved' });
      }

      const verified = verifyOperation();
      if (!verified) return;

      // Look up user's wallet
      const wallet = findWalletByPubkey(verified.pubkey);
      if (!wallet) {
        return jsonResponse(res, 404, { error: 'No wallet found for this pubkey. Provision a wallet first.' });
      }

      // C1: Mutex to prevent duplicate username claiming
      if (_claimingUsernames.has(sanitizedUsername)) {
        return jsonResponse(res, 409, { error: 'Username claim already in progress' });
      }
      _claimingUsernames.add(sanitizedUsername);

      // Opened inside the try: if this throws, the finally below still releases
      // the mutex. Opening it before the try leaked the username permanently.
      let lnurlpDb;
      try {
        lnurlpDb = openDb(LNURLP_DB_PATH);
        // Check if username is already taken
        const existing = lnurlpDb.prepare('SELECT id FROM pay_links WHERE username = ?').get(sanitizedUsername);
        if (existing) {
          return jsonResponse(res, 409, { error: 'This username is already taken' });
        }

        // Check if this wallet already has a pay link
        const walletLink = lnurlpDb.prepare('SELECT id, username FROM pay_links WHERE wallet = ?').get(wallet.id);
        if (walletLink) {
          return jsonResponse(res, 409, { error: `You already have a Lightning Address: ${walletLink.username}@${DOMAIN}` });
        }

        // Create pay link
        const payLinkId = randomBytes(6).toString('hex');
        const now = Date.now() / 1000;
        lnurlpDb.prepare(`
          INSERT INTO pay_links (id, wallet, description, min, max, served_meta, served_pr,
            webhook_url, success_text, success_url, currency, comment_chars,
            webhook_headers, webhook_body, username, zaps, domain, created_at, updated_at, disposable)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          payLinkId, wallet.id, 'Lightning Address', 1, 1000000, 0, 0,
          '', '', '', '', 255, '', '', sanitizedUsername, 1, DOMAIN, now, now, 0
        );

        // Update account username. These two writes live in different database
        // files and cannot share a transaction, so if this one fails we undo the
        // pay link rather than leaving a live Lightning Address behind a 500.
        try {
          const mainDb = openDb(LNBITS_DB_PATH);
          try {
            mainDb.prepare('UPDATE accounts SET username = ? WHERE id = ?').run(sanitizedUsername, wallet.user);
          } finally {
            mainDb.close();
          }
        } catch (e) {
          lnurlpDb.prepare('DELETE FROM pay_links WHERE id = ?').run(payLinkId);
          console.error(`[claim-username] rolled back pay link ${payLinkId}:`, e.message);
          throw e;
        }

        return jsonResponse(res, 200, { address: `${sanitizedUsername}@${DOMAIN}`, payLinkId });
      } catch (e) {
        console.error(`[claim-username] error:`, e.message);
        return jsonResponse(res, 500, { error: 'Failed to create Lightning Address' });
      } finally {
        lnurlpDb?.close();
        _claimingUsernames.delete(sanitizedUsername);
      }
    }

    // GET /api/lightning-address?pubkey=<hex>
    if (req.method === 'GET' && parsedUrl.pathname === '/api/lightning-address') {
      const pubkey = parsedUrl.searchParams.get('pubkey');
      if (!pubkey || !PUBKEY_RE.test(pubkey)) {
        return jsonResponse(res, 400, { error: 'Invalid or missing pubkey parameter' });
      }

      const wallet = findWalletByPubkey(pubkey);
      if (!wallet) {
        return jsonResponse(res, 200, { address: null });
      }

      const lnurlpDb = openDb(LNURLP_DB_PATH, { readOnly: true });
      try {
        const link = lnurlpDb.prepare('SELECT username FROM pay_links WHERE wallet = ?').get(wallet.id);
        if (link && link.username) {
          return jsonResponse(res, 200, { address: `${link.username}@${DOMAIN}` });
        }
        return jsonResponse(res, 200, { address: null });
      } catch (e) {
        console.error(`[lightning-address] lookup error:`, e.message);
        return jsonResponse(res, 500, { error: 'Lookup failed' });
      } finally {
        lnurlpDb.close();
      }
    }

    // POST /api/v2/release-username
    if (req.method === 'POST' && parsedUrl.pathname === '/api/v2/release-username') {

      const body = operationBody;

      const verified = verifyOperation();
      if (!verified) return;

      const wallet = findWalletByPubkey(verified.pubkey);
      if (!wallet) {
        return jsonResponse(res, 404, { error: 'No wallet found for this pubkey' });
      }

      const lnurlpDb = openDb(LNURLP_DB_PATH);
      try {
        const link = lnurlpDb.prepare('SELECT id, username FROM pay_links WHERE wallet = ?').get(wallet.id);
        if (!link) {
          return jsonResponse(res, 404, { error: 'No Lightning Address to release' });
        }

        lnurlpDb.prepare('DELETE FROM pay_links WHERE id = ?').run(link.id);

        const mainDb = openDb(LNBITS_DB_PATH);
        try {
          mainDb.prepare('UPDATE accounts SET username = NULL WHERE id = ?').run(wallet.user);
        } finally {
          mainDb.close();
        }

        return jsonResponse(res, 200, { ok: true });
      } catch (e) {
        console.error(`[release-username] error:`, e.message);
        return jsonResponse(res, 500, { error: 'Failed to release Lightning Address' });
      } finally {
        lnurlpDb.close();
      }
    }

    // POST /api/v2/delete-account: the signer deletes their own hosted account.
    // The body names no account: the verified signer is the only identity used.
    if (req.method === 'POST' && parsedUrl.pathname === '/api/v2/delete-account') {
      const { confirm, acknowledgeBalance } = operationBody;
      // Validated before verification, like the other routes, so a malformed
      // request does not burn the caller's challenge.
      if (confirm !== DELETE_CONFIRMATION || typeof acknowledgeBalance !== 'boolean') {
        return jsonResponse(res, 400, { error: 'invalid_request' });
      }

      const verified = verifyOperation();
      if (!verified) return;

      if (_busyPubkeys.has(verified.pubkey)) {
        return jsonResponse(res, 409, { error: 'in_progress' });
      }
      _busyPubkeys.add(verified.pubkey);
      try {
        const result = await deleteAccount(verified.pubkey, acknowledgeBalance);
        return jsonResponse(res, result.status, result.body);
      } catch (e) {
        // Safe to retry: every step before the failing one is idempotent.
        console.error(`[delete-account] failed at ${e.step || 'unknown'}: ${e.message}`);
        return e.upstream
          ? jsonResponse(res, 502, { error: 'upstream_unavailable' })
          : jsonResponse(res, 500, { error: 'deletion_failed' });
      } finally {
        _busyPubkeys.delete(verified.pubkey);
      }
    }

    // Only proxy allowlisted LNURL paths (GET only), everything else is 404
    if (req.method === 'GET' && PROXY_ALLOWLIST.some(re => re.test(parsedUrl.pathname))) {
      if (!checkRateLimit(clientIp, 'lnurl')) {
        return jsonResponse(res, 429, { error: 'Too many requests' });
      }
      // Use parsedUrl.pathname (normalized) instead of raw req.url
      let proxyPath = parsedUrl.pathname + parsedUrl.search;
      // NIP-57 fix (issue #8): some clients double-URL-encode the `nostr` zap
      // request. LNbits decodes the query once, so the value is still
      // percent-encoded and lnurlp's send_zap() crashes on json.loads(),
      // never publishing the kind:9735 receipt (the invoice still settles).
      // If we detect a double-encoded `nostr`, rebuild the query with it
      // encoded exactly once. Correctly single-encoded clients are untouched.
      const nostrParam = parsedUrl.searchParams.get('nostr');
      if (nostrParam !== null && !nostrParam.trimStart().startsWith('{')) {
        let decoded = nostrParam;
        for (let i = 0; i < 4 && !decoded.trimStart().startsWith('{'); i++) {
          try {
            const next = decodeURIComponent(decoded);
            if (next === decoded) break;
            decoded = next;
          } catch (e) { break; }
        }
        if (decoded.trimStart().startsWith('{')) {
          parsedUrl.searchParams.set('nostr', decoded);
          proxyPath = parsedUrl.pathname + '?' + parsedUrl.searchParams.toString();
        }
      }
      proxyToLnbits(req, res, proxyPath);
      return;
    }

    // Wallet API proxy (requires X-Api-Key, each path limited to its own verbs)
    const walletRoute = WALLET_API_ALLOWLIST.find(e => e.pathname.test(parsedUrl.pathname));
    if (walletRoute && walletRoute.methods.includes(req.method)) {
      if (!checkRateLimit(clientIp, 'wallet')) {
        return jsonResponse(res, 429, { error: 'Too many requests' });
      }
      if (!req.headers['x-api-key']) {
        return jsonResponse(res, 401, { error: 'Missing X-Api-Key header' });
      }
      // LNbits also accepts ?api-key=<key>. Allowing it here would write wallet
      // keys into our logs and nginx's, so require the header form only.
      if (parsedUrl.searchParams.has('api-key')) {
        return jsonResponse(res, 400, { error: 'Pass the wallet key in the X-Api-Key header, not the query string' });
      }
      const proxyPath = parsedUrl.pathname + parsedUrl.search;
      try {
        if (req.method === 'POST') {
          const body = await readBody(req);
          proxyWalletApi(req, res, proxyPath, body);
        } else {
          proxyWalletApi(req, res, proxyPath, null);
        }
      } catch (e) {
        if (e.message === 'BODY_TOO_LARGE') return jsonResponse(res, 413, { error: 'Request body too large' });
        throw e;
      }
      return;
    }

    // GET /healthz — what an operator or an uptime check should look at.
    // Exercises the real dependencies rather than reporting that the process is
    // merely alive, which pm2 already claims even when every request 500s.
    if (req.method === 'GET' && parsedUrl.pathname === '/healthz') {
      const checks = {};
      let healthy = true;
      for (const [name, path] of [['lnbitsDb', LNBITS_DB_PATH], ['lnurlpDb', LNURLP_DB_PATH]]) {
        try {
          const db = openDb(path, { readOnly: true });
          try {
            db.prepare('SELECT 1').get();
            checks[name] = 'ok';
          } finally { db.close(); }
        } catch (e) {
          checks[name] = `error: ${e.message}`;
          healthy = false;
        }
      }
      checks.adminKey = LNBITS_ADMIN_KEY ? 'set' : 'missing';
      if (!LNBITS_ADMIN_KEY) healthy = false;
      try {
        const upstream = await fetch(`${LNBITS_URL}/api/v1/health`, {
          signal: AbortSignal.timeout(5_000),
        });
        checks.lnbits = upstream.ok ? 'ok' : `HTTP ${upstream.status}`;
        if (!upstream.ok) healthy = false;
      } catch (e) {
        checks.lnbits = `unreachable: ${e.message}`;
        healthy = false;
      }
      return jsonResponse(res, healthy ? 200 : 503, { ok: healthy, checks });
    }

    jsonResponse(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('[server] unhandled error:', e);
    if (!res.headersSent) {
      jsonResponse(res, 500, { error: 'Internal server error' });
    }
  }
});

// Fail at startup rather than reporting "online" while every request 500s.
const startupProblems = [];
if (!LNBITS_ADMIN_KEY) startupProblems.push('LNBITS_ADMIN_KEY is not set');
for (const [label, path] of [['LNBITS_DB_PATH', LNBITS_DB_PATH], ['LNURLP_DB_PATH', LNURLP_DB_PATH]]) {
  if (!existsSync(path)) startupProblems.push(`${label} does not exist: ${path}`);
}
try {
  openProvisionDb().close();
} catch (e) {
  startupProblems.push(`PROVISION_DB_PATH is not usable (${PROVISION_DB_PATH}): ${e.message}`);
}
if (startupProblems.length) {
  for (const problem of startupProblems) console.error(`[zaps-provision] FATAL: ${problem}`);
  console.error('[zaps-provision] refusing to start misconfigured');
  process.exit(1);
}

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[zaps-provision] listening on 127.0.0.1:${PORT}`);
});

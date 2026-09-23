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
 *   GET  /api/provision/challenge  - Generate a random challenge
 *   POST /api/provision            - Verify signed event, create or recover wallet
 *   POST /api/claim-username       - Claim a Lightning Address username
 *   GET  /api/lightning-address    - Look up Lightning Address by pubkey
 *   POST /api/release-username     - Release a claimed Lightning Address
 *
 * Proxied LNURL paths (GET-only, needed for LNURL callbacks):
 *   GET /.well-known/lnurlp/:username
 *   GET /lnurlp/api/v1/lnurl/cb/:id
 *
 * Proxied wallet API paths (requires X-Api-Key, used by extension):
 *   GET/POST /api/v1/wallet
 *   GET/POST /api/v1/payments
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
import { verifyEvent } from 'nostr-tools/pure';

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
const CHALLENGE_TTL_MS = 60_000; // 60 seconds
const CHALLENGE_MAX = 10_000;
const EVENT_MAX_AGE_S = 60;      // 60 seconds
const DOMAIN = 'zaps.nostr-wot.com';
const BASE_URL = `https://${DOMAIN}`;
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
      )
    `);
  } catch (e) {
    db.close();
    throw e;
  }
  return db;
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

// Wallet API paths that require X-Api-Key authentication (used by extension)
const WALLET_API_ALLOWLIST = [
  /^\/api\/v1\/wallet$/,
  /^\/api\/v1\/payments$/,
];

// ── Per-IP rate limiting ──

const rateLimitBuckets = {
  nwc:        { maxPerMin: 60, entries: new Map() },
  challenge:  { maxPerMin: 10, entries: new Map() },
  provision:  { maxPerMin: 5,  entries: new Map() },
  claim:      { maxPerMin: 3,  entries: new Map() },
  release:    { maxPerMin: 3,  entries: new Map() },
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

// In-memory challenge store: challenge -> timestamp
const challenges = new Map();

// Cleanup expired challenges every 30s
const _chCleanup = setInterval(() => {
  const now = Date.now();
  for (const [ch, ts] of challenges) {
    if (now - ts > CHALLENGE_TTL_MS) challenges.delete(ch);
  }
}, 30_000);
_chCleanup.unref();

// In-memory mutex sets to prevent race conditions on provisioning/claiming
const _provisioningPubkeys = new Set();
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
      if (!tooLarge) resolve(Buffer.concat(chunks).toString());
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
 * Verify a NIP-98 kind:27235 event from a request body.
 * Validates signature FIRST, then consumes challenge (prevents challenge-burning DoS).
 * Returns the verified event or sends an error response and returns null.
 */
function verifyNip98Event(event, res, expectedUrl, expectedMethod) {
  if (!event || typeof event !== 'object') {
    jsonResponse(res, 400, { error: 'Missing or invalid "event" field' });
    return null;
  }
  if (event.kind !== 27235) {
    jsonResponse(res, 400, { error: `Invalid event kind: expected 27235, got ${event.kind}` });
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - event.created_at) > EVENT_MAX_AGE_S) {
    jsonResponse(res, 400, { error: 'Event expired or created_at too far from current time' });
    return null;
  }

  // Malformed tags must not reach t[0] and throw a 500 out of the handler
  if (!Array.isArray(event.tags)) {
    jsonResponse(res, 400, { error: 'Invalid event tags' });
    return null;
  }
  const tags = event.tags.filter((t) => Array.isArray(t));

  // Validate 'u' tag matches expected URL
  const uTag = tags.find((t) => t[0] === 'u');
  if (!uTag || uTag[1] !== expectedUrl) {
    jsonResponse(res, 400, { error: 'Invalid or missing "u" tag in event' });
    return null;
  }

  // Validate 'method' tag matches expected HTTP method
  const methodTag = tags.find((t) => t[0] === 'method');
  if (!methodTag || methodTag[1] !== expectedMethod) {
    jsonResponse(res, 400, { error: 'Invalid or missing "method" tag in event' });
    return null;
  }

  const challengeTag = tags.find((t) => t[0] === 'challenge');
  if (!challengeTag || !challengeTag[1]) {
    jsonResponse(res, 400, { error: 'Missing challenge tag in event' });
    return null;
  }
  const challenge = challengeTag[1];
  // Check age here rather than relying on the 30s sweeper, which otherwise let
  // a challenge stay usable for up to ~90s.
  const issuedAt = challenges.get(challenge);
  if (issuedAt === undefined || Date.now() - issuedAt > CHALLENGE_TTL_MS) {
    challenges.delete(challenge);
    jsonResponse(res, 400, { error: 'Invalid or expired challenge' });
    return null;
  }

  // H1: Verify signature BEFORE consuming the challenge
  let valid;
  try {
    valid = verifyEvent(event);
  } catch (e) {
    jsonResponse(res, 400, { error: 'Signature verification error' });
    return null;
  }
  if (!valid) {
    jsonResponse(res, 403, { error: 'Invalid event signature' });
    return null;
  }

  // M5: Validate pubkey format
  if (!PUBKEY_RE.test(event.pubkey)) {
    jsonResponse(res, 400, { error: 'Invalid pubkey format' });
    return null;
  }

  // Only consume challenge after all validation passes
  challenges.delete(challenge);
  return event;
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
 * only here, only after verifyNip98Event has checked a signature from this
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

// ── Request handler ──

const server = createServer(async (req, res) => {
  try {
    const clientIp = getClientIp(req);

    // CORS preflight — scope to LNURL proxy paths only
    if (req.method === 'OPTIONS') {
      const parsedCheck = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      const isLnurlPath = PROXY_ALLOWLIST.some(re => re.test(parsedCheck.pathname));
      if (isLnurlPath) {
        res.writeHead(204, { ...LNURL_CORS_HEADERS, 'Access-Control-Max-Age': '86400' });
      } else {
        res.writeHead(204);
      }
      return res.end();
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (parsedUrl.pathname === '/api/nwc/connections' || parsedUrl.pathname.startsWith('/api/nwc/connections/')) {
      if (!checkRateLimit(clientIp, 'nwc')) return jsonResponse(res, 429, { error: 'Too many requests' });
      if (await nwcRoutes(req, res, parsedUrl)) return;
    }

    // GET /api/provision/challenge
    if (req.method === 'GET' && parsedUrl.pathname === '/api/provision/challenge') {
      if (!checkRateLimit(clientIp, 'challenge')) {
        return jsonResponse(res, 429, { error: 'Too many requests' });
      }
      if (challenges.size >= CHALLENGE_MAX) {
        return jsonResponse(res, 503, { error: 'Server busy, try again later' });
      }
      const challenge = randomBytes(32).toString('hex');
      challenges.set(challenge, Date.now());
      return jsonResponse(res, 200, { challenge });
    }

    // POST /api/provision
    if (req.method === 'POST' && parsedUrl.pathname === '/api/provision') {
      if (!checkRateLimit(clientIp, 'provision')) {
        return jsonResponse(res, 429, { error: 'Too many requests' });
      }
      if (!LNBITS_ADMIN_KEY) {
        return jsonResponse(res, 500, { error: 'Server not configured: missing LNBITS_ADMIN_KEY' });
      }

      let body;
      try {
        const raw = await readBody(req);
        body = JSON.parse(raw);
      } catch (e) {
        if (e.message === 'BODY_TOO_LARGE') return jsonResponse(res, 413, { error: 'Request body too large' });
        return jsonResponse(res, 400, { error: 'Invalid JSON body' });
      }

      const { name, event } = body;
      if (!name || typeof name !== 'string') {
        return jsonResponse(res, 400, { error: 'Missing or invalid "name" field' });
      }

      const sanitizedName = sanitizeString(name).slice(0, WALLET_NAME_MAX);
      if (!sanitizedName) {
        return jsonResponse(res, 400, { error: 'Invalid wallet name' });
      }

      const verified = verifyNip98Event(event, res, `${BASE_URL}/api/provision`, 'POST');
      if (!verified) return;

      // C2: Mutex to prevent duplicate wallet provisioning for the same pubkey
      if (_provisioningPubkeys.has(verified.pubkey)) {
        return jsonResponse(res, 409, { error: 'Provisioning already in progress for this pubkey' });
      }
      _provisioningPubkeys.add(verified.pubkey);
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
            `pubkey=${verified.pubkey} — created but not linked: ${e.message}`
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
        _provisioningPubkeys.delete(verified.pubkey);
      }
    }

    // POST /api/claim-username — Claim a Lightning Address
    if (req.method === 'POST' && parsedUrl.pathname === '/api/claim-username') {
      if (!checkRateLimit(clientIp, 'claim')) {
        return jsonResponse(res, 429, { error: 'Too many requests' });
      }

      let body;
      try {
        const raw = await readBody(req);
        body = JSON.parse(raw);
      } catch (e) {
        if (e.message === 'BODY_TOO_LARGE') return jsonResponse(res, 413, { error: 'Request body too large' });
        return jsonResponse(res, 400, { error: 'Invalid JSON body' });
      }

      const { event, username } = body;
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

      const verified = verifyNip98Event(event, res, `${BASE_URL}/api/claim-username`, 'POST');
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

    // POST /api/release-username
    if (req.method === 'POST' && parsedUrl.pathname === '/api/release-username') {
      if (!checkRateLimit(clientIp, 'release')) {
        return jsonResponse(res, 429, { error: 'Too many requests' });
      }

      let body;
      try {
        const raw = await readBody(req);
        body = JSON.parse(raw);
      } catch (e) {
        if (e.message === 'BODY_TOO_LARGE') return jsonResponse(res, 413, { error: 'Request body too large' });
        return jsonResponse(res, 400, { error: 'Invalid JSON body' });
      }

      const verified = verifyNip98Event(body.event, res, `${BASE_URL}/api/release-username`, 'POST');
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

    // Wallet API proxy (requires X-Api-Key, supports GET/POST)
    if ((req.method === 'GET' || req.method === 'POST') &&
        WALLET_API_ALLOWLIST.some(re => re.test(parsedUrl.pathname))) {
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

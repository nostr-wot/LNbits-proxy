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
 * Environment variables:
 *   LNBITS_URL       - LNbits backend URL (default: http://127.0.0.1:5000)
 *   LNBITS_ADMIN_KEY - LNbits super-user API key for wallet creation
 *   LNBITS_DB_PATH   - Path to LNbits SQLite database
 *   LNURLP_DB_PATH   - Path to LNbits lnurlp extension database
 *   PORT             - Listen port (default: 3003)
 */

import { createServer, request as httpRequest } from 'node:http';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { verifyEvent } from 'nostr-tools/pure';

const LNBITS_URL = process.env.LNBITS_URL || 'http://127.0.0.1:5000';
const LNBITS_ADMIN_KEY = process.env.LNBITS_ADMIN_KEY;
const LNBITS_DB_PATH = process.env.LNBITS_DB_PATH || '/home/lnbits/lnbits/data/database.sqlite3';
const LNURLP_DB_PATH = process.env.LNURLP_DB_PATH || '/home/lnbits/lnbits/data/ext_lnurlp.sqlite3';
const PORT = parseInt(process.env.PORT || '3003', 10);
const CHALLENGE_TTL_MS = 60_000; // 60 seconds
const CHALLENGE_MAX = 10_000;
const EVENT_MAX_AGE_S = 60;      // 60 seconds
const DOMAIN = 'zaps.nostr-wot.com';
const BASE_URL = `https://${DOMAIN}`;
const MAX_BODY_BYTES = 65_536;   // 64KB body limit
const WALLET_NAME_MAX = 50;
const PUBKEY_RE = /^[0-9a-f]{64}$/;

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

// ── Per-IP rate limiting ──

const rateLimitBuckets = {
  challenge:  { maxPerMin: 10, entries: new Map() },
  provision:  { maxPerMin: 5,  entries: new Map() },
  claim:      { maxPerMin: 3,  entries: new Map() },
  release:    { maxPerMin: 3,  entries: new Map() },
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

/** Read body with size limit */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        req.destroy();
        reject(new Error('BODY_TOO_LARGE'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
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

  // Validate 'u' tag matches expected URL
  const uTag = event.tags?.find((t) => t[0] === 'u');
  if (!uTag || uTag[1] !== expectedUrl) {
    jsonResponse(res, 400, { error: 'Invalid or missing "u" tag in event' });
    return null;
  }

  // Validate 'method' tag matches expected HTTP method
  const methodTag = event.tags?.find((t) => t[0] === 'method');
  if (!methodTag || methodTag[1] !== expectedMethod) {
    jsonResponse(res, 400, { error: 'Invalid or missing "method" tag in event' });
    return null;
  }

  const challengeTag = event.tags?.find((t) => t[0] === 'challenge');
  if (!challengeTag || !challengeTag[1]) {
    jsonResponse(res, 400, { error: 'Missing challenge tag in event' });
    return null;
  }
  const challenge = challengeTag[1];
  if (!challenges.has(challenge)) {
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
      'host': url.host,
      'x-forwarded-proto': 'https',
      'x-forwarded-host': DOMAIN,
    },
  };

  console.log(`[proxy] GET ${proxiedPath}`);

  const proxy = httpRequest(opts, (proxyRes) => {
    const headers = { ...proxyRes.headers, ...LNURL_CORS_HEADERS };
    clientRes.writeHead(proxyRes.statusCode, headers);
    proxyRes.pipe(clientRes, { end: true });
  });

  proxy.on('error', (err) => {
    console.error('[proxy] LNbits error:', err.message);
    clientRes.writeHead(502, { 'Content-Type': 'application/json', ...LNURL_CORS_HEADERS });
    clientRes.end(JSON.stringify({ error: 'LNbits backend unavailable' }));
  });

  // LNURL callbacks are GET-only, no body to pipe
  proxy.end();
}

/**
 * Look up an existing wallet for a Nostr pubkey in the LNbits database.
 * Returns { id, adminkey, name, user, ... } or null if not found.
 */
function findWalletByPubkey(pubkey) {
  const db = new DatabaseSync(LNBITS_DB_PATH, { readOnly: true });
  try {
    const row = db.prepare(`
      SELECT w.id, w.name, w.adminkey, w.inkey, w."user"
      FROM accounts a
      JOIN wallets w ON w."user" = a.id
      WHERE a.pubkey = ?
        AND w.deleted = 0
      ORDER BY w.created_at ASC
      LIMIT 1
    `).get(pubkey);
    return row || null;
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
 * Set username and Nostr pubkey on the LNbits user account.
 */
function updateLnbitsUser(userId, pubkey, username) {
  const db = new DatabaseSync(LNBITS_DB_PATH);
  try {
    db.prepare(`UPDATE accounts SET pubkey = ?, username = ? WHERE id = ?`).run(pubkey, username, userId);
    console.log(`[provision] updated user ${userId}: pubkey=${pubkey.slice(0, 16)}...`);
  } catch (e) {
    console.error(`[provision] failed to update user ${userId}:`, e.message);
  } finally {
    db.close();
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
        const username = sanitizedName.replace(/^WoT:/, '').slice(0, 20);
        updateLnbitsUser(wallet.user, verified.pubkey, username);
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

      const lnurlpDb = new DatabaseSync(LNURLP_DB_PATH);
      try {
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
          '', '', '', '', 0, '', '', sanitizedUsername, 1, DOMAIN, now, now, 0
        );

        // Update account username
        const mainDb = new DatabaseSync(LNBITS_DB_PATH);
        try {
          mainDb.prepare('UPDATE accounts SET username = ? WHERE id = ?').run(sanitizedUsername, wallet.user);
        } finally {
          mainDb.close();
        }

        return jsonResponse(res, 200, { address: `${sanitizedUsername}@${DOMAIN}`, payLinkId });
      } catch (e) {
        console.error(`[claim-username] error:`, e.message);
        return jsonResponse(res, 500, { error: 'Failed to create Lightning Address' });
      } finally {
        lnurlpDb.close();
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

      const lnurlpDb = new DatabaseSync(LNURLP_DB_PATH, { readOnly: true });
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

      const lnurlpDb = new DatabaseSync(LNURLP_DB_PATH);
      try {
        const link = lnurlpDb.prepare('SELECT id, username FROM pay_links WHERE wallet = ?').get(wallet.id);
        if (!link) {
          return jsonResponse(res, 404, { error: 'No Lightning Address to release' });
        }

        lnurlpDb.prepare('DELETE FROM pay_links WHERE id = ?').run(link.id);

        const mainDb = new DatabaseSync(LNBITS_DB_PATH);
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
      // Use parsedUrl.pathname (normalized) instead of raw req.url
      const proxyPath = parsedUrl.pathname + parsedUrl.search;
      proxyToLnbits(req, res, proxyPath);
      return;
    }

    jsonResponse(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('[server] unhandled error:', e);
    if (!res.headersSent) {
      jsonResponse(res, 500, { error: 'Internal server error' });
    }
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[zaps-provision] listening on 127.0.0.1:${PORT}`);
  if (!LNBITS_ADMIN_KEY) {
    console.warn('[zaps-provision] WARNING: LNBITS_ADMIN_KEY not set — provisioning will fail');
  }
});

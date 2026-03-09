/**
 * Provisioning proxy for zaps.nostr-wot.com
 *
 * Sits in front of LNbits. Handles challenge-response wallet provisioning.
 * All other requests are proxied through to LNbits.
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
const EVENT_MAX_AGE_S = 60;      // 60 seconds
const DOMAIN = 'zaps.nostr-wot.com';

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{1,28}[a-z0-9]$/;
const RESERVED_USERNAMES = new Set([
  'admin', 'support', 'help', 'info', 'noreply', 'postmaster',
  'webmaster', 'abuse', 'root', 'system',
]);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Api-Key, Authorization',
};

// In-memory challenge store: challenge -> timestamp
const challenges = new Map();

// Cleanup expired challenges every 30s
setInterval(() => {
  const now = Date.now();
  for (const [ch, ts] of challenges) {
    if (now - ts > CHALLENGE_TTL_MS) challenges.delete(ch);
  }
}, 30_000);

// ── Helpers ──

function jsonResponse(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    ...CORS_HEADERS,
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

/**
 * Verify a NIP-98 kind:27235 event from a request body.
 * Returns the verified event or sends an error response and returns null.
 */
function verifyNip98Event(event, res) {
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
  challenges.delete(challenge);
  let valid;
  try {
    valid = verifyEvent(event);
  } catch (e) {
    jsonResponse(res, 400, { error: `Signature verification error: ${e.message}` });
    return null;
  }
  if (!valid) {
    jsonResponse(res, 403, { error: 'Invalid event signature' });
    return null;
  }
  return event;
}

/**
 * Proxy a request to LNbits backend.
 * Injects CORS headers into the proxied response.
 */
function proxyToLnbits(clientReq, clientRes) {
  const url = new URL(LNBITS_URL);
  const opts = {
    hostname: url.hostname,
    port: url.port || 80,
    path: clientReq.url,
    method: clientReq.method,
    headers: { ...clientReq.headers, host: url.host },
  };

  console.log(`[proxy] ${clientReq.method} ${clientReq.url}`);

  const proxy = httpRequest(opts, (proxyRes) => {
    // Merge CORS headers into proxied response
    const headers = { ...proxyRes.headers, ...CORS_HEADERS };
    clientRes.writeHead(proxyRes.statusCode, headers);
    proxyRes.pipe(clientRes, { end: true });

    console.log(`[proxy] ${clientReq.method} ${clientReq.url} → ${proxyRes.statusCode}`);
  });

  proxy.on('error', (err) => {
    console.error('[proxy] LNbits error:', err.message);
    jsonResponse(clientRes, 502, { error: 'LNbits backend unavailable' });
  });

  clientReq.pipe(proxy, { end: true });
}

/**
 * Look up an existing wallet for a Nostr pubkey in the LNbits database.
 * Returns { id, adminkey, name, user, ... } or null if not found.
 */
function findWalletByPubkey(pubkey) {
  try {
    const db = new DatabaseSync(LNBITS_DB_PATH, { readOnly: true });
    const row = db.prepare(`
      SELECT w.id, w.name, w.adminkey, w.inkey, w."user"
      FROM accounts a
      JOIN wallets w ON w."user" = a.id
      WHERE a.pubkey = ?
        AND w.deleted = 0
      ORDER BY w.created_at ASC
      LIMIT 1
    `).get(pubkey);
    db.close();
    return row || null;
  } catch (e) {
    console.error('[provision] SQLite lookup error:', e.message);
    throw new Error('Database lookup failed');
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
    throw new Error(`LNbits wallet creation failed (${res.status}): ${text}`);
  }
  return res.json();
}

/**
 * Set username and Nostr pubkey on the LNbits user account.
 * Writes directly to the SQLite database since the Users Manager API
 * requires auth tokens that the wallet admin key cannot provide.
 */
function updateLnbitsUser(userId, pubkey, username) {
  try {
    const db = new DatabaseSync(LNBITS_DB_PATH);
    db.prepare(`UPDATE accounts SET pubkey = ?, username = ? WHERE id = ?`).run(pubkey, username, userId);
    db.close();
    console.log(`[provision] updated user ${userId}: username=${username} pubkey=${pubkey.slice(0, 16)}...`);
  } catch (e) {
    console.error(`[provision] failed to update user ${userId}:`, e.message);
  }
}

// ── Request handler ──

const server = createServer(async (req, res) => {
  // CORS preflight — allow X-Api-Key and other headers for all paths
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      ...CORS_HEADERS,
      'Access-Control-Max-Age': '86400',
    });
    return res.end();
  }

  // Parse URL for query params
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // GET /api/provision/challenge
  if (req.method === 'GET' && parsedUrl.pathname === '/api/provision/challenge') {
    const challenge = randomBytes(32).toString('hex');
    challenges.set(challenge, Date.now());
    console.log(`[challenge] issued: ${challenge.slice(0, 16)}...`);
    return jsonResponse(res, 200, { challenge });
  }

  // POST /api/provision
  if (req.method === 'POST' && parsedUrl.pathname === '/api/provision') {
    if (!LNBITS_ADMIN_KEY) {
      return jsonResponse(res, 500, { error: 'Server not configured: missing LNBITS_ADMIN_KEY' });
    }

    let body;
    try {
      const raw = await readBody(req);
      body = JSON.parse(raw);
    } catch {
      return jsonResponse(res, 400, { error: 'Invalid JSON body' });
    }

    const { name, event } = body;
    if (!name || typeof name !== 'string') {
      return jsonResponse(res, 400, { error: 'Missing or invalid "name" field' });
    }

    const verified = verifyNip98Event(event, res);
    if (!verified) return;

    console.log(`[provision] verified pubkey: ${verified.pubkey.slice(0, 16)}... wallet: ${name}`);

    // Check if this pubkey already has a wallet
    const existing = findWalletByPubkey(verified.pubkey);
    if (existing) {
      console.log(`[provision] recovered existing wallet: ${existing.id} for ${verified.pubkey.slice(0, 16)}...`);
      return jsonResponse(res, 200, existing);
    }

    // Create new wallet via LNbits
    try {
      const wallet = await createLnbitsWallet(name);
      console.log(`[provision] created wallet: ${wallet.id} for ${verified.pubkey.slice(0, 16)}...`);

      // Set username (npub prefix) and pubkey on the new LNbits user account
      const username = name.replace(/^WoT:/, '').slice(0, 20);
      await updateLnbitsUser(wallet.user, verified.pubkey, username);

      return jsonResponse(res, 201, wallet);
    } catch (e) {
      console.error(`[provision] LNbits error: ${e.message}`);
      return jsonResponse(res, 502, { error: 'Failed to create wallet on LNbits backend' });
    }
  }

  // POST /api/claim-username — Claim a Lightning Address
  if (req.method === 'POST' && parsedUrl.pathname === '/api/claim-username') {
    let body;
    try {
      const raw = await readBody(req);
      body = JSON.parse(raw);
    } catch {
      return jsonResponse(res, 400, { error: 'Invalid JSON body' });
    }

    const { event, username } = body;
    if (!username || typeof username !== 'string') {
      return jsonResponse(res, 400, { error: 'Missing or invalid "username" field' });
    }

    // Validate username
    if (!USERNAME_RE.test(username)) {
      return jsonResponse(res, 400, { error: '3-30 characters, lowercase letters, numbers, dots, hyphens, underscores. Must start and end with alphanumeric.' });
    }
    if (RESERVED_USERNAMES.has(username)) {
      return jsonResponse(res, 400, { error: 'This username is reserved' });
    }

    const verified = verifyNip98Event(event, res);
    if (!verified) return;

    console.log(`[claim-username] verified pubkey: ${verified.pubkey.slice(0, 16)}... username: ${username}`);

    // Look up user's wallet
    const wallet = findWalletByPubkey(verified.pubkey);
    if (!wallet) {
      return jsonResponse(res, 404, { error: 'No wallet found for this pubkey. Provision a wallet first.' });
    }

    try {
      const lnurlpDb = new DatabaseSync(LNURLP_DB_PATH);

      // Check if username is already taken
      const existing = lnurlpDb.prepare('SELECT id FROM pay_links WHERE username = ?').get(username);
      if (existing) {
        lnurlpDb.close();
        return jsonResponse(res, 409, { error: 'This username is already taken' });
      }

      // Check if this wallet already has a pay link
      const walletLink = lnurlpDb.prepare('SELECT id, username FROM pay_links WHERE wallet = ?').get(wallet.id);
      if (walletLink) {
        lnurlpDb.close();
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
        '', '', '', '', 0, '', '', username, 1, DOMAIN, now, now, 0
      );
      lnurlpDb.close();

      // Update account username
      const mainDb = new DatabaseSync(LNBITS_DB_PATH);
      mainDb.prepare('UPDATE accounts SET username = ? WHERE id = ?').run(username, wallet.user);
      mainDb.close();

      console.log(`[claim-username] created pay link ${payLinkId} for ${username}@${DOMAIN}`);
      return jsonResponse(res, 200, { address: `${username}@${DOMAIN}`, payLinkId });
    } catch (e) {
      console.error(`[claim-username] error:`, e.message);
      return jsonResponse(res, 500, { error: 'Failed to create Lightning Address' });
    }
  }

  // GET /api/lightning-address?pubkey=<hex> — Look up Lightning Address
  if (req.method === 'GET' && parsedUrl.pathname === '/api/lightning-address') {
    const pubkey = parsedUrl.searchParams.get('pubkey');
    if (!pubkey || typeof pubkey !== 'string' || !/^[0-9a-f]{64}$/.test(pubkey)) {
      return jsonResponse(res, 400, { error: 'Invalid or missing pubkey parameter' });
    }

    try {
      const wallet = findWalletByPubkey(pubkey);
      if (!wallet) {
        return jsonResponse(res, 200, { address: null });
      }

      const lnurlpDb = new DatabaseSync(LNURLP_DB_PATH, { readOnly: true });
      const link = lnurlpDb.prepare('SELECT username FROM pay_links WHERE wallet = ?').get(wallet.id);
      lnurlpDb.close();

      if (link && link.username) {
        return jsonResponse(res, 200, { address: `${link.username}@${DOMAIN}` });
      }
      return jsonResponse(res, 200, { address: null });
    } catch (e) {
      console.error(`[lightning-address] lookup error:`, e.message);
      return jsonResponse(res, 500, { error: 'Lookup failed' });
    }
  }

  // POST /api/release-username — Release a claimed Lightning Address
  if (req.method === 'POST' && parsedUrl.pathname === '/api/release-username') {
    let body;
    try {
      const raw = await readBody(req);
      body = JSON.parse(raw);
    } catch {
      return jsonResponse(res, 400, { error: 'Invalid JSON body' });
    }

    const verified = verifyNip98Event(body.event, res);
    if (!verified) return;

    console.log(`[release-username] verified pubkey: ${verified.pubkey.slice(0, 16)}...`);

    const wallet = findWalletByPubkey(verified.pubkey);
    if (!wallet) {
      return jsonResponse(res, 404, { error: 'No wallet found for this pubkey' });
    }

    try {
      const lnurlpDb = new DatabaseSync(LNURLP_DB_PATH);
      const link = lnurlpDb.prepare('SELECT id, username FROM pay_links WHERE wallet = ?').get(wallet.id);
      if (!link) {
        lnurlpDb.close();
        return jsonResponse(res, 404, { error: 'No Lightning Address to release' });
      }

      lnurlpDb.prepare('DELETE FROM pay_links WHERE id = ?').run(link.id);
      lnurlpDb.close();

      // Clear account username
      const mainDb = new DatabaseSync(LNBITS_DB_PATH);
      mainDb.prepare('UPDATE accounts SET username = NULL WHERE id = ?').run(wallet.user);
      mainDb.close();

      console.log(`[release-username] deleted pay link ${link.id} (${link.username}@${DOMAIN})`);
      return jsonResponse(res, 200, { ok: true });
    } catch (e) {
      console.error(`[release-username] error:`, e.message);
      return jsonResponse(res, 500, { error: 'Failed to release Lightning Address' });
    }
  }

  // Everything else: proxy to LNbits
  proxyToLnbits(req, res);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[zaps-provision] listening on 127.0.0.1:${PORT}`);
  console.log(`[zaps-provision] proxying to LNbits at ${LNBITS_URL}`);
  console.log(`[zaps-provision] LNbits DB: ${LNBITS_DB_PATH}`);
  console.log(`[zaps-provision] lnurlp DB: ${LNURLP_DB_PATH}`);
  if (!LNBITS_ADMIN_KEY) {
    console.warn('[zaps-provision] WARNING: LNBITS_ADMIN_KEY not set — provisioning will fail');
  }
});

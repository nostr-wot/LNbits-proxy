import { randomBytes } from 'node:crypto';

const token = () => randomBytes(32).toString('hex');
const requireValid = value => { if (!value) throw new Error('Invalid or expired terminal session'); };
// Invoice authenticity/expiry is checked by the payer before approval. This bound
// prevents the public mailbox accepting an amount outside its advertised range.
function amount(invoice) {
  requireValid(typeof invoice === 'string' && invoice.length <= 8000);
  const match = /^lnbc([0-9]+)([munp]?)1[02-9ac-hj-np-z]+$/i.exec(invoice);
  requireValid(match);
  const numerator = BigInt(match[1]) * ({ '': 100000000000000n, m: 100000000000n, u: 100000000n, n: 100000n, p: 100n }[match[2].toLowerCase()]);
  requireValid(numerator % 1000n === 0n);
  return numerator / 1000n;
}

/** Ephemeral invoice mailbox only. Never holds payment credentials or pays funds. */
export function createTerminalMailbox({ origin, now = Date.now, maxSessions = 1000 }) {
  requireValid(new URL(origin).protocol === 'https:' && new URL(origin).origin === origin);
  const sessions = new Map();
  const prune = () => { for (const [id, s] of sessions) if (s.expiresAt <= now()) sessions.delete(id); };
  const get = id => { prune(); const s = sessions.get(id); requireValid(s); return s; };
  const owner = (id, secret) => { const s = get(id); requireValid(typeof secret === 'string' && secret === s.owner); return s; };
  return {
    create(maxMsat) {
      prune();
      requireValid(Number.isSafeInteger(maxMsat) && maxMsat >= 1000 && maxMsat <= 100000000000 && sessions.size < maxSessions);
      const id = token(), s = { owner: token(), k1: token(), maxMsat, expiresAt: now() + 60000, invoice: null };
      sessions.set(id, s);
      return { url: `${origin}/api/terminal-nfc/${id}`, owner: s.owner, expiresAt: s.expiresAt };
    },
    discover(id) {
      const s = get(id);
      return { tag: 'withdrawRequest', callback: `${origin}/api/terminal-nfc/${id}/callback`, k1: s.k1, minWithdrawable: 1000, maxWithdrawable: s.maxMsat, defaultDescription: 'Nostr WoT terminal payment' };
    },
    submit(id, k1, invoice) {
      const s = get(id);
      requireValid(k1 === s.k1);
      const msat = amount(invoice);
      requireValid(msat >= 1000n && msat <= BigInt(s.maxMsat));
      requireValid(s.invoice === null || s.invoice === invoice);
      s.invoice = invoice;
      // LNURL OK acknowledges submission, never claims Lightning settlement.
      return { status: 'OK' };
    },
    poll(id, secret) { const s = owner(id, secret); return { invoice: s.invoice, expiresAt: s.expiresAt }; },
    remove(id, secret) { owner(id, secret); sessions.delete(id); return { status: 'OK' }; },
  };
}

export function terminalHandler({ mailbox, readBody, allow }) {
  return async (req, res, url, ip) => {
    if (!url.pathname.startsWith('/api/terminal-nfc')) return false;
    res.setHeader('Cache-Control', 'no-store');
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); return true; };
    if (!allow(ip, req.method === 'POST' ? 'terminalCreate' : 'terminal')) return send(429, { status: 'ERROR', reason: 'Too many requests' });
    try {
      if (req.method === 'POST' && url.pathname === '/api/terminal-nfc' && !url.search) {
        const body = JSON.parse(await readBody(req));
        requireValid(body && Object.keys(body).join(',') === 'maxMsat');
        return send(201, mailbox.create(body.maxMsat));
      }
      const match = /^\/api\/terminal-nfc\/([a-f0-9]{64})(\/callback|\/status)?$/.exec(url.pathname);
      requireValid(match);
      const [, id, action] = match;
      if (req.method === 'GET' && !action && !url.search) return send(200, mailbox.discover(id));
      if (req.method === 'GET' && action === '/callback') {
        requireValid(url.searchParams.getAll('k1').length === 1 && url.searchParams.getAll('pr').length === 1);
        return send(200, mailbox.submit(id, url.searchParams.get('k1'), url.searchParams.get('pr')));
      }
      const auth = req.headers.authorization;
      const secret = typeof auth === 'string' && /^Bearer [a-f0-9]{64}$/.test(auth) ? auth.slice(7) : '';
      if (req.method === 'GET' && action === '/status' && !url.search) return send(200, mailbox.poll(id, secret));
      if (req.method === 'DELETE' && !action && !url.search) return send(200, mailbox.remove(id, secret));
    } catch { return send(400, { status: 'ERROR', reason: 'Invalid or expired terminal session' }); }
    return send(405, { status: 'ERROR', reason: 'Unsupported request' });
  };
}

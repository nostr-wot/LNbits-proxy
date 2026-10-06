import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { verifyEvent } from 'nostr-tools/pure';

const HEX = /^[0-9a-f]{64}$/;
export const AUTH_PATHS = ['/api/v2/provision','/api/v2/claim-username','/api/v2/release-username','/api/v2/delete-account'];
export const CHALLENGE_PATH = '/api/v2/provision/challenge';
export const sha256 = value => createHash('sha256').update(value).digest('hex');
function requireValid(condition, message = 'Invalid authentication') {
  if (!condition) throw new Error(message);
}
export function publicOrigin(value) {
  const u = new URL(value);
  requireValid(u.protocol === 'https:' && u.origin === value, 'Expected an exact HTTPS public origin');
  return value;
}
export function allowedOrigins(value = '') {
  return new Set(value.split(',').map(v=>v.trim()).filter(Boolean).map(publicOrigin));
}
// This distinguishes protocol flows, not trusted clients. Native callers must
// still possess a signed event and the separate transaction token.
export function clientScope(origin, allowed) {
  if (origin === undefined || /^(chrome-extension|moz-extension|safari-web-extension):\/\/[a-zA-Z0-9-]+$/.test(origin)) return 'native';
  requireValid(typeof origin === 'string' && allowed.has(origin), 'Browser origin denied');
  return origin;
}
export function createAuth({dbPath, publicOrigin: origin, maxRows = 10_000, now = ()=>Math.floor(Date.now()/1000)}) {
  publicOrigin(origin);
  const urls = new Set(AUTH_PATHS.map(path=>origin+path));
  function open() {
    const db = new DatabaseSync(dbPath);
    db.exec('PRAGMA busy_timeout = 5000');
    db.exec(`CREATE TABLE IF NOT EXISTS auth_challenges_v2 (
      challenge TEXT PRIMARY KEY, url TEXT NOT NULL, method TEXT NOT NULL,
      payload TEXT NOT NULL, token_hash TEXT NOT NULL, scope TEXT NOT NULL, expires_at INTEGER NOT NULL
    ); CREATE INDEX IF NOT EXISTS auth_challenges_v2_expiry ON auth_challenges_v2(expires_at)`);
    return db;
  }
  open().close();
  return {
    issue(body, scope) {
      requireValid(body && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).sort().join(',') === 'method,payload,url');
      requireValid(urls.has(body.url) && body.method === 'POST' && HEX.test(body.payload));
      const challenge=randomBytes(32).toString('hex');
      const transactionToken=randomBytes(32).toString('hex');
      const expiresAt=now()+60;
      const db=open();
      try {
        db.exec('BEGIN IMMEDIATE');
        db.prepare('DELETE FROM auth_challenges_v2 WHERE expires_at <= ?').run(now());
        requireValid(db.prepare('SELECT COUNT(*) AS n FROM auth_challenges_v2').get().n < maxRows, 'Server busy, try again later');
        db.prepare('INSERT INTO auth_challenges_v2 VALUES (?,?,?,?,?,?,?)').run(challenge,body.url,body.method,body.payload,sha256(transactionToken),scope,expiresAt);
        db.exec('COMMIT');
      } catch(e) { if(db.isTransaction) db.exec('ROLLBACK'); throw e; } finally { db.close(); }
      return {version:2,challenge,transactionToken,expiresAt};
    },
    verify({authorization, token, raw, url, scope}) {
      requireValid(urls.has(url) && typeof token === 'string' && HEX.test(token));
      requireValid(typeof authorization === 'string' && authorization.length < 16_384 && /^Nostr [A-Za-z0-9+/]+={0,2}$/.test(authorization));
      const encoded=authorization.slice(6);
      const decoded=Buffer.from(encoded,'base64');
      requireValid(decoded.toString('base64') === encoded);
      const event=JSON.parse(decoded.toString('utf8'));
      requireValid(event && event.kind===27235 && event.content==='' && Number.isSafeInteger(event.created_at) && Math.abs(now()-event.created_at)<=60 && HEX.test(event.pubkey));
      const expected = {u:url,method:'POST',payload:sha256(raw),transaction:sha256(token)};
      if(scope!=='native') expected['client-origin']=scope;
      requireValid(Array.isArray(event.tags) && event.tags.length===Object.keys(expected).length+1);
      const tags=new Map();
      for(const tag of event.tags) {
        requireValid(Array.isArray(tag) && tag.length===2 && tag.every(v=>typeof v==='string') && !tags.has(tag[0]));
        tags.set(tag[0],tag[1]);
      }
      for(const [key,value] of Object.entries(expected)) requireValid(tags.get(key)===value);
      const challenge=tags.get('challenge');
      requireValid(typeof challenge==='string' && HEX.test(challenge));
      requireValid(verifyEvent(event), 'Invalid signature');
      const db=open();
      try {
        // A single conditional DELETE is the cross-process authorization commit.
        // Invalid signatures, payloads, scopes or transactions cannot burn a row.
        const result=db.prepare(`DELETE FROM auth_challenges_v2 WHERE challenge=? AND url=? AND method='POST' AND payload=? AND token_hash=? AND scope=? AND expires_at>?`).run(challenge,url,expected.payload,expected.transaction,scope,now());
        requireValid(result.changes===1,'Invalid, expired or consumed challenge');
      } finally {db.close();}
      return event;
    },
  };
}

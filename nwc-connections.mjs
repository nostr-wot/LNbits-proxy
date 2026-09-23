/* global fetch, AbortSignal, URL */
/** Wallet-scoped NWC management for the zaps proxy. Never receives pairing secrets. */
import { DatabaseSync } from 'node:sqlite';
const keyPattern = /^[a-f0-9]{64}$/;
const basePath = '/api/nwc/connections';
const send = (res,status,value) => {
  res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});
  res.end(JSON.stringify(value));
};
export function createNwcRoutes({backend,dbPath,fetchFn=fetch}) {
  const upstream=async(key,path,method='GET',body)=>{
    const response=await fetchFn(`${backend}${path}`,{method,redirect:'error',signal:AbortSignal.timeout(15000),headers:{'X-Api-Key':key,'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
    if(!response.ok) {const e=new Error('LNbits rejected request');e.status=response.status;throw e;}
    // A non-JSON 2xx (an nginx error page, an empty body) is a backend fault, not
    // a client one. Without this it surfaced as a SyntaxError and was reported
    // to the caller as 400, so clients would not retry.
    try {return await response.json();}
    catch {const e=new Error('Invalid upstream response');e.status=502;throw e;}
  };
  const handle = async function nwcRoutes(req,res,url) {
    if(url.pathname!==basePath&&!url.pathname.startsWith(`${basePath}/`)) return false;
    try {
      const pubkey=url.pathname.slice(basePath.length+1);
      if(url.search || !((req.method==='GET'&&!pubkey&&url.pathname===basePath)||(['PUT','DELETE'].includes(req.method)&&keyPattern.test(pubkey)))) {
        send(res,404,{error:'Not found'});return true;
      }
      const key=req.headers['x-api-key'];
      if(typeof key!=='string'||key.length>256) {send(res,401,{error:'Wallet Admin API key required'});return true;}
      const db=new DatabaseSync(dbPath);
      // node:sqlite defaults to no busy timeout, so a concurrent LNbits write
      // makes the next statement throw SQLITE_BUSY immediately.
      db.exec('PRAGMA busy_timeout = 5000');
      let wallet;
      try {
        wallet=db.prepare('SELECT id,user FROM wallets WHERE adminkey=? AND deleted=0').get(key);
        if(!wallet) {send(res,403,{error:'Wallet Admin API key required'});return true;}
        // Preserve LNbits account restrictions; possession of an old key is not enough.
        await upstream(key,'/api/v1/wallet');
        const enabled=db.prepare("SELECT active FROM installed_extensions WHERE id='nwcprovider'").get();
        if(!enabled?.active) {send(res,503,{error:'NWC Provider is unavailable'});return true;}
        const userExtension=db.prepare("SELECT active FROM extensions WHERE user=? AND extension='nwcprovider'").get(wallet.user);
        if(req.method==='PUT') {
          // Collect Buffers and decode once: `body+=chunk` decoded each chunk
          // separately and corrupted any multi-byte character split across two.
          // Keep draining past the limit instead of breaking, because breaking
          // out of `for await` destroys the request before the 413 can be sent.
          const chunks=[];let size=0,tooLarge=false;
          for await(const chunk of req) {
            size+=chunk.length;
            if(size>4096){tooLarge=true;if(size>16384){req.destroy();break;}continue;}
            chunks.push(chunk);
          }
          if(tooLarge){send(res,413,{error:'Request too large'});return true;}
          const input=JSON.parse(Buffer.concat(chunks).toString());
          if(typeof input.name!=='string'||!input.name.trim()||input.name.trim().length>50||[...input.name].some(c=>c.charCodeAt(0)<32||c.charCodeAt(0)===127)
             ||!Number.isSafeInteger(input.dailyLimit)||input.dailyLimit<=0||input.dailyLimit>=10000000
             ||!Number.isSafeInteger(input.days)||input.days<1||input.days>365) {send(res,400,{error:'Invalid connection settings'});return true;}
          // Explicit user action enables this installed extension for their own LNbits account.
          db.prepare("INSERT INTO extensions (user,extension,active) VALUES (?,'nwcprovider',1) ON CONFLICT(user,extension) DO UPDATE SET active=1").run(wallet.user);
          const existing=await upstream(key,'/nwcprovider/api/v1/nwc');
          if(existing.some(row=>row.data.pubkey===pubkey)) {send(res,200,{ok:true});return true;}
          if(existing.length>=50) {send(res,409,{error:'Maximum active connections reached'});return true;}
          // Expired grants are hidden from the default listing but the provider
          // keys table has pubkey as PRIMARY KEY, so re-registering one would
          // fail the insert forever. Clear the stale row first; DELETE upstream
          // is wallet-scoped and idempotent.
          const all=await upstream(key,'/nwcprovider/api/v1/nwc?include_expired=true');
          if(all.some(row=>row.data.pubkey===pubkey)) await upstream(key,`/nwcprovider/api/v1/nwc/${pubkey}`,'DELETE');
          const now=Math.floor(Date.now()/1000);
          await upstream(key,`/nwcprovider/api/v1/nwc/${pubkey}`,'PUT',{
            description:input.name.trim(),expires_at:now+input.days*86400,permissions:['pay','lookup','info'],
            budgets:[{pubkey,budget_msats:input.dailyLimit*1000,refresh_window:86400,created_at:now}],
          });
          send(res,201,{ok:true});return true;
        }
        if(req.method==='DELETE') {
          if(userExtension?.active) await upstream(key,`/nwcprovider/api/v1/nwc/${pubkey}`,'DELETE');
          else {send(res,409,{error:'Enable NWC Provider before managing existing connections'});return true;}
          send(res,200,{ok:true});return true;
        }
        const connections=userExtension?.active ? await upstream(key,'/nwcprovider/api/v1/nwc?calculate_spent_budget=true') : [];
        // Dummy secret only: no user's pairing secret is transmitted in a URL or server log.
        const pairing=await upstream(key,`/nwcprovider/api/v1/pairing/${'0'.repeat(64)}`);
        const uri=new URL(pairing);
        const relay=uri.searchParams.get('relay');
        if(uri.protocol!=='nostr+walletconnect:'||!keyPattern.test(uri.hostname)||!relay||new URL(relay).protocol!=='wss:') throw new Error('Invalid provider configuration');
        send(res,200,{connections,provider:{pubkey:uri.hostname,relay}});return true;
      } finally {db.close();}
    } catch(e) {
      // Never return upstream exception text (could contain credentials or payloads).
      // Log enough to diagnose a wave of 502s without recording the key or body.
      console.error(`[nwc] ${req.method} ${url.pathname} status=${e.status??'-'} ${e.message}`);
      send(res,e instanceof SyntaxError?400:(e.status===401||e.status===403?e.status:502),{error:'Unable to manage NWC connections. Refresh before trying again.'});
      return true;
    }
  };
  const mutations=new Map();
  return async(req,res,url)=>{
    if(!['PUT','DELETE'].includes(req.method)) return handle(req,res,url);
    const key=req.headers['x-api-key'];
    const previous=mutations.get(key) || Promise.resolve();
    const current=previous.catch(()=>{}).then(()=>handle(req,res,url));
    mutations.set(key,current);
    try {return await current;} finally {if(mutations.get(key)===current)mutations.delete(key);}
  };
}

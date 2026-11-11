import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {createServer as httpServer} from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {finalizeEvent,generateSecretKey,getPublicKey} from 'nostr-tools/pure';
import {sha256} from '../auth-v2.mjs';

test('HTTP v2 boundary rejects legacy, mutation, query, origin, replay; recovers only signed wallet',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'auth-route-'));
  const dbPath=join(dir,'lnbits.db'),mapping=join(dir,'mapping.db');
  const key=generateSecretKey(), pubkey=getPublicKey(key);
  let db=new DatabaseSync(dbPath);
  db.exec(`CREATE TABLE wallets(id TEXT,name TEXT,adminkey TEXT,inkey TEXT,"user" TEXT,deleted INTEGER);
    CREATE TABLE accounts(id TEXT PRIMARY KEY, username TEXT);
    INSERT INTO accounts VALUES ('user',NULL);
    CREATE TABLE pay_links(id TEXT, wallet TEXT, description TEXT, min INTEGER, max INTEGER, served_meta INTEGER, served_pr INTEGER,
      webhook_url TEXT,success_text TEXT,success_url TEXT,currency TEXT,comment_chars INTEGER,webhook_headers TEXT,webhook_body TEXT,
      username TEXT,zaps INTEGER,domain TEXT,created_at REAL,updated_at REAL,disposable INTEGER);`);
  db.prepare('INSERT INTO wallets VALUES(?,?,?,?,?,0)').run('wallet','test','test-admin','test-invoice','user');db.close();
  db=new DatabaseSync(mapping);db.exec('CREATE TABLE provisioned(pubkey TEXT PRIMARY KEY,user_id TEXT,wallet_id TEXT,created_at REAL)');
  db.prepare('INSERT INTO provisioned VALUES(?,?,?,0)').run(pubkey,'user','wallet');db.close();
  const socket=createServer();await new Promise(resolve=>socket.listen(0,'127.0.0.1',resolve));
  const port=socket.address().port;await new Promise(resolve=>socket.close(resolve));
  let created=0;
  const admin=httpServer(async(req,res)=>{
    assert.equal(req.url,'/users/api/v1/user'); assert.equal(req.headers.authorization,'Bearer test-only');
    assert.equal(req.headers['x-api-key'],undefined);
    let raw='';for await(const c of req)raw+=c;assert.deepEqual(JSON.parse(raw),{});
    const c=new DatabaseSync(dbPath);
    c.prepare('INSERT INTO wallets VALUES (?,?,?,?,?,0)').run('a'.repeat(32),'initial','b'.repeat(32),'c'.repeat(32),'d'.repeat(32));c.close();created++;
    res.end(JSON.stringify({id:'d'.repeat(32),password:'internal-only'}));
  });
  await new Promise(r=>admin.listen(0,'127.0.0.1',r));t.after(()=>admin.close());
  const child=spawn(process.execPath,['server.js'],{cwd:new URL('..',import.meta.url),env:{...process.env,PORT:String(port),LNBITS_URL:'http://127.0.0.1:'+admin.address().port,PUBLIC_ORIGIN:'https://wallet.test',BROWSER_ORIGINS:'https://client.test',LNBITS_PROVISION_TOKEN:'test-only',LNBITS_DB_PATH:dbPath,LNURLP_DB_PATH:dbPath,PROVISION_DB_PATH:mapping},stdio:['ignore','pipe','pipe']});
  t.after(async()=>{child.kill();await new Promise(resolve=>child.once('exit',resolve));rmSync(dir,{recursive:true,force:true});});
  await new Promise((resolve,reject)=>{child.stdout.on('data',chunk=>{if(chunk.toString().includes('listening'))resolve();});child.once('exit',code=>reject(new Error('startup '+code)));});
  const local=`http://127.0.0.1:${port}`;
  const call=(path,body,headers={})=>fetch(local+path,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(body)});
  assert.equal((await call('/api/provision',{})).status,426);
  assert.equal((await fetch(local+'/api/provision/challenge')).status,426);
  const raw=JSON.stringify({name:'wallet'}), url='https://wallet.test/api/v2/provision';
  const challengeBody={url,method:'POST',payload:sha256(raw)};
  assert.equal((await call('/api/v2/provision/challenge',challengeBody,{Origin:'https://evil.test'})).status,403);
  assert.equal((await call('/api/v2/provision/challenge?x=1',challengeBody)).status,400);
  const issued=await (await call('/api/v2/provision/challenge',challengeBody)).json();
  assert.equal(issued.version,2);
  const event=finalizeEvent({kind:27235,created_at:Math.floor(Date.now()/1000),content:'',tags:[['u',url],['method','POST'],['payload',sha256(raw)],['challenge',issued.challenge],['transaction',sha256(issued.transactionToken)]]},key);
  const headers={Authorization:'Nostr '+Buffer.from(JSON.stringify(event)).toString('base64'),'X-Nostr-Transaction':issued.transactionToken};
  assert.equal((await call('/api/v2/provision',{name:'evil'},headers)).status,403);
  assert.equal((await call('/api/v2/provision?x=1',{name:'wallet'},headers)).status,400);
  const accepted=await call('/api/v2/provision',{name:'wallet'},headers);
  assert.equal(accepted.status,200);assert.equal((await accepted.json()).id,'wallet');
  assert.equal((await call('/api/v2/provision',{name:'wallet'},headers)).status,403);
  const browserChallenge=await (await call('/api/v2/provision/challenge',challengeBody,{Origin:'https://client.test'})).json();
  const browserEvent=finalizeEvent({...event,tags:event.tags.map(tag=>tag[0]==='challenge'?['challenge',browserChallenge.challenge]:tag[0]==='transaction'?['transaction',sha256(browserChallenge.transactionToken)]:tag).concat([['client-origin','https://client.test']])},key);
  const browserHeaders={Origin:'https://client.test',Authorization:'Nostr '+Buffer.from(JSON.stringify(browserEvent)).toString('base64'),'X-Nostr-Transaction':browserChallenge.transactionToken};
  const browserResponse=await call('/api/v2/provision',{name:'wallet'},browserHeaders);
  assert.equal(browserResponse.status,200);assert.equal(browserResponse.headers.get('access-control-allow-origin'),'https://client.test');assert.equal(browserResponse.headers.get('vary'),'Origin');
  async function signOperation(path,body,owner=key) {
    const target='https://wallet.test'+path, payload=sha256(JSON.stringify(body));
    const issued=await (await call('/api/v2/provision/challenge',{url:target,method:'POST',payload})).json();
    const event=finalizeEvent({kind:27235,created_at:Math.floor(Date.now()/1000),content:'',tags:[['u',target],['method','POST'],['payload',payload],['challenge',issued.challenge],['transaction',sha256(issued.transactionToken)]]},owner);
    return {Authorization:'Nostr '+Buffer.from(JSON.stringify(event)).toString('base64'),'X-Nostr-Transaction':issued.transactionToken};
  }
  db = new DatabaseSync(dbPath);
  db.prepare('UPDATE wallets SET adminkey=? WHERE id=?').run('new-admin','wallet');
  db.close();
  async function recover(hash,owner=key) {
    const body = {previousKeyHash:hash}, path='/api/v2/provision';
    const headers = await signOperation(path,body,owner);
    return call(path,body,{...headers,'X-Forwarded-For':'192.0.2.100'});
  }
  const recoveryPath = '/api/v2/provision';
  const recoveryBody = {previousKeyHash:sha256('test-admin')};
  const signedRecovery = {...await signOperation(recoveryPath,recoveryBody), 'X-Forwarded-For':'192.0.2.101'};
  const responses = await Promise.all([call(recoveryPath,recoveryBody,signedRecovery), call(recoveryPath,recoveryBody,signedRecovery)]);
  assert.deepEqual(responses.map(r=>r.status).sort(),[200,403]);
  const refused = responses.find(r=>r.status===403);
  assert.deepEqual(Object.keys(await refused.json()),['error']);
  const refreshed = responses.find(r=>r.status===200);
  assert.equal(refreshed.headers.get('cache-control'),'no-store');
  assert.equal(refreshed.status,200);
  assert.deepEqual(await refreshed.json(),{id:'wallet',adminkey:'new-admin'});
  assert.equal((await recover(sha256('unrelated'))).status,409);
  assert.equal((await recover(sha256('test-admin'),generateSecretKey())).status,409);
  assert.equal(created,0);
  const claimHeaders=await signOperation('/api/v2/claim-username',{username:'alice'});
  assert.equal((await call('/api/v2/claim-username',{username:'mallory'},claimHeaders)).status,403);
  const claimed=await call('/api/v2/claim-username',{username:'alice'},claimHeaders);
  assert.equal(claimed.status,200);assert.equal((await claimed.json()).address,'alice@wallet.test');
  assert.equal((await call('/api/v2/claim-username',{username:'alice'},claimHeaders)).status,403);
  const releaseHeaders=await signOperation('/api/v2/release-username',{});
  assert.equal((await call('/api/v2/release-username',{username:'alice'},releaseHeaders)).status,400);
  assert.equal((await call('/api/v2/release-username',{},releaseHeaders)).status,200);
  assert.equal((await call('/api/v2/release-username',{},releaseHeaders)).status,403);
  db=new DatabaseSync(dbPath);assert.equal(db.prepare('SELECT COUNT(*) AS n FROM pay_links').get().n,0);assert.equal(db.prepare('SELECT username FROM accounts').get().username,null);db.close();
  const newKey=generateSecretKey(),newBody={name:'Fresh wallet'};
  async function onboard(){
    const raw=JSON.stringify(newBody),payload=sha256(raw);
    const i=await (await call('/api/v2/provision/challenge',{url,method:'POST',payload})).json();
    const e=finalizeEvent({kind:27235,created_at:Math.floor(Date.now()/1000),content:'',tags:[['u',url],['method','POST'],['payload',payload],['challenge',i.challenge],['transaction',sha256(i.transactionToken)]]},newKey);
    return call('/api/v2/provision',newBody,{Authorization:'Nostr '+Buffer.from(JSON.stringify(e)).toString('base64'),'X-Nostr-Transaction':i.transactionToken,'X-Forwarded-For':'192.0.2.99'});
  }
  const first=await onboard();assert.equal(first.status,201);
  const w=await first.json();assert.deepEqual(Object.keys(w).sort(),['adminkey','id','inkey','name','user']);assert.equal(w.name,newBody.name);
  const recovered=await onboard();assert.equal(recovered.status,200);assert.deepEqual(await recovered.json(),w);assert.equal(created,1);
  const preflight=await fetch(local+'/api/v2/provision',{method:'OPTIONS',headers:{Origin:'https://client.test','Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization,x-nostr-transaction,content-type'}});
  assert.equal(preflight.status,204);assert.equal(preflight.headers.get('access-control-allow-methods'),'POST');
  assert.equal((await fetch(local+'/api/v2/provision',{method:'OPTIONS',headers:{Origin:'https://evil.test','Access-Control-Request-Method':'POST'}})).status,403);
});

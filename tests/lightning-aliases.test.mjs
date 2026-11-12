import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import {createServer} from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {finalizeEvent,generateSecretKey,getPublicKey} from 'nostr-tools/pure';
import {sha256} from '../auth-v2.mjs';

test('owned aliases route safely, persist, reject strangers and permit owner reclaim',async t=>{
 const dir=mkdtempSync(join(tmpdir(),'aliases-')), dbPath=join(dir,'lnbits.db'), mapping=join(dir,'mapping.db');
 const key=generateSecretKey(), stranger=generateSecretKey(), pubkey=getPublicKey(key);
 const db=new DatabaseSync(dbPath), pdb=new DatabaseSync(mapping);
 db.exec(`CREATE TABLE accounts(id TEXT PRIMARY KEY, username TEXT,pubkey TEXT);
 CREATE TABLE wallets(id TEXT,name TEXT,adminkey TEXT,inkey TEXT,"user" TEXT,deleted INTEGER);
 CREATE TABLE pay_links(id TEXT, wallet TEXT, description TEXT, min INTEGER, max INTEGER, served_meta INTEGER, served_pr INTEGER,webhook_url TEXT,success_text TEXT,success_url TEXT,currency TEXT,comment_chars INTEGER,webhook_headers TEXT,webhook_body TEXT,username TEXT,zaps INTEGER,domain TEXT,created_at REAL,updated_at REAL,disposable INTEGER);
 INSERT INTO accounts VALUES ('owner','primary',NULL),('stranger',NULL,NULL);
 INSERT INTO wallets VALUES ('owner-wallet','test','admin','in','owner',0),('stranger-wallet','test','admin2','in2','stranger',0);
 INSERT INTO pay_links(id,wallet,username) VALUES('pay','owner-wallet','primary'),('other','stranger-wallet','occupied');`);
 pdb.exec('CREATE TABLE provisioned(pubkey TEXT PRIMARY KEY,user_id TEXT,wallet_id TEXT,created_at REAL)');
 pdb.prepare('INSERT INTO provisioned VALUES(?,?,?,0)').run(pubkey,'owner','owner-wallet');
 pdb.prepare('INSERT INTO provisioned VALUES(?,?,?,0)').run(getPublicKey(stranger),'stranger','stranger-wallet');
 let delayNext, upstreamArrived;
 const upstream=createServer(async(req,res)=>{if(delayNext){const wait=delayNext;delayNext=null;upstreamArrived();await wait;const target=req.url.startsWith('/.well-known/')?db.prepare('SELECT wallet FROM pay_links WHERE username=?').get(req.url.split('/').at(-1)):db.prepare('SELECT wallet FROM pay_links WHERE id=?').get(req.url.split('/').at(-1));res.setHeader('Content-Type','application/json');res.end(JSON.stringify({wallet:target?.wallet ?? null}));return;}res.setHeader('Content-Type','application/json');res.end(JSON.stringify({path:req.url,host:req.headers.host}));});
 await new Promise(r=>upstream.listen(0,'127.0.0.1',r));
 const env={...process.env,PORT:'0',PUBLIC_ORIGIN:'https://zaps.nostr-wot.com',LNBITS_URL:`http://127.0.0.1:${upstream.address().port}`,LNBITS_PROVISION_TOKEN:'test',LNBITS_DB_PATH:dbPath,LNURLP_DB_PATH:dbPath,PROVISION_DB_PATH:mapping};
 // Reserve a free port because the proxy logs configured PORT rather than its assigned port.
 const portServer=createServer(); await new Promise(r=>portServer.listen(0,'127.0.0.1',r));env.PORT=String(portServer.address().port);await new Promise(r=>portServer.close(r));
 const local=`http://127.0.0.1:${env.PORT}`;
 let child;
 async function start(){child=spawn(process.execPath,['server.js'],{cwd:new URL('..',import.meta.url),env,stdio:['ignore','pipe','pipe']});await new Promise((r,j)=>{child.stdout.on('data',c=>{if(c.toString().includes('listening'))r();});child.once('exit',c=>j(Error('startup '+c)));});}
 async function stop(){const done=new Promise(r=>child.once('exit',r));child.kill();await done;}
 t.after(async()=>{if(child?.exitCode===null)await stop();await new Promise(r=>upstream.close(r));db.close();pdb.close();rmSync(dir,{recursive:true,force:true});});
 await start();
 const reserve=(...args)=>spawnSync(process.execPath,['scripts/reserve-lightning-aliases.mjs','--pubkey',pubkey,...args],{cwd:new URL('..',import.meta.url),env,encoding:'utf8'});
 const identity=async name=>(await(await fetch(local+'/.well-known/nostr.json?name='+name)).json()).names;
 assert.deepEqual(await identity('primary'),{primary:pubkey});
 assert.deepEqual(await identity('absent'),{});
 let result=reserve('alias','primary');assert.equal(result.status,0,result.stderr);
 result=reserve('unused','occupied');assert.notEqual(result.status,0);assert.equal(pdb.prepare("SELECT 1 FROM lightning_aliases WHERE username='unused'").get(),undefined,'batch must be atomic');
 result=reserve('--allow-existing-name','occupied','occupied');assert.equal(result.status,0,result.stderr);
 assert.deepEqual(await identity('occupied'),{occupied:pubkey});
 const availability = name => fetch(local+'/api/username-availability?name='+name);
 for (const [name, available] of [['fresh',true],['admin',false],['alias',false],['occupied',false],['primary',false]]) {
   assert.deepEqual(await (await availability(name)).json(),{available});
 }
 assert.equal((await availability('x')).status,400);
 for (let i=6;i<20;i++) assert.equal((await availability('fresh')).status,200);
 const limited=await availability('fresh');
 assert.equal(limited.status,429);
 assert.equal(limited.headers.get('retry-after'),'60');
 const get=async name=>fetch(local+'/.well-known/lnurlp/'+name);
 for(const name of ['alias','occupied','primary']) {const response=await get(name);assert.equal(response.status,200);assert.deepEqual(await response.json(),{path:'/lnurlp/api/v1/lnurl/pay',host:'zaps.nostr-wot.com'});}
 assert.equal((await (await fetch(local+'/api/lightning-address?pubkey='+pubkey)).json()).address,'primary@nostrwot.com');
 assert.equal((await (await get('ordinary')).json()).path,'/.well-known/lnurlp/ordinary');
 let releaseUpstream;delayNext=new Promise(r=>{releaseUpstream=r;});const arrived=new Promise(r=>{upstreamArrived=r;});
 const pending=get('alias');await arrived;
 // A different process releases and reassigns the canonical name while upstream waits.
 db.exec("UPDATE pay_links SET username='moved' WHERE id='pay'; INSERT INTO pay_links(id,wallet,username) VALUES('takeover','stranger-wallet','primary')");
 releaseUpstream();assert.equal((await(await pending).json()).wallet,'owner-wallet','in-flight alias must stay bound to its checked pay-link ID');
 db.exec("DELETE FROM pay_links WHERE id='takeover'; UPDATE pay_links SET username='primary' WHERE id='pay'");
 const zap=JSON.stringify(finalizeEvent({kind:9734,created_at:1,content:'',tags:[['p',pubkey],['relays','wss://relay.example']]}, key));const callback=await fetch(local+'/lnurlp/api/v1/lnurl/cb/pay?amount=1000&nostr='+encodeURIComponent(encodeURIComponent(zap)));assert.equal(new URL('https://test'+(await callback.json()).path).searchParams.get('nostr'),zap);
 let counter=0;
 async function operation(path,body,secret=key){const ip=`192.0.2.${++counter}`,url=env.PUBLIC_ORIGIN+path,payload=sha256(JSON.stringify(body));const post=(path,body,headers={})=>fetch(local+path,{method:'POST',headers:{'Content-Type':'application/json','X-Forwarded-For':ip,...headers},body:JSON.stringify(body)});const issued=await(await post('/api/v2/provision/challenge',{url,method:'POST',payload})).json();const event=finalizeEvent({kind:27235,created_at:Math.floor(Date.now()/1000),content:'',tags:[['u',url],['method','POST'],['payload',payload],['challenge',issued.challenge],['transaction',sha256(issued.transactionToken)]]},secret);return post(path,body,{Authorization:'Nostr '+Buffer.from(JSON.stringify(event)).toString('base64'),'X-Nostr-Transaction':issued.transactionToken});}
 const freshKey=generateSecretKey(), handle='new-signup', reserveBody={username:handle,reserveOnly:true};
 const claim=(body,owner)=>operation('/api/v2/claim-username',body,owner);
 assert.equal((await claim(reserveBody,freshKey)).status,200);
 assert.equal((await claim(reserveBody,freshKey)).status,200);
 assert.equal((await claim(reserveBody,stranger)).status,409);
 assert.equal((await claim({username:handle},stranger)).status,409);
 assert.equal((await claim({...reserveBody,username:'another'},freshKey)).status,409);
 assert.deepEqual(await identity(handle),{[handle]:getPublicKey(freshKey)});
 assert.equal((await get(handle)).status,404);
 assert.equal((await operation('/api/v2/delete-account',{confirm:'delete-account',acknowledgeBalance:false},freshKey)).status,200);
 assert.deepEqual(await identity(handle),{});
 assert.equal((await claim({...reserveBody,username:'occupied'},freshKey)).status,409);
 assert.equal((await operation('/api/v2/release-username',{})).status,200);
 assert.equal((await get('alias')).status,404);
 assert.deepEqual(await identity('alias'),{});
 assert.equal((await operation('/api/v2/claim-username',{username:'alias'},stranger)).status,409);
 assert.equal((await operation('/api/v2/claim-username',{username:'alias'})).status,200);
 assert.equal(db.prepare("SELECT domain FROM pay_links WHERE wallet='owner-wallet'").get().domain,'zaps.nostr-wot.com');
 assert.equal((await(await get('primary')).json()).path,'/lnurlp/api/v1/lnurl/'+db.prepare("SELECT id FROM pay_links WHERE wallet='owner-wallet'").get().id);
 await stop();env.LIGHTNING_ADDRESS_DOMAIN='addresses.test';await start();assert.equal((await get('primary')).status,200);
 assert.equal((await (await fetch(local+'/api/lightning-address?pubkey='+pubkey)).json()).address,'alias@addresses.test');
 const reassigned=spawnSync(process.execPath,['scripts/reserve-lightning-aliases.mjs','--pubkey',getPublicKey(stranger),'--allow-existing-name','primary'],{cwd:new URL('..',import.meta.url),env,encoding:'utf8'});assert.notEqual(reassigned.status,0);assert.match(reassigned.stderr,/reserved to another owner/);
 db.exec("INSERT INTO pay_links(id,wallet,username) VALUES('duplicate','stranger-wallet','alias')");assert.equal((await get('primary')).status,404);db.exec("DELETE FROM pay_links WHERE id='duplicate'");
 db.exec("UPDATE wallets SET deleted=1 WHERE id='owner-wallet'");assert.equal((await get('alias')).status,404);
 db.exec("UPDATE wallets SET deleted=0 WHERE id='owner-wallet'");pdb.prepare('DELETE FROM provisioned WHERE pubkey=?').run(pubkey);
 db.prepare("UPDATE accounts SET pubkey=? WHERE id='stranger'").run(pubkey);
 assert.equal((await get('occupied')).status,404,'must not fall back to occupied foreign link or accounts.pubkey');
 assert.equal((await operation('/api/v2/claim-username',{username:'primary'},stranger)).status,409);
 assert.equal(pdb.prepare('SELECT COUNT(*) AS n FROM lightning_aliases').get().n,3);
});

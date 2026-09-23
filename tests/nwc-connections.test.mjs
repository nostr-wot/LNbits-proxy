import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createNwcRoutes} from '../nwc-connections.mjs';

test('proxy authenticates wallet ownership, scopes mutations, budgets and public metadata',async t=>{
 const dir=mkdtempSync(join(tmpdir(),'nwc-proxy-')),dbPath=join(dir,'db.sqlite');
 const db=new DatabaseSync(dbPath);
 db.exec("CREATE TABLE wallets(id TEXT,user TEXT,adminkey TEXT,deleted INT);CREATE TABLE extensions(user TEXT,extension TEXT,active INT,UNIQUE(user,extension));CREATE TABLE installed_extensions(id TEXT,active INT);INSERT INTO installed_extensions VALUES ('nwcprovider',1);INSERT INTO wallets VALUES ('a','a','key-a',0),('b','b','key-b',0),('gone','gone','deleted-key',1)");
 const rows=new Map([['key-a',new Map()],['key-b',new Map()]]);const calls=[];let blocked=false;
 const upstream=async(url,init)=>{
  assert.equal(init.redirect,'error');assert.ok(init.signal);
  const mine=rows.get(init.headers['X-Api-Key']);if(!mine||blocked)return new Response('{}',{status:403});
  const path=new URL(url).pathname;calls.push({path,method:init.method,body:init.body});
  if(path==='/api/v1/wallet')return Response.json({id:init.headers['X-Api-Key']});
  if(path.includes('/pairing/')){assert.ok(path.endsWith('0'.repeat(64)));return Response.json(`nostr+walletconnect://${'34'.repeat(32)}?relay=wss://relay.test&secret=${'0'.repeat(64)}`);}
  const key=path.split('/').pop();
  if(init.method==='DELETE'){mine.delete(key);return Response.json({});}
  if(init.method==='PUT'){const body=JSON.parse(init.body);mine.set(key,{data:{...body,pubkey:key},budgets:body.budgets});return Response.json({});}
  return Response.json([...mine.values()]);
 };
 const route=createNwcRoutes({backend:'http://127.0.0.1:5000',dbPath,fetchFn:upstream});
 const server=createServer(async(req,res)=>{if(!await route(req,res,new URL(req.url,'http://localhost'))){res.writeHead(404);res.end('{}');}});
 server.listen(0,'127.0.0.1');await once(server,'listening');const base=`http://127.0.0.1:${server.address().port}`;
 t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));db.close();rmSync(dir,{recursive:true,force:true});});
 const api=(path='',method='GET',key='key-a',body)=>fetch(base+'/api/nwc/connections'+path,{method,headers:{'X-Api-Key':key},...(body?{body:JSON.stringify(body)}:{})});
 for(const key of ['','bad','invoice-key','deleted-key'])assert.ok((await api('','GET',key)).status>=400);
 for(const path of ['?api-key=key-a','/config','/../config'])assert.equal((await api(path)).status,404);
 const key='12'.repeat(32),draft={name:'Primal',dailyLimit:1000,days:30};
 for(const dailyLimit of [0,-1,0.5,10000000])assert.equal((await api('/'+key,'PUT','key-a',{...draft,dailyLimit})).status,400);
 for(const days of [0,366,1.5])assert.equal((await api('/'+key,'PUT','key-a',{...draft,days})).status,400);
 assert.equal((await api('/'+key,'PUT','key-a',{...draft,name:'x'.repeat(4097)})).status,413);
 const empty=await api();assert.equal(empty.headers.get('Cache-Control'),'no-store');assert.deepEqual((await empty.json()).connections,[]);
 const simultaneous=await Promise.all([api('/'+key,'PUT','key-a',draft),api('/'+key,'PUT','key-a',draft)]);
 assert.deepEqual(simultaneous.map(r=>r.status).sort(),[200,201]);
 assert.equal((await api('/'+key,'PUT','key-a',draft)).status,200);
 assert.equal(rows.get('key-a').size,1);
 const created=rows.get('key-a').get(key);assert.deepEqual(created.data.permissions,['pay','lookup','info']);
 assert.equal(created.budgets[0].budget_msats,1000000);assert.equal(created.budgets[0].refresh_window,86400);
 assert.ok(created.data.expires_at>Date.now()/1000+29*86400);
 const result=await (await api()).json();assert.equal(result.connections.length,1);assert.deepEqual(Object.keys(result.provider).sort(),['pubkey','relay']);assert.doesNotMatch(JSON.stringify(result),/secret/);
 assert.equal((await (await api('','GET','key-b')).json()).connections.length,0);
 await api('/'+'56'.repeat(32),'PUT','key-b',draft);await api('/'+key,'DELETE','key-b');assert.equal(rows.get('key-a').size,1);
 await api('/'+key,'DELETE','key-a');assert.equal(rows.get('key-a').size,0);
 blocked=true;assert.equal((await api()).status,403);blocked=false;
 db.exec("UPDATE installed_extensions SET active=0");assert.equal((await api()).status,503);
 assert.ok(calls.every(c=>!c.path.includes('key-a')));
});

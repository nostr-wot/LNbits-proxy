import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { finalizeEvent, generateSecretKey } from 'nostr-tools/pure';
import { createAuth, sha256, clientScope } from '../auth-v2.mjs';

const origin = 'https://wallet.test';
const url = origin + '/api/v2/provision';
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'auth-v2-'));
  t.after(() => rmSync(dir, {recursive:true, force:true}));
  const dbPath = join(dir,'auth.db');
  const auth = createAuth({dbPath, publicOrigin:origin});
  const raw = Buffer.from('{"name":"wallet"}');
  const issued = auth.issue({url,method:'POST',payload:sha256(raw)}, 'native');
  const base = {kind:27235,created_at:Math.floor(Date.now()/1000),content:'',tags:[['u',url],['method','POST'],['payload',sha256(raw)],['challenge',issued.challenge],['transaction',sha256(issued.transactionToken)]]};
  const key = generateSecretKey();
  const request = (event=finalizeEvent(base,key), body=raw) => ({authorization:'Nostr '+Buffer.from(JSON.stringify(event)).toString('base64'),token:issued.transactionToken,raw:body,url,scope:'native'});
  return {auth,dbPath,raw,issued,base,key,request};
}
test('body mutation does not burn challenge; valid request consumes it once',t=>{
  const f=fixture(t);
  assert.throws(()=>f.auth.verify(f.request(undefined,Buffer.from('{"name":"evil"}'))));
  assert.ok(f.auth.verify(f.request()).pubkey);
  assert.throws(()=>f.auth.verify(f.request()));
});
test('reject ambiguity, incorrect audience, timestamp, content and invalid signature without burning nonce',t=>{
  const f=fixture(t);
  for (const change of [b=>b.tags.push(['u',url]),b=>b.tags[0][1]='https://evil.test/api/v2/provision',b=>b.created_at=1.5,b=>b.content='no']) {
    const b=structuredClone(f.base);change(b);
    assert.throws(()=>f.auth.verify(f.request(finalizeEvent(b,f.key))));
  }
  const bad=JSON.parse(JSON.stringify(finalizeEvent(f.base,f.key)));bad.sig='00'.repeat(64);
  assert.throws(()=>f.auth.verify(f.request(bad)));
  assert.ok(f.auth.verify(f.request()));
});
test('nonce store persists and binds transaction and client scope',t=>{
  const f=fixture(t);const second=createAuth({dbPath:f.dbPath,publicOrigin:origin});
  assert.throws(()=>second.verify({...f.request(),scope:'https://client.test'}));
  assert.throws(()=>second.verify({...f.request(),token:'a'.repeat(64)}));
  assert.ok(second.verify(f.request()));assert.throws(()=>f.auth.verify(f.request()));
});
test('challenge audience and browser policy are exact',t=>{
  const f=fixture(t);
  for (const u of [url+'?',url+'?x=1',url+'#x','https://evil.test/api/v2/provision']) assert.throws(()=>f.auth.issue({url:u,method:'POST',payload:sha256(f.raw)},'native'));
  assert.equal(clientScope(undefined,new Set()),'native');
  assert.equal(clientScope('chrome-extension://abc',new Set()),'native');
  assert.throws(()=>clientScope('null',new Set()));
  assert.throws(()=>clientScope('https://evil.test',new Set()));
  assert.equal(clientScope('https://client.test',new Set(['https://client.test'])),'https://client.test');
});

test('separate processes race to consume the same nonce: exactly one succeeds',async t=>{
  const {spawn}=await import('node:child_process');
  const f=fixture(t);
  const request=f.request(); request.raw=request.raw.toString('base64');
  const code=`import {createAuth} from ${JSON.stringify(new URL('../auth-v2.mjs',import.meta.url).href)};
    const r=JSON.parse(process.env.TEST_REQUEST);r.raw=Buffer.from(r.raw,'base64');
    try {createAuth({dbPath:process.env.TEST_DB,publicOrigin:${JSON.stringify(origin)}}).verify(r);process.exit(0)} catch {process.exit(1)}`;
  const run=()=>new Promise(resolve=>{const child=spawn(process.execPath,['--input-type=module','-e',code],{env:{...process.env,TEST_DB:f.dbPath,TEST_REQUEST:JSON.stringify(request)},stdio:'ignore'});child.on('exit',resolve);});
  assert.deepEqual((await Promise.all([run(),run()])).sort(),[0,1]);
});
test('challenge expiry and bounded storage are enforced',t=>{
  const f=fixture(t);let clock=1000;
  const auth=createAuth({dbPath:f.dbPath,publicOrigin:origin,maxRows:2,now:()=>clock});
  auth.issue({url,method:'POST',payload:sha256(f.raw)},'native');
  assert.throws(()=>auth.issue({url,method:'POST',payload:sha256(f.raw)},'native'),/Server busy/);
  clock+=60;
  assert.ok(auth.issue({url,method:'POST',payload:sha256(f.raw)},'native'));
});
test('nonce expires at 60 seconds even when event timestamp is fresh',t=>{
  const f=fixture(t);let clock=2000;
  const auth=createAuth({dbPath:f.dbPath,publicOrigin:origin,now:()=>clock});
  const issued=auth.issue({url,method:'POST',payload:sha256(f.raw)},'native');
  clock+=60;
  const event=finalizeEvent({...f.base,created_at:clock,tags:f.base.tags.map(tag=>tag[0]==='challenge'?['challenge',issued.challenge]:tag[0]==='transaction'?['transaction',sha256(issued.transactionToken)]:tag)},f.key);
  assert.throws(()=>auth.verify({...f.request(event),token:issued.transactionToken}),/expired/);
});
test('browser origin requires exact signed claim and rejects native tag forwarding',t=>{
  const f=fixture(t),scope='https://client.test';
  const issued=f.auth.issue({url,method:'POST',payload:sha256(f.raw)},scope);
  const base={...f.base,tags:f.base.tags.map(tag=>tag[0]==='challenge'?['challenge',issued.challenge]:tag[0]==='transaction'?['transaction',sha256(issued.transactionToken)]:tag)};
  const request=event=>({...f.request(event),scope,token:issued.transactionToken});
  assert.throws(()=>f.auth.verify(request(finalizeEvent(base,f.key))));
  assert.throws(()=>f.auth.verify(request(finalizeEvent({...base,tags:[...base.tags,['client-origin','https://evil.test']]},f.key))));
  const signed=finalizeEvent({...base,tags:[...base.tags,['client-origin',scope]]},f.key);
  assert.throws(()=>f.auth.verify({...request(signed),scope:'native'}));
  assert.ok(f.auth.verify(request(signed)));
});

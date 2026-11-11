import test from 'node:test';
import assert from 'node:assert/strict';
import {finalizeEvent,generateSecretKey} from 'nostr-tools/pure';
import {walletBody,upstreamPath} from '../request-policy.mjs';
const path=p=>upstreamPath(new URL(p,'https://example.org'),'GET');
test('wallet payment options cannot add callbacks, metadata, or change invoice units',()=>{
  for(const body of [{out:false,amount:10,webhook:'unwanted'},{out:false,amount:10,extra:{}},{out:false,amount:10,unit:'usd'},{out:false,amount:-1},{out:'false',amount:10},{bolt11:'oops'}])assert.throws(()=>walletBody(JSON.stringify(body)));
  assert.deepEqual(JSON.parse(walletBody('{"out":false,"amount":1,"memo":"test"}')),{out:false,unit:'sat',amount:1,memo:'test'});
  assert.equal(path('/api/v1/payments?unknown=foo&limit=20&status%5Bne%5D=pending'),'/api/v1/payments?limit=20&status%5Bne%5D=pending');
  assert.throws(()=>path('/api/v1/payments?limit=2&limit=4'));
});
test('zap receipt keeps the signed payload through double encoding, unrelated input is dropped',()=>{
  const event=finalizeEvent({kind:9734,content:'',created_at:1,tags:[['p','12'.repeat(32)],['relays','wss://relay.example']]},generateSecretKey());
  const json=JSON.stringify(event), result=path('/lnurlp/api/v1/lnurl/cb/abc?amount=1000&webhook_data=x&nostr='+encodeURIComponent(encodeURIComponent(json)));
  const u=new URL(result,'https://example.org');
  assert.equal(u.searchParams.get('nostr'),json); assert.equal(u.searchParams.has('webhook_data'),false);
  assert.throws(()=>path('/lnurlp/api/v1/lnurl/cb/abc?amount=1000&nostr={}'));
});

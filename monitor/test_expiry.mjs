// Live check against a running deployment. It mints a real invoice and then
// retires it through cleanup.py, so run it by hand, not in CI.
//   MONITOR_LINK_ID=<id> node monitor/test_expiry.mjs [short|default|invalid]
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
const mode=process.argv[2] || 'short';
const BASE=process.env.MONITOR_BASE_URL || 'https://zaps.nostr-wot.com';
const LINK=process.env.MONITOR_LINK_ID;
const PY=process.env.MONITOR_PYTHON || '/usr/bin/python3';
const CLEANUP=process.env.MONITOR_CLEANUP || '/srv/zaps-monitor/cleanup.py';
const BOLT11_PY=process.env.BOLT11_PYTHON || '/home/lnbits/lnbits-v1.6.0/venv/bin/python';
if(!LINK) throw new Error('MONITOR_LINK_ID is required');
const param=mode==='default'?'':'&expiry='+ (mode==='invalid'?'29':'30');
const r=await fetch(`${BASE}/lnurlp/api/v1/lnurl/cb/${LINK}?amount=1000`+param);
if(mode==='invalid') { assert.equal(r.status,400);const error=await r.json();assert.ok(error.detail.some(e=>e.loc.includes('expiry')));console.log('expiry below 30s rejected'); }
else {
 assert.equal(r.status,200);
 const d=await r.json();assert.ok(d.pr);
 const decoded=spawnSync(BOLT11_PY,['-c','import sys,bolt11; print(bolt11.decode(sys.stdin.read().strip()).expiry)'],{input:d.pr,encoding:'utf8'});
 assert.equal(decoded.status,0);
 const retired=spawnSync(PY,[CLEANUP,'--retire-monitor'],{input:d.pr,encoding:'utf8'});
 assert.equal(retired.status,0,'test invoice retirement failed');
 const actual=Number(decoded.stdout.trim());console.log(`${mode}: signed expiry ${actual}s; retired`);
 assert.equal(actual,mode==='default'?3600:30);
}

// Positive schemas for the two public pass-throughs; never forward raw bodies or queries.
import {validateZapRequest} from 'nostr-tools/nip57';
export class InvalidInput extends Error {}
function check(ok) { if (!ok) throw new InvalidInput('Invalid request'); }
function invoice(v) { return typeof v === 'string' && v.length <= 8000 && /^lnbc(?:[0-9]+[munp]?)?1[02-9ac-hj-np-z]+$/i.test(v); }
const uint = (s,max,min=0) => /^\d{1,16}$/.test(s) && Number.isSafeInteger(Number(s)) && Number(s)>=min && Number(s)<=max;
export function walletBody(raw) {
  let v; try { v=JSON.parse(raw); } catch { throw new InvalidInput(); }
  check(v && typeof v.out==='boolean' && !Array.isArray(v));
  if(v.out) {
    check(invoice(v.bolt11) && Object.keys(v).every(k=>['out','bolt11'].includes(k)));
    return JSON.stringify({out:true,bolt11:v.bolt11});
  }
  check(Object.keys(v).every(k=>['out','unit','amount','memo'].includes(k)) && (v.unit===undefined || v.unit==='sat'));
  check(Number.isSafeInteger(v.amount) && v.amount>=0 && v.amount<=2100000000000000);
  check(v.memo===undefined || (typeof v.memo==='string' && Buffer.byteLength(v.memo)<=639));
  return JSON.stringify({out:false,unit:'sat',amount:v.amount,memo:v.memo});
}
const history={limit:v=>uint(v,1000,1),offset:v=>uint(v,10000000),sortby:v=>v==='time',direction:v=>['asc','desc'].includes(v),'status[ne]':v=>v==='pending',payment_hash:v=>/^[a-f0-9]{64}$/.test(v)};
function zap(value,amount) {
  for(let i=0;i<4 && !value.trimStart().startsWith('{');i++) { try {value=decodeURIComponent(value);} catch {throw new InvalidInput();} }
  let e; try {e=JSON.parse(value);} catch {throw new InvalidInput();}
  check(e && e.kind===9734 && Object.keys(e).length===7 && Object.keys(e).every(k=>['kind','id','sig','pubkey','created_at','tags','content'].includes(k)) && Array.isArray(e.tags) && typeof e.content==='string');
  try {
    check(validateZapRequest(value)===null);
    check(e.tags.every(t=>Array.isArray(t) && t.every(x=>typeof x==='string')));
    for(const field of ['p','amount','relays']) check(e.tags.filter(t=>t[0]===field).length<=1);
    const signedAmount=e.tags.find(t=>t[0]==='amount');
    if(signedAmount)check(signedAmount[1]===amount);
  } catch {throw new InvalidInput();}
  return value;
}
export function upstreamPath(url,method) {
  const isCallback=url.pathname.startsWith('/lnurlp/api/v1/lnurl/cb/');
  const schema=isCallback?{amount:v=>uint(v,Number.MAX_SAFE_INTEGER,1),expiry:v=>uint(v,86400,1),comment:v=>[...v].length<=255,nostr:v=>v.length<=16384}:
    url.pathname.endsWith('/fee-reserve')?{invoice}:
    url.pathname==='/api/v1/payments' && method==='GET'?history:{};
  const q=new URLSearchParams();
  for(const [k,v] of url.searchParams) {
    check(k!=='api-key');
    if(!Object.hasOwn(schema,k))continue;
    check(!q.has(k) && schema[k](v)); q.set(k,k==='nostr'?zap(v,url.searchParams.get('amount')):v);
  }
  if(isCallback)check(q.has('amount'));
  if(url.pathname.endsWith('/fee-reserve'))check(q.has('invoice'));
  return url.pathname+(q.size?'?'+q:'');
}

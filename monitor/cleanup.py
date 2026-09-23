#!/usr/bin/env python3
"""Prune expired incoming LNbits invoices only after Phoenixd confirms no payment.
A retired monitor invoice is NOT canceled on Lightning; retain until expiry + 1h.
"""
import argparse,base64,concurrent.futures,datetime,fcntl,json,os,pathlib,re,sqlite3,sys,time,urllib.error,urllib.request
# Configuration. Defaults match the reference deployment; every value can be
# overridden so another operator can run this against their own instance.
DB=os.environ.get('LNBITS_DB_PATH','/home/lnbits/lnbits/data/database.sqlite3')
CONF=os.environ.get('PHOENIX_CONF','/home/phoenixd/.phoenix/phoenix.conf')
PHOENIX_URL=os.environ.get('PHOENIX_URL','http://127.0.0.1:9740')
STATE_DIR=pathlib.Path(os.environ.get('MONITOR_STATE_DIR','/srv/zaps-monitor'))
# Only --retire-monitor needs these, and only for the monitor's own test invoice.
# No default: retiring against the wrong wallet would touch a real user's payments.
MONITOR_WALLET_ID=os.environ.get('MONITOR_WALLET_ID')
MONITOR_LINK_ID=os.environ.get('MONITOR_LINK_ID')
SAFE="""amount > 0 AND status IN ('pending','failed') AND expiry < ?

 AND checking_id NOT LIKE 'internal_%' AND checking_id NOT LIKE 'temp_%'
 AND checking_id NOT LIKE 'fiat_%' AND checking_id=payment_hash"""

def backend_check(status,body):
    # LNbits' Phoenixd adapter treats authenticated 404 as unpaid.
    if status==404:return 'unpaid'
    if status==200 and isinstance(body,dict) and body.get('isPaid') is True:return 'paid'
    if status==200 and isinstance(body,dict) and body.get('isPaid') is False and type(body.get('receivedSat')) is int and body['receivedSat']==0:
        if body.get('isExpired') is True:return 'unpaid'
        if body.get('isExpired') is False:return 'unpaid_active'
    return 'unknown'  # Includes partial receipts and malformed responses.

def phoenix():
    conf=pathlib.Path(CONF).read_text()
    pw=re.search(r'^http-password=(\S+)',conf,re.M).group(1)
    auth='Basic '+base64.b64encode((':'+pw).encode()).decode()
    def request(path):
        req=urllib.request.Request(PHOENIX_URL+path,headers={'Authorization':auth})
        try:
            with urllib.request.urlopen(req,timeout=5) as r:return r.status,json.load(r)
        except urllib.error.HTTPError as e:
            if e.code==404:return 404,None
            raise RuntimeError('Phoenixd HTTP '+str(e.code)) from None
    status,body=request('/getinfo')
    if status!=200 or not isinstance(body,dict) or not body.get('nodeId'):
        raise RuntimeError('Phoenixd identity/health check failed')
    def check(key):
        if not re.fullmatch('[0-9a-f]{64}',key):return 'unknown'
        return backend_check(*request('/payments/incoming/'+key))
    return check

def prune(db,check,now=None,limit=1000,workers=1,dry_run=False):
    now=time.time() if now is None else now
    cutoff=now-3600
    rows=db.execute('SELECT checking_id,wallet_id FROM apipayments WHERE '+SAFE+' ORDER BY expiry LIMIT ?',(cutoff,limit)).fetchall()
    stats=dict(candidates=len(rows),deleted=0,confirmed_unpaid=0,paid=0,unknown=0)
    def inspect(row):
        try:return check(row['checking_id'])
        except Exception:return 'unknown'
    pool=concurrent.futures.ThreadPoolExecutor(max_workers=workers) if workers>1 else None
    pending=[]
    def flush():
        with db:
            for row in pending:
                cur=db.execute('DELETE FROM apipayments WHERE checking_id=? AND wallet_id=? AND '+SAFE,(row['checking_id'],row['wallet_id'],cutoff))
                stats['deleted']+=cur.rowcount
        pending.clear()
    try:
        results=pool.map(inspect,rows) if pool else map(inspect,rows)
        for i,(row,state) in enumerate(zip(rows,results)):
            if state=='unpaid':
                stats['confirmed_unpaid']+=1
                if not dry_run:
                    # Recheck accounting state inside the write statement: never overwrite settlement.
                    pending.append(row)
            elif state=='paid':stats['paid']+=1
            else:stats['unknown']+=1
            if i%100==99:flush()
        flush()
    finally:
        if pool:pool.shutdown()
    return stats

def retire_monitor(db,bolt,check,now=None,wallet=None,link=None):
    now=time.time() if now is None else now
    wallet=MONITOR_WALLET_ID if wallet is None else wallet
    link=MONITOR_LINK_ID if link is None else link
    if not wallet or not link:
        raise ValueError('MONITOR_WALLET_ID and MONITOR_LINK_ID must be set to retire a monitor invoice')
    row=db.execute("SELECT * FROM apipayments WHERE bolt11=? AND wallet_id=? AND amount=1000 AND tag='lnurlp' AND status='pending'",(bolt,wallet)).fetchone()
    if row is None or json.loads(row['extra'] or '{}').get('link')!=link:
        raise ValueError('Invoice is not the expected unpaid monitor invoice')
    if check(row['checking_id']) not in ('unpaid','unpaid_active'):raise ValueError('Backend has a payment or could not confirm unpaid')
    labels=json.loads(row['labels'] or '[]')
    if 'monitor_verified' not in labels:labels.append('monitor_verified')
    cur=db.execute("UPDATE apipayments SET status='failed',labels=?,updated_at=? WHERE checking_id=? AND wallet_id=? AND bolt11=? AND status='pending'",(json.dumps(labels),now,row['checking_id'],wallet,bolt))
    db.commit()
    if cur.rowcount!=1:raise ValueError('Invoice changed during retirement; retained')
    return {'retired':1,'lightning_canceled':False}

def backup(db):
    folder=STATE_DIR/'backups';folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    name='lnbits-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')+'.sqlite3'
    dest=folder/name
    if not dest.exists():
        tmp=folder/(name+'.tmp')
        with sqlite3.connect(tmp) as target:db.backup(target)
        os.chmod(tmp,0o600);os.replace(tmp,dest)
    for old in sorted(folder.glob('lnbits-????????.sqlite3'))[:-7]:old.unlink()

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('--retire-monitor',action='store_true');parser.add_argument('--dry-run',action='store_true');parser.add_argument('--limit',type=int,default=1000)
    args=parser.parse_args()
    STATE_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    with open(STATE_DIR/('retire.lock' if args.retire_monitor else 'cleanup.lock'),'w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('Cleanup already running')
        check=phoenix()
        db=sqlite3.connect('file:'+DB+'?mode=rw',uri=True,timeout=10);db.row_factory=sqlite3.Row
        try:
            if args.retire_monitor:
                result=retire_monitor(db,sys.stdin.read().strip(),check)
            else:
                if not args.dry_run:backup(db)
                result=prune(db,check,limit=args.limit,workers=4,dry_run=args.dry_run)
            print(json.dumps({'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),**result}),flush=True)
            if result.get('unknown',0) or result.get('paid',0):return 1
        finally:db.close()
    return 0
if __name__=='__main__':sys.exit(main())

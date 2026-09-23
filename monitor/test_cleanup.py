import unittest,sqlite3,json
from cleanup import prune,retire_monitor,backend_check

WALLET='test-wallet'
LINK='test-link'

class CleanupTests(unittest.TestCase):
 def setUp(self):
  self.db=sqlite3.connect(':memory:'); self.db.row_factory=sqlite3.Row
  self.db.execute('CREATE TABLE apipayments(checking_id TEXT, payment_hash TEXT, wallet_id TEXT, amount INTEGER,status TEXT,expiry REAL,preimage TEXT,bolt11 TEXT,tag TEXT,extra TEXT,labels TEXT,updated_at REAL)')
 def add(self,key,**kw):
  row=dict(checking_id=key,payment_hash=key,wallet_id='test-wallet',amount=1000,status='pending',expiry=1000,preimage=None,bolt11=key,tag='lnurlp',extra=json.dumps({'link':'test-link'}),labels='[]',updated_at=0);row.update(kw)
  self.db.execute('INSERT INTO apipayments VALUES('+','.join('?'*len(row))+')',list(row.values()));self.db.commit()
 def keys(self):return {r[0] for r in self.db.execute('select checking_id from apipayments')}
 def test_only_confirmed_expired_incoming_deleted(self):
  for k,kw in [('old',{}),('paid',{'status':'success'}),('out',{'amount':-1000}),('fresh',{'expiry':4500}),('preimage',{'preimage':'abc'}),('unknown',{}),('backend_paid',{}),('internal_x',{})]:self.add(k,**kw)
  states={'old':'unpaid','unknown':'unknown','backend_paid':'paid'}
  prune(self.db,lambda k:states.get(k,'unpaid'),now=5000)
  self.assertEqual(self.keys(),{'paid','out','fresh','unknown','backend_paid','internal_x'})
 def test_backend_requires_definite_absence(self):
  self.assertEqual(backend_check(404,None),'unpaid')
  self.assertEqual(backend_check(200,{'isPaid':False,'receivedSat':0,'isExpired':True}),'unpaid')
  self.assertEqual(backend_check(200,{'isPaid':False,'receivedSat':1,'isExpired':True}),'unknown')
  for status,body in [(200,{'isPaid':False}),(200,{}),(500,None),(401,None)]:self.assertEqual(backend_check(status,body),'unknown')
  self.assertEqual(backend_check(200,{'isPaid':True}),'paid')
 def test_backend_checks_do_not_hold_write_lock(self):
  self.add('first');self.add('second')
  def check(k):
   self.assertFalse(self.db.in_transaction)
   return 'unpaid'
  result=prune(self.db,check,now=5000)
  self.assertEqual(result['deleted'],2)
  self.assertEqual(result['unknown'],0)
 def test_known_preimage_does_not_mean_incoming_invoice_paid(self):
  self.add('known',preimage='known-at-creation',expiry=9000)
  retire_monitor(self.db,'known',lambda k:'unpaid_active',now=5000,wallet=WALLET,link=LINK)
  self.assertEqual(self.db.execute('select status from apipayments').fetchone()[0],'failed')
  prune(self.db,lambda k:'unpaid',now=13000)
  self.assertEqual(self.keys(),set())
 def test_grace_boundary(self):
  self.add('boundary',expiry=1400);self.add('older',expiry=1399)
  prune(self.db,lambda k:'unpaid',now=5000)
  self.assertEqual(self.keys(),{'boundary'})
 def test_settlement_race_preserved(self):
  self.add('race')
  def check(k):self.db.execute("update apipayments set status='success' where checking_id=?",(k,));self.db.commit();return 'unpaid'
  prune(self.db,check,now=5000);self.assertEqual(self.keys(),{'race'})
 def test_backend_failure_preserves_record(self):
  self.add('error')
  def check(k):raise RuntimeError('offline')
  prune(self.db,check,now=5000);self.assertEqual(self.keys(),{'error'})
 def test_monitor_retirement_is_exact_and_retains_row(self):
  self.add('test',expiry=9000);self.add('other',expiry=9000)
  retire_monitor(self.db,'test',lambda k:'unpaid',now=5000,wallet=WALLET,link=LINK)
  rows={r['checking_id']:r for r in self.db.execute('select * from apipayments')}
  self.assertEqual(rows['test']['status'],'failed');self.assertIn('monitor_verified',json.loads(rows['test']['labels']));self.assertEqual(rows['other']['status'],'pending')
 def test_retirement_refuses_to_run_unconfigured(self):
  # Without an explicit wallet and link this would match whatever invoice the
  # bolt11 happens to belong to, which could be a real user's payment.
  self.add('unconfigured',expiry=9000)
  for wallet,link in [(None,LINK),(WALLET,None),(None,None)]:
   with self.assertRaises(ValueError) as caught:
    retire_monitor(self.db,'unconfigured',lambda k:'unpaid',now=5000,wallet=wallet,link=link)
   self.assertIn('MONITOR_WALLET_ID',str(caught.exception))
  self.assertEqual(self.db.execute('select status from apipayments').fetchone()[0],'pending')
 def test_paid_or_wrong_monitor_is_never_retired(self):
  self.add('paid');self.add('wrong',wallet_id='other')
  for bolt,state in [('paid','paid'),('wrong','unpaid')]:
   with self.assertRaises(ValueError):retire_monitor(self.db,bolt,lambda k:state,now=5000,wallet=WALLET,link=LINK)
  self.assertEqual([r[0] for r in self.db.execute('select status from apipayments')],['pending','pending'])
if __name__=='__main__':unittest.main()

import {DatabaseSync} from 'node:sqlite';
const db=new DatabaseSync(process.argv[2],{readOnly:true});
const core=new DatabaseSync(process.env.LNBITS_DB_PATH || '/home/lnbits/lnbits/data/database.sqlite3',{readOnly:true});
try {
  const rows=db.prepare('SELECT user_id,wallet_id FROM provisioned').all();
  const known=core.prepare('SELECT 1 FROM wallets WHERE user=? AND id=? AND deleted=0');
  if (rows.some(r=>!known.get(r.user_id,r.wallet_id))) throw new Error('Provisioning map contains an unavailable wallet; review before deploying');
  console.log('Verified mapped wallets:',rows.length);
} finally {db.close();core.close();}

#!/usr/bin/env node
// Operator-only: PROVISION_DB_PATH is the authority, never accounts.pubkey.
import {DatabaseSync} from 'node:sqlite';
import {existsSync} from 'node:fs';
import {parseArgs} from 'node:util';

const {values,positionals:names}=parseArgs({options:{pubkey:{type:'string'},'allow-existing-name':{type:'boolean',default:false}},allowPositionals:true});
if(!/^[0-9a-f]{64}$/.test(values.pubkey || '') || !names.length || names.some(name=>!/^[a-z0-9][a-z0-9._-]{1,28}[a-z0-9]$/.test(name))) {
 console.error('Usage: node scripts/reserve-lightning-aliases.mjs --pubkey <verified 64-hex owner> [--allow-existing-name] <name> ...');process.exit(1);
}
const paths={proxy:process.env.PROVISION_DB_PATH || '/srv/zaps-provision/provisioning.sqlite3',wallets:process.env.LNBITS_DB_PATH || '/home/lnbits/lnbits/data/database.sqlite3',links:process.env.LNURLP_DB_PATH || '/home/lnbits/lnbits/data/ext_lnurlp.sqlite3'};
let proxy,wallets,links;
try {
 for(const path of Object.values(paths))if(!existsSync(path))throw Error('Required database does not exist');
 proxy=new DatabaseSync(paths.proxy);proxy.exec('PRAGMA busy_timeout=5000; BEGIN IMMEDIATE');
 wallets=new DatabaseSync(paths.wallets,{readOnly:true});links=new DatabaseSync(paths.links,{readOnly:true});
 const owner=proxy.prepare('SELECT user_id,wallet_id FROM provisioned WHERE pubkey=?').get(values.pubkey);
 if(!owner || !wallets.prepare('SELECT 1 FROM wallets WHERE id=? AND "user"=? AND deleted=0').get(owner.wallet_id,owner.user_id))throw Error('Owner must have an existing proxy-provisioned, active wallet');
 const active=links.prepare('SELECT username FROM pay_links WHERE wallet=?').all(owner.wallet_id);
 if(active.length!==1 || !active[0].username)throw Error('Owner must have exactly one named pay link');
 proxy.exec('CREATE TABLE IF NOT EXISTS lightning_aliases(username TEXT PRIMARY KEY,pubkey TEXT NOT NULL)');
 for(const name of new Set(names)) {
  const reservation=proxy.prepare('SELECT pubkey FROM lightning_aliases WHERE username=?').get(name);
  if(reservation && reservation.pubkey!==values.pubkey)throw Error(`Alias ${name} is already reserved to another owner; refusing reassignment`);
  const conflicts=links.prepare('SELECT wallet FROM pay_links WHERE username=? AND wallet!=?').all(name,owner.wallet_id);
  if(conflicts.length && !values['allow-existing-name'])throw Error(`Name ${name} belongs to another pay link; review its owner before using --allow-existing-name`);
  proxy.prepare('INSERT INTO lightning_aliases(username,pubkey) VALUES(?,?) ON CONFLICT(username) DO NOTHING').run(name,values.pubkey);
 }
 proxy.exec('COMMIT');console.log(`Reserved ${new Set(names).size} names for the verified owner. Existing pay links were not modified.`);
} catch(error) {console.error(error.message);process.exitCode=1;}
finally {links?.close();wallets?.close();proxy?.close();}

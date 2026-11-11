"""Import only key fingerprints for existing proxy-owned wallets from a trusted LNbits snapshot."""
import hashlib
import sqlite3
import sys
from pathlib import Path

mapping_path, snapshot_path = map(Path, sys.argv[1:])
with sqlite3.connect(mapping_path.resolve().as_uri() + "?mode=rw", uri=True) as mapping:
    with sqlite3.connect(snapshot_path.resolve().as_uri() + "?mode=ro", uri=True) as snapshot:
        mapping.execute("BEGIN IMMEDIATE")
        count = 0
        for pubkey, user, wallet in mapping.execute("SELECT pubkey,user_id,wallet_id FROM provisioned"):
            row = snapshot.execute("SELECT adminkey FROM wallets WHERE id=? AND user=? AND deleted=0", (wallet, user)).fetchone()
            if row and isinstance(row[0], str) and len(row[0]) == 32:
                fingerprint = hashlib.sha256(row[0].encode()).hexdigest()
                mapping.execute("INSERT OR IGNORE INTO wallet_key_history VALUES (?,?,?,?)", (pubkey, user, wallet, fingerprint))
                count += 1
print(f"Matched {count} provisioned wallets")

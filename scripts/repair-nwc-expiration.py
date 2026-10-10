"""Repair the installed LNbits NWC provider's NIP-40 tag parser, fail closed on drift."""
import argparse
import ast
import os
from pathlib import Path
import shutil
import tempfile

OLD = 'expiration = int(next((tag for tag in tags if tag[0] == "expiration"), -1))'
NEW = 'expiration = int(next((tag[1] if len(tag) > 1 else "" for tag in tags if tag and tag[0] == "expiration"), -1))'


def repair(path: Path, dry_run: bool = False) -> str:
    source = path.read_text()
    if source.count(NEW) == 1 and OLD not in source:
        return 'unchanged'
    if source.count(OLD) != 1 or NEW in source:
        raise ValueError('Unrecognized NWC provider source; inspect upstream before patching')
    updated = source.replace(OLD, NEW)
    ast.parse(updated)
    if dry_run:
        return 'would-change'
    backup = path.with_name(path.name + '.before-expiration-fix')
    if backup.exists() and backup.read_text() != source:
        raise ValueError('Existing backup differs; refusing to overwrite it')
    if not backup.exists():
        shutil.copy2(path, backup)
    stat = path.stat()
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.nwc-repair-')
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(updated)
        os.chmod(temporary, stat.st_mode)
        if os.geteuid() == 0:
            os.chown(temporary, stat.st_uid, stat.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return 'changed'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    print(repair(args.path, args.dry_run))

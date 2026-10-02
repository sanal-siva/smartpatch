#!/usr/bin/env python3
"""Preview or apply permanent device removal while the service is stopped."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services.device_purge import purge_device


def require_stopped(pid_file):
    if not pid_file or not Path(pid_file).is_file():
        raise ValueError('--apply requires the stopped service\'s existing --pid-file')
    pid = int(Path(pid_file).read_text().strip())
    if pid <= 1:
        raise ValueError('Invalid service PID')
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    stat = Path('/proc') / str(pid) / 'stat'
    if stat.exists() and stat.read_text().rsplit(')', 1)[1].split()[0] == 'Z':
        return
    raise ValueError('Service process is still running; stop it before --apply')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--device-id', required=True)
    parser.add_argument('--pid-file', type=Path)
    parser.add_argument('--apply', action='store_true', help='Permanently delete the selected data')
    parser.add_argument('--compact', action='store_true', help='Reclaim SQLite free pages after --apply')
    args = parser.parse_args()
    try:
        path = args.database.resolve(strict=True)
        if args.compact and not args.apply:
            raise ValueError('--compact requires --apply')
        if args.apply:
            require_stopped(args.pid_file)
        with sqlite3.connect(path.as_uri()+('?mode=rw' if args.apply else '?mode=ro'), uri=True, timeout=5) as db:
            report = purge_device(db, args.device_id, apply=args.apply)
            if args.compact:
                db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                db.execute('VACUUM')
                db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            report['integrity'] = db.execute('PRAGMA quick_check').fetchone()[0]
        print(json.dumps(report, indent=2))
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(1, str(exc)+'\n')


if __name__ == '__main__':
    main()

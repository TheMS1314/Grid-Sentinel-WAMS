"""Read-only local validation of a Grid Sentinel PostgreSQL custom archive.

Supply a SHA-256 fingerprint recorded separately at backup time. For optional
PostgreSQL archive structural validation, use --pg-restore-list when pg_restore
is available; this does NOT restore or write to a database.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def verify_backup(path, expected_sha256, pg_restore_list=False, runner=subprocess.run):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError('Backup must be a regular file')
    if not re.fullmatch(r'[0-9a-fA-F]{64}', expected_sha256):
        raise ValueError('A valid independently recorded SHA-256 is required')
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        if stream.read(5) != b'PGDMP':
            raise ValueError('Not a PostgreSQL custom-format dump')
        stream.seek(0)
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(chunk)
            digest.update(chunk)
    if size < 6:
        raise ValueError('Incomplete custom-format archive')
    if digest.hexdigest() != expected_sha256.lower():
        raise ValueError('Backup SHA-256 mismatch: DO NOT RESTORE')
    structure = 'not_requested'
    if pg_restore_list:
        result = runner(['pg_restore', '--list', str(path)], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, check=False, timeout=120)
        if result.returncode:
            raise RuntimeError('pg_restore archive listing failed: DO NOT RESTORE')
        structure = 'list_passed'
    return {'status': 'BACKUP_FILE_VERIFIED', 'size_bytes': size,
            'sha256': digest.hexdigest(), 'archive_structure': structure,
            'scope': 'Integrity/readability only; no restore performed or data correctness proven'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--sha256', required=True, help='Independent digest from backup time')
    parser.add_argument('--pg-restore-list', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify_backup(args.backup, args.sha256, args.pg_restore_list), indent=2))


if __name__ == '__main__':
    main()

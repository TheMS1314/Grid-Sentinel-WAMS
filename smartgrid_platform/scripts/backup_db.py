"""Private, non-overwriting PostgreSQL backup from a local Docker Compose stack."""
import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


COMPOSE = Path(__file__).resolve().parents[1]
COMMAND = ['docker', 'compose', 'exec', '-T', 'db', 'pg_dump', '-U', 'smartgrid',
           '-d', 'smartgrid', '--format=custom', '--no-owner', '--no-acl']


def backup(destination: Path, compose_dir=COMPOSE, command=None, runner=subprocess.run):
    """Create a PGDMP backup and publish it only if a new filename is available."""
    destination = Path(destination).absolute()
    if os.path.lexists(destination):
        raise FileExistsError(f'Backup destination already exists: {destination.name}')
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not (Path(compose_dir) / 'compose.yaml').is_file():
        raise ValueError('Compose directory must contain compose.yaml')
    command = list(command if command is not None else COMMAND)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix='.grid_backup_', suffix='.partial', dir=parent)
        with os.fdopen(fd, 'wb') as output:
            result = runner(command, cwd=compose_dir, stdout=output,
                            stderr=subprocess.PIPE, check=False)
            output.flush()
            os.fsync(output.fileno())
        if result.returncode:
            raise RuntimeError('pg_dump failed; no backup was published')
        with open(temporary, 'rb') as source:
            if source.read(5) != b'PGDMP':
                raise RuntimeError('Unexpected PostgreSQL backup format; no backup was published')
            source.seek(0)
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        size = os.path.getsize(temporary)
        if size < 6:
            raise RuntimeError('Incomplete backup; no backup was published')
        # os.link fails if a destination has appeared since the first check.
        os.link(temporary, destination)
        return {'file': str(destination), 'size_bytes': size, 'sha256': digest,
                'verified_magic': 'PGDMP', 'overwrote_existing_file': False}
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=COMPOSE / 'backups' / ('grid_sentinel_' +
                                dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.dump'))
    parser.add_argument('--compose-dir', type=Path, default=COMPOSE)
    args = parser.parse_args()
    print(json.dumps(backup(args.output, args.compose_dir), indent=2))


if __name__ == '__main__':
    main()

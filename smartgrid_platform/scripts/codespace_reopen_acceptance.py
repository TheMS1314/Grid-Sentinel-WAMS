"""Two-step, non-mutating Codespace stop/reopen persistence acceptance.

Before stopping Codespace (from smartgrid_platform):
    python scripts/codespace_reopen_acceptance.py --prepare
After reopening Codespace and running codespaces_deploy.py:
    python scripts/codespace_reopen_acceptance.py --verify

The local baseline is deliberately ignored by git and stays in backups/.
Never stores API credentials or raw sensor readings.
"""
import argparse
import json
import os
import secrets
from pathlib import Path

try:
    from scripts.persistence_acceptance import PROJECT, snapshot
    from scripts.smoke_check import verify as smoke
except ModuleNotFoundError:
    from persistence_acceptance import PROJECT, snapshot
    from smoke_check import verify as smoke


BASELINE = PROJECT / 'backups' / 'codespace_reopen_baseline.json'
EXPECTED_KEYS = {'analysis_id', 'detail_sha256', 'totals'}


def record(*, baseline=BASELINE, project=PROJECT, take_snapshot=snapshot, check_smoke=smoke):
    """Capture an immutable, owner-controlled baseline without restarting anything."""
    if check_smoke().get('status') != 'LOCAL_SMOKE_PASS':
        raise RuntimeError('Private stack is not healthy')
    state = take_snapshot(project)
    if set(state) != EXPECTED_KEYS:
        raise ValueError('Incomplete persistence snapshot')
    dest = Path(baseline)
    dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if dest.is_symlink():
        raise ValueError('Refusing symlink baseline')
    # Never silently replace a baseline; it must survive Codespaces reopening.
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump({'schema': 1, 'state': state}, stream, sort_keys=True)
            stream.write('\n')
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return {'status': 'CODESPACE_REOPEN_BASELINE_SAVED',
            'analysis_id': state['analysis_id'],
            'baseline_filename': dest.name}


def compare(*, baseline=BASELINE, project=PROJECT, take_snapshot=snapshot, check_smoke=smoke):
    """After reopening: compare persisted analysis, findings and aggregate counts."""
    dest = Path(baseline)
    if dest.is_symlink() or not dest.is_file():
        raise ValueError('A regular saved baseline file is required')
    if dest.stat().st_size > 4096:
        raise ValueError('Unexpectedly large baseline')
    payload = json.loads(dest.read_text(encoding='utf-8'))
    if not isinstance(payload, dict) or payload.get('schema') != 1:
        raise ValueError('Unrecognized baseline format')
    before = payload.get('state')
    if not isinstance(before, dict) or set(before) != EXPECTED_KEYS:
        raise ValueError('Incomplete baseline data')
    if check_smoke().get('status') != 'LOCAL_SMOKE_PASS':
        raise RuntimeError('Private stack has not recovered')
    after = take_snapshot(project)
    if before != after:
        raise RuntimeError('Saved analysis or aggregate counts changed after Codespace reopen')
    return {'status': 'CODESPACE_REOPEN_PERSISTENCE_PASS',
            'analysis_id': after['analysis_id'],
            'detail_sha256': after['detail_sha256'], 'totals': after['totals'],
            'scope': 'Database data survived the owner-controlled Codespace stop/reopen'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', action='store_true')
    group.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    try:
        result = record() if args.prepare else compare()
        print(json.dumps(result, indent=2))
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({'status': 'CODESPACE_REOPEN_CHECK_BLOCKED', 'reason': str(error)}))
        raise SystemExit(2)


if __name__ == '__main__':
    main()

"""Read-only by default: verify saved analyses survive an explicit DB restart.

Run from smartgrid_platform on the private Codespace:
  python scripts/persistence_acceptance.py
  python scripts/persistence_acceptance.py --execute

The --execute form temporarily interrupts the private database container.
It neither drops databases nor creates, changes, or deletes analysis rows.
"""
import argparse
import hashlib
import json
import subprocess
import time
import urllib.request
from pathlib import Path

try:
    from scripts.smoke_check import read_private_token, verify, _RejectRedirects
except ModuleNotFoundError:
    from smoke_check import read_private_token, verify, _RejectRedirects


PROJECT = Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:8080'


def snapshot(project=PROJECT, opener=None):
    """Check authenticated local API and fingerprint one persisted analysis."""
    token = read_private_token(project)
    if not token:
        raise RuntimeError('Private access token missing; no restart attempted')
    if opener is None:
        opener = urllib.request.build_opener(_RejectRedirects()).open

    def request(path):
        url = BASE + path
        req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token})
        with opener(req, timeout=8) as response:
            actual = response.geturl() if callable(getattr(response, 'geturl', None)) else url
            if actual != url or response.status != 200:
                raise RuntimeError('Authenticated local API request failed or redirected')
            return json.load(response)

    overview = request('/api/overview')
    recent = request('/api/analyses?limit=1')
    if not isinstance(recent, list) or not recent or not isinstance(recent[0], dict):
        raise RuntimeError('At least one saved analysis is required for the persistence drill')
    analysis_id = recent[0].get('id')
    if not isinstance(analysis_id, str) or not analysis_id or any(c not in '0123456789abcdef-' for c in analysis_id.lower()):
        raise RuntimeError('Unexpected persisted analysis identifier')
    detail = request('/api/analyses/' + analysis_id)
    if detail.get('id') != analysis_id:
        raise RuntimeError('Analysis detail identity mismatch')
    keys = ('analyses', 'observations', 'review_rows', 'abstention_rows')
    totals = {key: overview.get(key) for key in keys}
    if not isinstance(totals['analyses'], int) or totals['analyses'] < 1:
        raise RuntimeError('No persisted run count was returned')
    # Database row ordering is not a persistence guarantee; canonicalize findings.
    if isinstance(detail.get('findings'), list):
        detail['findings'] = sorted(detail['findings'], key=lambda row: json.dumps(row, sort_keys=True))
    digest = hashlib.sha256(json.dumps(detail, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'analysis_id': analysis_id, 'detail_sha256': digest, 'totals': totals}


def check(project=PROJECT, *, execute=False, runner=subprocess.run,
          take_snapshot=snapshot, smoke=verify, clock=time.monotonic,
          pause=time.sleep):
    project = Path(project).resolve(strict=True)
    if not (project / 'compose.yaml').is_file():
        raise ValueError('Not a Grid Sentinel Compose project')
    if smoke().get('status') != 'LOCAL_SMOKE_PASS':
        raise RuntimeError('Private stack must pass the read-only smoke test first')
    before = take_snapshot(project)
    if not execute:
        return {'status': 'BASELINE_CAPTURED_NO_RESTART', **before,
                'note': 'Pass --execute to restart only the db container and compare saved data'}
    result = runner(['docker', 'compose', 'restart', 'db'], cwd=project,
                    capture_output=True, check=False, timeout=90)
    if result.returncode:
        raise RuntimeError('PostgreSQL restart command failed; inspect Docker privately')
    end = clock() + 120
    while True:
        try:
            if smoke().get('status') == 'LOCAL_SMOKE_PASS':
                after = take_snapshot(project)
                break
        except (OSError, RuntimeError, ValueError):
            pass
        if clock() >= end:
            raise RuntimeError('PostgreSQL/API did not recover within 120 seconds')
        pause(2)
    if before != after:
        raise RuntimeError('Persisted analysis or aggregate counts changed across database restart')
    return {'status': 'POSTGRES_RESTART_PERSISTENCE_PASS', **after,
            'scope': 'Existing saved analysis and aggregate counts matched after DB restart'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='Temporarily restart only PostgreSQL')
    args = parser.parse_args()
    try:
        print(json.dumps(check(execute=args.execute), indent=2))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'PERSISTENCE_CHECK_BLOCKED', 'reason': str(exc)}))
        raise SystemExit(2)


if __name__ == '__main__':
    main()

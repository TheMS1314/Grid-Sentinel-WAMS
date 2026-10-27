"""Read-only smoke checks for a localhost-bound Grid Sentinel frontend."""
import argparse
import json
import urllib.parse
import urllib.request
from pathlib import Path


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise RuntimeError('Local smoke check refused an HTTP redirect')


def read_private_token(directory=None):
    """Read local .env without logging or accepting secrets on command line."""
    root = Path(directory) if directory is not None else Path(__file__).resolve().parents[1]
    try:
        lines = (root / '.env').read_text(encoding='utf8').splitlines()
    except OSError:
        return ''
    values = [line.split('=', 1)[1] for line in lines
              if line.startswith('GRID_SENTINEL_ACCESS_TOKEN=')]
    return values[0] if len(values) == 1 and len(values[0]) >= 40 else ''


def verify(base='http://127.0.0.1:8080', opener=None, access_token=None):
    parts = urllib.parse.urlsplit(base)
    if parts.scheme != 'http' or parts.hostname not in ('127.0.0.1', 'localhost', '::1'):
        raise ValueError('Smoke checks are restricted to loopback HTTP endpoints')
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ('', '/'):
        raise ValueError('Specify a bare loopback URL without credentials or path')
    if opener is None:
        opener = urllib.request.build_opener(_RejectRedirects()).open
    if access_token is None:
        access_token = read_private_token()
    results = {}
    for path in ('/api/health', '/api/ready', '/api/model', '/api/arp-research'):
        requested = base.rstrip('/') + path
        headers = {'Authorization': 'Bearer ' + access_token} if access_token and path not in ('/api/health', '/api/ready') else {}
        req = urllib.request.Request(requested, headers=headers) if headers else requested
        with opener(req, timeout=8) as response:
            effective_url = response.geturl() if callable(getattr(response, 'geturl', None)) else requested
            if effective_url != requested:
                raise RuntimeError('Local smoke check received redirected response')
            payload = json.load(response)
            if response.status != 200 or response.headers.get('cache-control') != 'no-store':
                raise RuntimeError(f'{path}: unexpected status or missing private cache header')
            if path == '/api/ready' and payload.get('status') != 'ready_research_only':
                raise RuntimeError('Backend is not research-ready')
            if path == '/api/model' and payload.get('status') != 'research_only':
                raise RuntimeError('Model unexpectedly claims production status')
            if path == '/api/arp-research' and 'NOT_AUTHENTICATED' not in payload.get('status', ''):
                raise RuntimeError('Research warning missing')
            results[path] = 'passed'
    return {'status': 'LOCAL_SMOKE_PASS', 'checks': results,
            'disclaimer': 'Does not test backup recovery, real traffic or security certification'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='http://127.0.0.1:8080')
    args = parser.parse_args()
    print(json.dumps(verify(args.base), indent=2))


if __name__ == '__main__':
    main()

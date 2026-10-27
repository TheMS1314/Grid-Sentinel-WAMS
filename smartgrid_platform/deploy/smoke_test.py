"""Read-only end-to-end HTTP smoke test after `docker compose up --build -d`."""

import json
import sys
from urllib.error import URLError
from urllib.request import urlopen


BASE_URL = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://127.0.0.1:8080'


def get_json(path):
    with urlopen(f'{BASE_URL}{path}', timeout=12) as response:
        assert response.status == 200, (path, response.status)
        return json.load(response)


def main():
    ready = get_json('/api/ready')
    assert ready['status'] == 'ready_research_only', ready
    assert ready['database'] == 'connected', ready
    model = get_json('/api/model')
    assert model['status'] == 'research_only', model
    assert model['features'] == 15, model
    overview = get_json('/api/overview')
    assert isinstance(overview['analyses'], int), overview
    with urlopen(BASE_URL, timeout=12) as response:
        page = response.read(3000)
        assert response.status == 200 and b'<html' in page.lower()
    print('PASS: React entrypoint, API, PostgreSQL readiness, model, overview')
    print(f"Model: {model['model_id']} | Saved runs: {overview['analyses']}")


if __name__ == '__main__':
    try:
        main()
    except (URLError, AssertionError, ValueError, KeyError) as exc:
        print(f'FAIL: smoke check: {exc}', file=sys.stderr)
        raise SystemExit(1)

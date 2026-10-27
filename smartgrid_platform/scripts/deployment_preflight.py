"""Read-only, offline Compose security preflight; never starts services.

Requires PyYAML. This inspects local configuration but cannot attest Docker
behavior, container image signatures, database recovery, or host firewall.
"""
import argparse
import json
import re
from pathlib import Path

import yaml


def inspect_project(directory):
    root = Path(directory).resolve()
    errors, warnings, checks = [], [], []
    compose = root / 'compose.yaml'
    if not compose.is_file():
        return {'status': 'BLOCKED', 'errors': ['Missing compose.yaml'], 'warnings': [], 'checks': []}
    try:
        doc = yaml.safe_load(compose.read_text(encoding='utf8'))
    except (yaml.YAMLError, UnicodeError) as exc:
        return {'status': 'BLOCKED', 'errors': ['Invalid Compose YAML'], 'warnings': [], 'checks': []}
    if not isinstance(doc, dict) or not isinstance(doc.get('services'), dict):
        return {'status': 'BLOCKED', 'errors': ['Compose services unavailable'], 'warnings': [], 'checks': []}
    services = doc['services']
    if set(services) != {'db', 'backend', 'frontend'}:
        errors.append('Unexpected Compose services; review every added or removed service')
    for name in ('db', 'backend', 'frontend'):
        if not isinstance(services.get(name), dict):
            errors.append(f'Missing or invalid {name} service')
    if errors:
        return {'status': 'BLOCKED', 'errors': errors, 'warnings': warnings, 'checks': checks}
    frontend, backend, database = services['frontend'], services['backend'], services['db']
    def check(condition, label):
        if condition:
            checks.append(label)
        else:
            errors.append(label)

    check(frontend.get('ports') == ['127.0.0.1:8080:8080'], 'Frontend must bind exclusively to 127.0.0.1:8080:8080')
    check('ports' not in backend and 'ports' not in database, 'Backend and database must not publish host ports')
    check(frontend.get('networks') == ['private'] and backend.get('networks') == ['private'] and database.get('networks') == ['private'],
          'All services must use only the declared private bridge network')
    check(doc.get('networks', {}).get('private', {}).get('driver') == 'bridge', 'Private bridge network required')
    def has_healthcheck(name, service):
        if 'healthcheck' in service:
            return True
        dockerfile = root / name / 'Dockerfile'
        return dockerfile.is_file() and any(line.lstrip().startswith('HEALTHCHECK ')
                                               for line in dockerfile.read_text(encoding='utf8').splitlines())
    check(has_healthcheck('frontend', frontend) and has_healthcheck('backend', backend)
          and has_healthcheck('db', database), 'All three services must have healthchecks')
    check(backend.get('read_only') is True, 'Backend root filesystem must remain read-only')
    for service_name, service in (('backend', backend), ('frontend', frontend)):
        check(service.get('cap_drop') == ['ALL'], f'{service_name} must drop all Linux capabilities')
        check('no-new-privileges:true' in service.get('security_opt', []),
              f'{service_name} must prohibit privilege escalation')
    check(database.get('volumes') == ['grid_sentinel_db:/var/lib/postgresql/data'],
          'PostgreSQL must keep its named persistent volume')
    check('grid_sentinel_db' in doc.get('volumes', {}), 'Named PostgreSQL volume must be declared')
    check(backend.get('depends_on', {}).get('db', {}).get('condition') == 'service_healthy',
          'Backend must wait for healthy PostgreSQL')
    check(frontend.get('depends_on', {}).get('backend', {}).get('condition') == 'service_healthy',
          'Frontend must wait for healthy backend')
    check(database.get('image') == 'postgres:17-alpine', 'Database image must match reviewed PostgreSQL major version 17')
    check(backend.get('environment', {}).get('MODEL_PATH') == '/app/model/smartgrid_meter_integrity_model.json',
          'Backend must use the reviewed frozen model path')
    check(backend.get('environment', {}).get('GRID_SENTINEL_AUTH_REQUIRED') == '1',
          'Backend must require private access authentication')
    access = backend.get('environment', {}).get('GRID_SENTINEL_ACCESS_TOKEN', '')
    check(isinstance(access, str) and access.startswith('${GRID_SENTINEL_ACCESS_TOKEN:?'),
          'Backend must require an explicit private access token')
    for service_name, service in (('db', database), ('backend', backend)):
        password = service.get('environment', {}).get('POSTGRES_PASSWORD', '')
        check(isinstance(password, str) and password.startswith('${POSTGRES_PASSWORD:?'),
              f'{service_name} must require an explicit database password')

    required = ['backend/Dockerfile', 'backend/model/smartgrid_meter_integrity_model.json',
                'backend/alembic.ini', 'backend/migrations/env.py', 'frontend/Dockerfile',
                'frontend/nginx.conf', 'frontend/package-lock.json', '.env.example']
    for relative in required:
        check((root / relative).is_file(), f'Required deployment file: {relative}')
    if (root / '.env').exists():
        env_text = (root / '.env').read_text(encoding='utf8')
        lines = [line.strip() for line in env_text.splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
        values = [line[len('POSTGRES_PASSWORD='):] for line in lines
                  if line.startswith('POSTGRES_PASSWORD=')]
        check(len(values) == 1 and len(values[0]) >= 20
              and values[0] != 'REPLACE_WITH_A_LONG_RANDOM_PASSWORD'
              and not re.search(r'\s', values[0]), 'Database password must be a nonplaceholder, single, 20+ character value')
        access_values = [line[len('GRID_SENTINEL_ACCESS_TOKEN='):] for line in lines
                         if line.startswith('GRID_SENTINEL_ACCESS_TOKEN=')]
        valid_access = (len(values) == 1 and len(access_values) == 1
                        and len(access_values[0]) >= 40
                        and access_values[0] != 'REPLACE_WITH_A_LONG_RANDOM_ACCESS_TOKEN'
                        and not re.search(r'\s', access_values[0])
                        and access_values[0] != values[0])
        check(valid_access,
              'Private access token must be a distinct nonplaceholder, 40+ character value')
        if any(not line.startswith(('POSTGRES_PASSWORD=', 'GRID_SENTINEL_ACCESS_TOKEN=')) for line in lines):
            warnings.append('Unexpected .env settings: review before launch (values are never printed)')
    else:
        errors.append('Missing private .env; copy .env.example and set a unique strong password')
    warnings.extend(['This is static-only and has NOT built containers or checked live PostgreSQL.',
                     'Bearer token authentication is enabled, but there is no TLS or multi-user role management; keep localhost binding.',
                     'Restore rehearsal, live smoke checks, and independent model validation remain required.'])
    return {'status': 'STATIC_PREFLIGHT_PASS_NOT_DEPLOYED' if not errors else 'BLOCKED',
            'errors': errors, 'warnings': warnings, 'checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = inspect_project(args.project)
    print(json.dumps(result, indent=2))
    if result['errors']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()

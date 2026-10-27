"""Guarded first-migration tests on disposable SQLite databases.

PostgreSQL is the target engine; these tests validate baseline decision logic,
not a PostgreSQL Docker deployment.
"""
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool

from app.database import Base
from app import models  # noqa: F401


INI = Path(__file__).resolve().parents[1] / 'alembic.ini'


def migrate(connection):
    config = Config(str(INI))
    config.attributes['connection'] = connection
    command.upgrade(config, 'head')


def test_fresh_database_creates_versioned_tables():
    engine = create_engine('sqlite://', poolclass=StaticPool)
    with engine.begin() as conn:
        migrate(conn)
        tables = set(inspect(conn).get_table_names())
        assert {'analysis_runs', 'findings', 'alembic_version'} <= tables
        assert conn.execute(text('SELECT version_num FROM alembic_version')).scalar_one() == '0001_grid_baseline'


def test_existing_legacy_schema_preserves_data():
    engine = create_engine('sqlite://', poolclass=StaticPool)
    with engine.begin() as conn:
        Base.metadata.create_all(bind=conn)
        conn.execute(text("INSERT INTO analysis_runs (id, created_at, source_name, observation_count, review_count, abstention_count, max_score, duration_seconds, model_id) VALUES ('legacy', '2026-10-26 00:00:00', 'Before migration', 1, 0, 0, 0, 0, 'test')"))
        migrate(conn)
        assert conn.execute(text("SELECT source_name FROM analysis_runs WHERE id='legacy'")).scalar_one() == 'Before migration'
        assert conn.execute(text('SELECT version_num FROM alembic_version')).scalar_one() == '0001_grid_baseline'


def test_partial_schema_fails_without_filling_missing_tables():
    engine = create_engine('sqlite://', poolclass=StaticPool)
    with engine.begin() as conn:
        Base.metadata.tables['analysis_runs'].create(bind=conn)
        with pytest.raises(RuntimeError, match='Partial Grid Sentinel schema'):
            migrate(conn)
        assert 'findings' not in inspect(conn).get_table_names()


def test_schema_drift_fails_without_mutating_data():
    engine = create_engine('sqlite://', poolclass=StaticPool)
    with engine.begin() as conn:
        Base.metadata.create_all(bind=conn)
        conn.execute(text('ALTER TABLE analysis_runs ADD COLUMN unexpected TEXT'))
        with pytest.raises(RuntimeError, match='Unexpected schema'):
            migrate(conn)
        assert 'unexpected' in {c['name'] for c in inspect(conn).get_columns('analysis_runs')}


def test_missing_legacy_index_fails_closed():
    engine = create_engine('sqlite://', poolclass=StaticPool)
    with engine.begin() as conn:
        Base.metadata.create_all(bind=conn)
        conn.execute(text('DROP INDEX ix_analysis_runs_created_at'))
        with pytest.raises(RuntimeError, match='Missing required indexes'):
            migrate(conn)

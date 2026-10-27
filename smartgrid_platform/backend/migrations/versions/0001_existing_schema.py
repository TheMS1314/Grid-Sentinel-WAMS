"""Guarded baseline: preserve valid existing data or initialize empty databases.

Revision ID: 0001_grid_baseline
Revises:
"""
from alembic import op
from sqlalchemy import inspect

from app.database import Base
from app import models  # noqa: F401


revision = '0001_grid_baseline'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    inspector = inspect(connection)
    present = set(inspector.get_table_names())
    expected_tables = set(Base.metadata.tables)
    old = expected_tables & present
    if not old:
        Base.metadata.create_all(bind=connection, checkfirst=True)
        return
    if old != expected_tables:
        raise RuntimeError('Partial Grid Sentinel schema: aborting without changes')
    for name, table in Base.metadata.tables.items():
        expected_columns = {col.name for col in table.columns}
        actual_columns = {col['name'] for col in inspector.get_columns(name)}
        if actual_columns != expected_columns:
            raise RuntimeError(f'Unexpected schema for {name}: manual review required')
        required_indexes = {index.name for index in table.indexes}
        present_indexes = {index['name'] for index in inspector.get_indexes(name)}
        if not required_indexes <= present_indexes:
            raise RuntimeError(f'Missing required indexes for {name}: manual review required')
    actual_fks = inspector.get_foreign_keys('findings')
    if not any(fk.get('referred_table') == 'analysis_runs' and
               fk.get('constrained_columns') == ['analysis_id'] and
               fk.get('referred_columns') == ['id'] for fk in actual_fks):
        raise RuntimeError('Missing findings foreign key: manual review required')
    # Legacy pre-Alembic deployments already have exactly these columns.
    # Only Alembic's own version marker is created during this upgrade.


def downgrade():
    raise RuntimeError('Destructive schema downgrade is intentionally unsupported')

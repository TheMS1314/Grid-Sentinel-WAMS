"""Safe online migrations using the existing private database configuration."""
from alembic import context
from sqlalchemy import create_engine

from app.database import Base, DATABASE_URL
from app import models  # noqa: F401 - register mapped tables


target_metadata = Base.metadata
configuration = context.config


def run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata,
                      compare_type=True, transaction_per_migration=True)
    with context.begin_transaction():
        context.run_migrations()


def run_online():
    supplied = configuration.attributes.get('connection')
    if supplied is not None:
        run_migrations(supplied)
    else:
        # Never render passwords into a config file or log them.
        engine = create_engine(DATABASE_URL, pool_pre_ping=True)
        try:
            with engine.connect() as connection:
                run_migrations(connection)
        finally:
            engine.dispose()


if context.is_offline_mode():
    raise RuntimeError('Offline SQL generation is disabled for this guarded baseline')
run_online()

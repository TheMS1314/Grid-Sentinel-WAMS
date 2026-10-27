import os
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session


if os.getenv('POSTGRES_PASSWORD'):
    DATABASE_URL = URL.create(
        drivername='postgresql+psycopg',
        username=os.getenv('POSTGRES_USER', 'smartgrid'),
        password=os.environ['POSTGRES_PASSWORD'],
        host=os.getenv('POSTGRES_HOST', 'db'),
        port=int(os.getenv('POSTGRES_PORT', '5432')),
        database=os.getenv('POSTGRES_DB', 'smartgrid'),
    )
else:
    DATABASE_URL = os.environ.get(
        'DATABASE_URL',
        'postgresql+psycopg://smartgrid:smartgrid@localhost:5432/smartgrid',
    )

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5, max_overflow=5)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

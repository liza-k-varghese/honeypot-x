"""
PostgreSQL connection layer (SQLAlchemy). Primary structured database —
Group 1 infra + backing store for AttackEvents, Users, Alerts, etc.
(see app/models.py for the full entity list from the master plan).
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,   # avoids using a connection PostgreSQL already dropped
    pool_size=10,
    max_overflow=20,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a session, always closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



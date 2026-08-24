"""
Run once (or on every container start — it's idempotent) to create every
table from app/models.py and seed the data the system can't boot without:
a default admin user and the three honeypot rows System 2 reports into.

    python -m app.init_db
"""

from app.core.config import settings
from app.core.security import hash_password
from app.db.postgres import Base, SessionLocal, engine
from app import models


def init_db():
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        _seed_admin_user(db)
        _seed_honeypots(db)
        db.commit()
    finally:
        db.close()


def _seed_admin_user(db):
    existing = db.query(models.User).filter_by(username="admin").first()
    if existing:
        return
    admin_password = settings.__dict__.get("INITIAL_ADMIN_PASSWORD") or "ChangeMe123!"
    db.add(models.User(
        username="admin",
        email="admin@honeyshield.local",
        hashed_password=hash_password(admin_password),
        role="admin",
    ))
    print(f"Seeded default admin user (username=admin, password={admin_password}) — change this immediately.")


def _seed_honeypots(db):
    defaults = [
        {"name": "cowrie", "service_type": "ssh", "host": "system2", "port": 2222},
        {"name": "cowrie-telnet", "service_type": "telnet", "host": "system2", "port": 2223},
        {"name": "opencanary-http", "service_type": "http", "host": "system2", "port": 8080},
        {"name": "opencanary-ftp", "service_type": "ftp", "host": "system2", "port": 21},
        {"name": "opencanary-smb", "service_type": "smb", "host": "system2", "port": 445},
        {"name": "dionaea", "service_type": "malware", "host": "system2", "port": 445},
    ]
    for hp in defaults:
        existing = db.query(models.Honeypot).filter_by(name=hp["name"]).first()
        if not existing:
            db.add(models.Honeypot(**hp))


if __name__ == "__main__":
    init_db()



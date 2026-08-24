"""
HoneyShield X SOC Backend — FastAPI application entry point.

    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload   # dev
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4  # prod

Run app/init_db.py once before starting this (creates tables + seeds the
default admin user), and app/workers/ingestion_worker.py as a separate
long-lived process alongside it.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    ai, alerts, attacks, auth, config, correlation, deception,
    esp32, evidence, health, playbooks, reports, threat_intel, users,
)
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Best-effort — a Neo4j hiccup at startup shouldn't prevent the API
    # itself from serving requests (most routes don't touch Neo4j at all).
    try:
        from app.db import neo4j_client
        neo4j_client.ensure_constraints()
    except Exception as exc:  # noqa: BLE001
        import logging
        logging.getLogger("startup").warning("Neo4j constraint setup skipped: %s", exc)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Assisted Multi-Layer Honeypot, Threat Intelligence, Attack Correlation & Adaptive Cybersecurity Monitoring System",
    version="1.0.0",
    debug=settings.DEBUG,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(attacks.router)
app.include_router(alerts.router)
app.include_router(threat_intel.router)
app.include_router(correlation.router)
app.include_router(ai.router)
app.include_router(reports.router)
app.include_router(esp32.router)
app.include_router(health.router)
app.include_router(deception.router)
app.include_router(evidence.router)
app.include_router(evidence.incidents_router)
app.include_router(config.router)
app.include_router(playbooks.router)


@app.get("/")
def root():
    return {"service": settings.APP_NAME, "status": "running"}


@app.get("/api/ping")
def ping():
    return {"pong": True}



"""
HoneyShield X — Ingestion Worker.

Long-lived background process that continuously polls OpenSearch indices,
normalizes log events, correlates sessions, enriches threat intelligence,
runs detection & AI inference, triggers response playbooks, and updates
Neo4j graph relationships.

Usage:
    python -m app.workers.ingestion_worker          # run continuous loop
    python -m app.workers.ingestion_worker --once   # single batch pass
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timedelta, timezone

from app import models
from app.core.config import settings
from app.db import neo4j_client, opensearch_client, redis_client
from app.db.postgres import SessionLocal
from app.services import (
    ai_engine, alerting, correlation, deception, detection,
    log_normalization, playbooks, threat_intel,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [ingestion_worker] %(message)s",
)
logger = logging.getLogger("ingestion_worker")

SOURCES = ["cowrie", "opencanary", "dionaea", "zeek", "suricata"]


def process_event(db, source: str, raw_doc: dict):
    """Processes a single raw log event end-to-end."""
    norm = log_normalization.normalize(source, raw_doc)
    if not norm:
        return

    src_ip = norm["src_ip"]
    occurred_at = norm["occurred_at"]
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=timezone.utc)

    # 1. Find or create AttackSession
    session = None
    if norm.get("session_external_id"):
        session = (
            db.query(models.AttackSession)
            .filter(models.AttackSession.external_session_id == norm["session_external_id"])
            .first()
        )

    if session is None and src_ip != "unknown":
        # Find open session from this IP within last 30 minutes
        recent_cutoff = occurred_at - timedelta(minutes=30)
        session = (
            db.query(models.AttackSession)
            .filter(
                models.AttackSession.src_ip == src_ip,
                models.AttackSession.started_at >= recent_cutoff,
            )
            .order_by(models.AttackSession.started_at.desc())
            .first()
        )

    if session is None:
        session = models.AttackSession(
            external_session_id=norm.get("session_external_id"),
            src_ip=src_ip,
            src_port=None,
            dst_port=norm.get("dst_port"),
            started_at=occurred_at,
            ended_at=occurred_at,
            login_attempt_count=0,
            had_successful_login=False,
            command_count=0,
            high_risk_command_count=0,
            severity="info",
        )
        db.add(session)
        db.flush()

    # 2. Update session state based on event type
    if norm["event_type"] == "login_attempt":
        session.login_attempt_count += 1
    elif norm["event_type"] == "login_success":
        session.had_successful_login = True
    elif norm["event_type"] == "command" and norm.get("command"):
        session.command_count += 1
        high_risk = detection.find_high_risk_commands([norm["command"]])
        if high_risk:
            session.high_risk_command_count += len(high_risk)

    session.ended_at = max(session.ended_at or occurred_at, occurred_at)

    # 3. Create AttackEvent record
    event_row = models.AttackEvent(
        session_id=session.id,
        source=norm["source"],
        event_type=norm["event_type"],
        src_ip=src_ip,
        dst_ip=norm.get("dst_ip"),
        dst_port=norm.get("dst_port"),
        protocol=norm.get("protocol"),
        username=norm.get("username"),
        password=norm.get("password"),
        command=norm.get("command"),
        ids_signature=norm.get("ids_signature"),
        raw_json=norm.get("raw_json"),
        occurred_at=occurred_at,
    )
    db.add(event_row)

    # 4. Check Deception Canary Triggers
    deception_triggered = False
    if norm.get("command"):
        canary_hit = deception.check_canary_access(norm["command"])
        if canary_hit:
            deception_triggered = True
            db.add(models.Alert(
                session_id=session.id,
                title=f"Deception Canary Triggered [{canary_hit['canary_path']}]",
                description=f"Attacker accessed decoy canary asset: {canary_hit['canary_path']} (cmd: {norm['command']})",
                severity="critical",
                source="deception",
                status="open",
            ))

    # 5. Threat Intelligence Enrichment (cached / on-demand)
    reputation_score = None
    if src_ip != "unknown":
        ti = db.query(models.ThreatIntelligence).filter_by(ip_address=src_ip).first()
        if ti is None:
            ti_data = threat_intel.enrich(src_ip)
            ti = models.ThreatIntelligence(**ti_data)
            ti.total_attack_count = 1
            db.add(ti)
        else:
            ti.total_attack_count = (ti.total_attack_count or 0) + 1
            ti.last_seen = occurred_at
            reputation_score = ti.reputation_score

    # 6. Severity & Detection Analysis
    is_bf = detection.is_brute_force(session.login_attempt_count)
    computed_severity = detection.classify_severity(
        had_successful_login=session.had_successful_login,
        high_risk_command_count=session.high_risk_command_count,
        is_brute_force_flag=is_bf,
        is_port_scan_flag=False,
        is_repeated_attack_flag=False,
        is_abnormal_flag=False,
        threat_intel_reputation_score=reputation_score,
    )
    if deception_triggered:
        computed_severity = "critical"
    session.severity = computed_severity

    # 7. AI Inference
    feat_vector = ai_engine.extract_features({
        "started_at": session.started_at,
        "ended_at": session.ended_at,
        "login_attempt_count": session.login_attempt_count,
        "had_successful_login": session.had_successful_login,
        "command_count": session.command_count,
        "high_risk_command_count": session.high_risk_command_count,
    })
    is_anom, anom_score = ai_engine.score_anomaly(feat_vector)
    ai_class, ai_conf = ai_engine.classify_attack(feat_vector)

    session.risk_score = anom_score
    session.ai_classification = ai_class
    session.ai_confidence = ai_conf

    # 8. Alert Generation for high/critical events
    if computed_severity in ["high", "critical"] and not deception_triggered:
        # Check if alert already exists for this session
        existing_alert = db.query(models.Alert).filter_by(session_id=session.id).first()
        if not existing_alert:
            alert_obj = models.Alert(
                session_id=session.id,
                title=f"Attack Detected: {ai_class or computed_severity.upper()} from {src_ip}",
                description=f"Severity {computed_severity}: {session.login_attempt_count} logins, {session.high_risk_command_count} high-risk commands",
                severity=computed_severity,
                source="detection_engine",
                status="open",
            )
            db.add(alert_obj)
            db.flush()
            redis_client.push_alert(json.dumps({
                "alert_id": str(alert_obj.id),
                "title": alert_obj.title,
                "severity": alert_obj.severity,
                "src_ip": src_ip,
            }))

    # 9. Automated Response Playbooks
    playbook_context = {
        "src_ip": src_ip,
        "session_id": str(session.id),
        "severity": computed_severity,
        "had_successful_login": session.had_successful_login,
        "high_risk_command_count": session.high_risk_command_count,
        "is_anomalous": is_anom,
        "source": "deception" if deception_triggered else norm["source"],
    }
    action_results = playbooks.run(playbook_context)
    for act in action_results:
        db.add(models.ResponseAction(
            session_id=session.id,
            playbook_name=act["playbook_name"],
            action_type=act["action_type"],
            target=act.get("target"),
            success=act.get("success", False),
            skipped=act.get("skipped", False),
            detail=act.get("detail"),
        ))

    # 10. Sync to Neo4j Graph (best-effort)
    try:
        correlation.sync_ip_attacked_honeypot(src_ip, norm["source"])
        correlation.sync_ip_generated_session(src_ip, str(session.id), session.started_at)
        if norm.get("command"):
            correlation.sync_session_command(str(session.id), norm["command"])
        if norm.get("dst_port"):
            correlation.sync_session_service(str(session.id), f"port-{norm['dst_port']}")
    except Exception as exc:
        logger.debug("Neo4j graph sync skipped: %s", exc)

    db.commit()


def run_poll_cycle():
    """Runs a single polling cycle across all log sources."""
    db = SessionLocal()
    try:
        for source in SOURCES:
            checkpoint = redis_client.get_ingestion_checkpoint(source)
            if not checkpoint:
                checkpoint = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

            index_pattern = f"{source}-logs-*" if source != "suricata" else "suricata-alerts-*"
            try:
                docs = opensearch_client.poll_new_documents(index_pattern, since_iso=checkpoint, size=100)
            except Exception as exc:
                logger.debug("Could not poll index %s: %s", index_pattern, exc)
                continue

            last_ts = checkpoint
            for doc in docs:
                try:
                    process_event(db, source, doc)
                    if "@timestamp" in doc:
                        last_ts = max(last_ts, doc["@timestamp"])
                except Exception as exc:
                    logger.error("Error processing %s doc: %s", source, exc)
                    db.rollback()

            if docs and last_ts != checkpoint:
                redis_client.set_ingestion_checkpoint(source, last_ts)
                logger.info("Ingested %d events from %s (checkpoint: %s)", len(docs), source, last_ts)
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="HoneyShield X Log Ingestion Worker")
    parser.add_argument("--once", action="store_true", help="Run a single poll pass and exit")
    parser.add_argument("--interval", type=float, default=2.0, help="Poll interval in seconds")
    args = parser.parse_args()

    logger.info("HoneyShield X Ingestion Worker started (interval=%.1fs, once=%s)", args.interval, args.once)

    while True:
        try:
            run_poll_cycle()
        except Exception as exc:
            logger.error("Error in ingestion poll cycle: %s", exc)

        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()

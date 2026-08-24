"""
Attack Correlation & Campaign Analysis — Group 8.

Split deliberately into two kinds of functions:
  - `build_*_query()` — pure functions returning (cypher_string, params).
    No driver needed, so the query-construction logic itself is unit
    testable (see tests/test_correlation.py) even without a live Neo4j
    instance in this environment.
  - `sync_*()` — thin wrappers that call the builders and execute via
    app.db.neo4j_client.run_query(). These need a real Neo4j connection
    and are what app/workers/ingestion_worker.py calls per event.

Graph shape matches the master plan exactly:
    IP -[ATTACKED]-> Honeypot
    IP -[GENERATED]-> Session
    Session -[EXECUTED]-> Command
    Session -[TARGETED]-> Service
    IP -[ASSOCIATED_WITH]-> Campaign
"""

from collections import defaultdict
from datetime import datetime, timedelta

from app.db import neo4j_client


# ---------------------------------------------------------------------------
# Query builders (pure, testable)
# ---------------------------------------------------------------------------

def build_merge_ip_query(ip_address: str):
    return (
        "MERGE (i:IP {address: $ip}) "
        "ON CREATE SET i.first_seen = datetime() "
        "SET i.last_seen = datetime() "
        "RETURN i",
        {"ip": ip_address},
    )


def build_link_ip_attacked_honeypot_query(ip_address: str, honeypot_name: str):
    return (
        "MERGE (i:IP {address: $ip}) "
        "MERGE (h:Honeypot {name: $honeypot}) "
        "MERGE (i)-[r:ATTACKED]->(h) "
        "ON CREATE SET r.count = 1 "
        "ON MATCH SET r.count = r.count + 1 "
        "RETURN r",
        {"ip": ip_address, "honeypot": honeypot_name},
    )


def build_link_ip_generated_session_query(ip_address: str, session_id: str, started_at: datetime):
    return (
        "MERGE (i:IP {address: $ip}) "
        "MERGE (s:Session {session_id: $session_id}) "
        "ON CREATE SET s.started_at = $started_at "
        "MERGE (i)-[:GENERATED]->(s) "
        "RETURN s",
        {"ip": ip_address, "session_id": session_id, "started_at": started_at.isoformat()},
    )


def build_link_session_executed_command_query(session_id: str, command_text: str):
    return (
        "MERGE (s:Session {session_id: $session_id}) "
        "MERGE (c:Command {text: $command}) "
        "MERGE (s)-[:EXECUTED]->(c) "
        "RETURN c",
        {"session_id": session_id, "command": command_text},
    )


def build_link_session_targeted_service_query(session_id: str, service_name: str):
    return (
        "MERGE (s:Session {session_id: $session_id}) "
        "MERGE (svc:Service {name: $service}) "
        "MERGE (s)-[:TARGETED]->(svc) "
        "RETURN svc",
        {"session_id": session_id, "service": service_name},
    )


def build_link_ip_campaign_query(ip_address: str, campaign_id: str):
    return (
        "MERGE (i:IP {address: $ip}) "
        "MERGE (c:Campaign {campaign_id: $campaign_id}) "
        "MERGE (i)-[:ASSOCIATED_WITH]->(c) "
        "RETURN c",
        {"ip": ip_address, "campaign_id": campaign_id},
    )


def build_timeline_query(ip_address: str, limit: int = 100):
    """Reconstructs a chronological timeline of everything one IP is
    connected to — Feature 79 (Attack Timeline Reconstruction)."""
    return (
        "MATCH (i:IP {address: $ip})-[:GENERATED]->(s:Session) "
        "OPTIONAL MATCH (s)-[:EXECUTED]->(c:Command) "
        "OPTIONAL MATCH (s)-[:TARGETED]->(svc:Service) "
        "RETURN s.session_id AS session_id, s.started_at AS started_at, "
        "       collect(DISTINCT c.text) AS commands, collect(DISTINCT svc.name) AS services "
        "ORDER BY s.started_at ASC LIMIT $limit",
        {"ip": ip_address, "limit": limit},
    )


def build_relationship_graph_query(ip_address: str, depth: int = 2):
    """Feature 80 (Threat Relationship Graph) — everything within `depth`
    hops of one IP, for the dashboard's interactive graph view."""
    return (
        f"MATCH path = (i:IP {{address: $ip}})-[*1..{depth}]-(connected) "
        "RETURN path LIMIT 200",
        {"ip": ip_address},
    )


def build_cross_honeypot_correlation_query(ip_address: str):
    """Feature 77 — has this IP hit more than one honeypot service?"""
    return (
        "MATCH (i:IP {address: $ip})-[:ATTACKED]->(h:Honeypot) "
        "RETURN collect(DISTINCT h.name) AS honeypots_hit, count(DISTINCT h) AS honeypot_count",
        {"ip": ip_address},
    )


# ---------------------------------------------------------------------------
# Execution wrappers (need a live Neo4j connection)
# ---------------------------------------------------------------------------

def sync_ip_attacked_honeypot(ip_address: str, honeypot_name: str):
    query, params = build_link_ip_attacked_honeypot_query(ip_address, honeypot_name)
    neo4j_client.run_query(query, params)


def sync_ip_generated_session(ip_address: str, session_id: str, started_at: datetime):
    query, params = build_link_ip_generated_session_query(ip_address, session_id, started_at)
    neo4j_client.run_query(query, params)


def sync_session_command(session_id: str, command_text: str):
    query, params = build_link_session_executed_command_query(session_id, command_text)
    neo4j_client.run_query(query, params)


def sync_session_service(session_id: str, service_name: str):
    query, params = build_link_session_targeted_service_query(session_id, service_name)
    neo4j_client.run_query(query, params)


def get_timeline(ip_address: str) -> list[dict]:
    query, params = build_timeline_query(ip_address)
    return neo4j_client.run_query(query, params)


def get_cross_honeypot_correlation(ip_address: str) -> dict:
    query, params = build_cross_honeypot_correlation_query(ip_address)
    results = neo4j_client.run_query(query, params)
    return results[0] if results else {"honeypots_hit": [], "honeypot_count": 0}


# ---------------------------------------------------------------------------
# Feature 78: Campaign Identification — pure Python clustering logic,
# fully testable without any database at all.
# ---------------------------------------------------------------------------

def identify_campaigns(
    sessions: list[dict],
    time_window_minutes: int = 60,
    min_sessions: int = 3,
    min_distinct_ips: int = 2,
) -> list[dict]:
    """Groups sessions into candidate campaigns.

    A "campaign" here means: multiple sessions, from at least
    `min_distinct_ips` different source IPs, targeting the same service,
    clustered close enough in time (no gap larger than
    `time_window_minutes` between consecutive sessions in the cluster) to
    plausibly be coordinated or tool-driven activity rather than
    coincidence. This deliberately requires >1 IP — a single IP hitting
    the honeypot repeatedly is already covered by
    detection.is_repeated_attack() and isn't a "campaign" on its own.

    Each session dict needs: session_id, src_ip, started_at (datetime),
    target_service (str).
    """
    by_service = defaultdict(list)
    for s in sessions:
        by_service[s["target_service"]].append(s)

    campaigns = []
    window = timedelta(minutes=time_window_minutes)

    for service, service_sessions in by_service.items():
        ordered = sorted(service_sessions, key=lambda s: s["started_at"])
        cluster = []

        def flush_cluster(cluster):
            if len(cluster) < min_sessions:
                return
            distinct_ips = {s["src_ip"] for s in cluster}
            if len(distinct_ips) < min_distinct_ips:
                return
            campaigns.append({
                "target_service": service,
                "session_ids": [s["session_id"] for s in cluster],
                "source_ips": sorted(distinct_ips),
                "first_seen": cluster[0]["started_at"],
                "last_seen": cluster[-1]["started_at"],
                "session_count": len(cluster),
                "source_ip_count": len(distinct_ips),
            })

        for session in ordered:
            if cluster and (session["started_at"] - cluster[-1]["started_at"]) > window:
                flush_cluster(cluster)
                cluster = []
            cluster.append(session)
        flush_cluster(cluster)

    return campaigns



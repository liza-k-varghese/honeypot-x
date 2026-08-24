"""
Attack Correlation & Campaign Analysis API routes — Group 8 (Features 71-80).
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user, require_role
from app.core import security
from app.db import neo4j_client
from app.db.postgres import get_db
from app.services import audit, correlation

router = APIRouter(prefix="/api/correlation", tags=["correlation"])


@router.get("/campaigns", response_model=list[schemas.CampaignOut])
def list_campaigns(
    limit: int = Query(50, le=200),
    severity: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List identified attack campaigns."""
    query = db.query(models.Campaign)
    if severity:
        query = query.filter(models.Campaign.severity == severity)
    return query.order_by(models.Campaign.last_seen.desc()).limit(limit).all()


@router.get("/timeline/{ip_address}")
def get_attack_timeline(
    ip_address: str,
    limit: int = Query(100, le=500),
    _=Depends(get_current_user),
):
    """Feature 79: Attack Timeline Reconstruction — chronological graph
    timeline of sessions, commands, and services associated with an IP."""
    try:
        timeline = correlation.get_timeline(ip_address)
        return {"ip_address": ip_address, "timeline": timeline}
    except Exception as exc:
        return {"ip_address": ip_address, "timeline": [], "note": str(exc)}


@router.get("/cross-honeypot/{ip_address}")
def get_cross_honeypot(
    ip_address: str,
    _=Depends(get_current_user),
):
    """Feature 77: Cross-Honeypot Correlation — checks if an IP has
    interacted across multiple honeypots."""
    try:
        return correlation.get_cross_honeypot_correlation(ip_address)
    except Exception as exc:
        return {"honeypots_hit": [], "honeypot_count": 0, "note": str(exc)}


@router.get("/graph", response_model=schemas.GraphResponse)
def get_relationship_graph(
    ip: str | None = None,
    depth: int = Query(2, ge=1, le=3),
    _=Depends(get_current_user),
):
    """Feature 80: Threat Relationship Graph — returns nodes and edges
    for interactive visual attack graphs."""
    nodes = []
    edges = []
    node_ids = set()

    try:
        if ip:
            query, params = correlation.build_relationship_graph_query(ip, depth=depth)
            records = neo4j_client.run_query(query, params)
        else:
            # General recent overview query
            query = (
                "MATCH (i:IP)-[r:ATTACKED]->(h:Honeypot) "
                "RETURN i.address AS src, h.name AS dst, type(r) AS rel, r.count AS count "
                "LIMIT 100"
            )
            records = neo4j_client.run_query(query)
            for rec in records:
                src_ip = rec.get("src")
                dst_hp = rec.get("dst")
                if src_ip and src_ip not in node_ids:
                    nodes.append(schemas.GraphNode(id=src_ip, label=src_ip, type="IP"))
                    node_ids.add(src_ip)
                if dst_hp and dst_hp not in node_ids:
                    nodes.append(schemas.GraphNode(id=dst_hp, label=dst_hp, type="Honeypot"))
                    node_ids.add(dst_hp)
                if src_ip and dst_hp:
                    edges.append(schemas.GraphEdge(source=src_ip, target=dst_hp, relationship=rec.get("rel", "ATTACKED")))
            return schemas.GraphResponse(nodes=nodes, edges=edges)

        # Parse graph paths from deep query if ip specified
        for rec in records:
            path = rec.get("path")
            if hasattr(path, "nodes") and hasattr(path, "relationships"):
                for n in path.nodes:
                    nid = str(n.element_id if hasattr(n, "element_id") else n.id)
                    lbl = n.get("address") or n.get("name") or n.get("session_id") or n.get("text") or nid
                    ntype = list(n.labels)[0] if n.labels else "Node"
                    if nid not in node_ids:
                        nodes.append(schemas.GraphNode(id=nid, label=str(lbl), type=ntype))
                        node_ids.add(nid)
                for r in path.relationships:
                    start_id = str(r.start_node.element_id if hasattr(r.start_node, "element_id") else r.start_node.id)
                    end_id = str(r.end_node.element_id if hasattr(r.end_node, "element_id") else r.end_node.id)
                    edges.append(schemas.GraphEdge(source=start_id, target=end_id, relationship=r.type))

    except Exception:
        # Fallback if Neo4j is not reachable
        pass

    return schemas.GraphResponse(nodes=nodes, edges=edges)


@router.post(
    "/identify-campaigns",
    response_model=list[schemas.CampaignOut],
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def run_campaign_identification(
    lookback_hours: int = Query(24, ge=1, le=168),
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Feature 78: Campaign Identification — clusters recent sessions into
    coordinated attack campaigns and saves them."""
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    sessions = db.query(models.AttackSession).filter(
        models.AttackSession.started_at >= since
    ).all()

    session_dicts = [
        {
            "session_id": str(s.id),
            "src_ip": s.src_ip,
            "started_at": s.started_at,
            "target_service": f"port-{s.dst_port}" if s.dst_port else "generic",
        }
        for s in sessions
    ]

    identified = correlation.identify_campaigns(session_dicts)
    created_campaigns = []

    for c in identified:
        name = f"Campaign against {c['target_service']} ({len(c['source_ips'])} IPs)"
        camp = models.Campaign(
            name=name,
            description=f"Automated cluster of {c['session_count']} sessions across {c['source_ip_count']} IPs",
            first_seen=c["first_seen"],
            last_seen=c["last_seen"],
            source_ip_count=c["source_ip_count"],
            session_count=c["session_count"],
            severity="high" if c["source_ip_count"] >= 5 else "medium",
        )
        db.add(camp)
        db.flush()
        created_campaigns.append(camp)

        # Link in Neo4j if driver is available
        try:
            for ip_addr in c["source_ips"]:
                query, params = correlation.build_link_ip_campaign_query(ip_addr, str(camp.id))
                neo4j_client.run_query(query, params)
        except Exception:
            pass

    if created_campaigns:
        db.add(models.AuditLog(**audit.build_audit_entry(
            user_id=str(current_user.id),
            action="correlation.campaign_clustering",
            target_type="campaign",
            details={"campaigns_identified": len(created_campaigns)},
            ip_address=get_client_ip(request) if request else "unknown",
        )))

    db.commit()
    for camp in created_campaigns:
        db.refresh(camp)

    return created_campaigns

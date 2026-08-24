"""
AI & Machine Learning Engine API routes — Group 7 (Features 61-70).
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user, require_role
from app.core import security
from app.db.postgres import get_db
from app.services import ai_engine, audit

router = APIRouter(prefix="/api/ai", tags=["ai"])


class ClassifyRequest(BaseModel):
    session_id: str | None = None
    features: list[float] | None = None


class AnomalyRequest(BaseModel):
    session_id: str | None = None
    features: list[float] | None = None


class SimilarityRequest(BaseModel):
    session_id_a: str
    session_id_b: str


@router.post("/classify")
def classify_session(
    payload: ClassifyRequest,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Features 61, 69: AI Attack Classification & Confidence Score."""
    if payload.features is not None:
        features = payload.features
    elif payload.session_id is not None:
        sess = db.query(models.AttackSession).filter(models.AttackSession.id == payload.session_id).first()
        if sess is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
        features = ai_engine.extract_features({
            "started_at": sess.started_at,
            "ended_at": sess.ended_at,
            "login_attempt_count": sess.login_attempt_count,
            "had_successful_login": sess.had_successful_login,
            "command_count": sess.command_count,
            "high_risk_command_count": sess.high_risk_command_count,
        })
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Must provide either features or session_id")

    classification, confidence = ai_engine.classify_attack(features)
    return {
        "classification": classification or "unclassified",
        "confidence": round(confidence, 4) if confidence is not None else None,
        "features": features,
    }


@router.post("/anomaly")
def check_anomaly(
    payload: AnomalyRequest,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Feature 64: Anomaly Detection."""
    if payload.features is not None:
        features = payload.features
    elif payload.session_id is not None:
        sess = db.query(models.AttackSession).filter(models.AttackSession.id == payload.session_id).first()
        if sess is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
        features = ai_engine.extract_features({
            "started_at": sess.started_at,
            "ended_at": sess.ended_at,
            "login_attempt_count": sess.login_attempt_count,
            "had_successful_login": sess.had_successful_login,
            "command_count": sess.command_count,
            "high_risk_command_count": sess.high_risk_command_count,
        })
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Must provide either features or session_id")

    is_anomalous, score = ai_engine.score_anomaly(features)
    return {
        "is_anomalous": is_anomalous,
        "anomaly_score": round(score, 4) if score is not None else None,
        "features": features,
    }


@router.post("/similarity")
def check_similarity(
    payload: SimilarityRequest,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Feature 67: Session Similarity Analysis."""
    s1 = db.query(models.AttackSession).filter(models.AttackSession.id == payload.session_id_a).first()
    s2 = db.query(models.AttackSession).filter(models.AttackSession.id == payload.session_id_b).first()
    if not s1 or not s2:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "One or both sessions not found")

    f1 = ai_engine.extract_features({
        "started_at": s1.started_at, "ended_at": s1.ended_at,
        "login_attempt_count": s1.login_attempt_count, "had_successful_login": s1.had_successful_login,
        "command_count": s1.command_count, "high_risk_command_count": s1.high_risk_command_count,
    })
    f2 = ai_engine.extract_features({
        "started_at": s2.started_at, "ended_at": s2.ended_at,
        "login_attempt_count": s2.login_attempt_count, "had_successful_login": s2.had_successful_login,
        "command_count": s2.command_count, "high_risk_command_count": s2.high_risk_command_count,
    })

    sim = ai_engine.session_similarity(f1, f2)
    return {
        "session_a": payload.session_id_a,
        "session_b": payload.session_id_b,
        "similarity_score": round(sim, 4),
    }


@router.get("/clusters")
def get_attack_clusters(
    limit: int = Query(100, le=500),
    n_clusters: int = Query(4, ge=2, le=10),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Feature 68: Attack Clustering."""
    sessions = db.query(models.AttackSession).order_by(models.AttackSession.started_at.desc()).limit(limit).all()
    if not sessions:
        return {"clusters": []}

    rows = []
    session_ids = []
    for s in sessions:
        rows.append(ai_engine.extract_features({
            "started_at": s.started_at, "ended_at": s.ended_at,
            "login_attempt_count": s.login_attempt_count, "had_successful_login": s.had_successful_login,
            "command_count": s.command_count, "high_risk_command_count": s.high_risk_command_count,
        }))
        session_ids.append(str(s.id))

    labels = ai_engine.cluster_attacks(rows, n_clusters=n_clusters)
    result = [
        {"session_id": sid, "cluster": label, "src_ip": sess.src_ip, "severity": sess.severity}
        for sid, label, sess in zip(session_ids, labels, sessions)
    ]
    return {"cluster_count": n_clusters, "assignments": result}


@router.post(
    "/retrain",
    dependencies=[Depends(require_role(security.ROLE_ADMIN))],
)
def retrain_models(
    request: Request,
    from_synthetic: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Retrain AI anomaly detection and classification models."""
    from scripts import train_ai_models

    if from_synthetic:
        train_ai_models.train_from_synthetic()
        source = "synthetic"
    else:
        # Check if enough database sessions exist
        session_count = db.query(models.AttackSession).count()
        if session_count < 10:
            # Fall back to synthetic with warning
            train_ai_models.train_from_synthetic()
            source = "synthetic (fallback due to <10 DB sessions)"
        else:
            train_ai_models.train_from_database(db)
            source = "database"

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id),
        action="ai.retrain_models",
        target_type="ai_engine",
        details={"source": source},
        ip_address=get_client_ip(request),
    )))
    db.commit()

    return {"status": "success", "training_source": source}

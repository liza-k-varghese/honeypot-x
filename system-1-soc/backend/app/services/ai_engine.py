"""
AI / Machine Learning Engine — Group 7.

Three models, all scikit-learn (matches the master plan's software list
exactly — "Additional deep-learning frameworks should only be added if
the project actually requires them," and for session-level tabular
features like these, it doesn't):

  - IsolationForest   -> anomaly detection (Feature 64)
  - RandomForestClassifier -> attack classification + confidence (Features 61, 69)
  - KMeans            -> attack clustering (Feature 68)

Feature extraction (extract_features) is a pure function shared by all
three, so a session is only ever turned into numbers one way — see
tests/test_ai_engine.py.

This extends the same IsolationForest approach already built and proven
out in the companion smart-firewall-honeypot project's
automation/ml_detector.py; the class imbalance / calibration lessons
learned there (use decision_function's calibrated boundary, not a
hand-picked score_samples cutoff; make sure training data covers
"stealthy" attack shapes, not just extreme ones) apply here too.
"""

import os
from datetime import datetime

import numpy as np

from app.core.config import settings

FEATURE_NAMES = [
    "login_attempt_count",
    "unique_usernames",
    "unique_passwords",
    "had_successful_login",
    "command_count",
    "high_risk_command_count",
    "duration_seconds",
    "avg_seconds_between_events",
    "distinct_services_targeted",
]

ATTACK_CLASSES = ["reconnaissance", "brute_force", "exploitation", "malware_delivery", "benign_scan"]

_anomaly_model_cache = None
_anomaly_model_mtime = None
_classifier_cache = None
_classifier_mtime = None


# ---------------------------------------------------------------------------
# Feature extraction (pure, shared by every model)
# ---------------------------------------------------------------------------

def extract_features(session: dict) -> list[float]:
    """session: a dict with the same shape as app.models.AttackSession's
    columns (or a plain dict with matching keys, for tests). Missing keys
    default sensibly rather than raising, since not every caller will
    have every field populated (e.g. a session still in progress has no
    duration yet)."""
    started_at = session.get("started_at")
    ended_at = session.get("ended_at")
    if started_at and ended_at:
        duration = (ended_at - started_at).total_seconds()
    else:
        duration = session.get("duration_seconds", 0.0)

    command_count = session.get("command_count", 0)
    span = duration if duration else 0.0
    avg_gap = span / command_count if command_count else span

    return [
        session.get("login_attempt_count", 0),
        session.get("unique_usernames", 0),
        session.get("unique_passwords", 0),
        1 if session.get("had_successful_login") else 0,
        command_count,
        session.get("high_risk_command_count", 0),
        duration,
        avg_gap,
        session.get("distinct_services_targeted", 1),
    ]


# ---------------------------------------------------------------------------
# Feature 64: Anomaly Detection (IsolationForest)
# ---------------------------------------------------------------------------

def train_anomaly_model(feature_rows: list[list[float]], contamination: float = 0.2):
    from sklearn.ensemble import IsolationForest
    import joblib

    if len(feature_rows) < 10:
        raise ValueError(f"Need at least 10 samples to train, got {len(feature_rows)}")

    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    model.fit(feature_rows)

    os.makedirs(os.path.dirname(settings.ANOMALY_MODEL_PATH), exist_ok=True)
    joblib.dump(model, settings.ANOMALY_MODEL_PATH)
    return model


def _load_anomaly_model():
    global _anomaly_model_cache, _anomaly_model_mtime
    import joblib

    if not os.path.exists(settings.ANOMALY_MODEL_PATH):
        return None
    mtime = os.path.getmtime(settings.ANOMALY_MODEL_PATH)
    if _anomaly_model_cache is None or mtime != _anomaly_model_mtime:
        _anomaly_model_cache = joblib.load(settings.ANOMALY_MODEL_PATH)
        _anomaly_model_mtime = mtime
    return _anomaly_model_cache


def score_anomaly(feature_vector: list[float]):
    """Returns (is_anomalous, score). See the companion project's
    ml_detector.py for why decision_function (not raw score_samples) is
    the right thing to threshold against."""
    model = _load_anomaly_model()
    if model is None:
        return False, None
    score = float(model.decision_function([feature_vector])[0])
    return score < settings.ANOMALY_SCORE_THRESHOLD, score


# ---------------------------------------------------------------------------
# Features 61, 69: Attack Classification + AI Confidence Score
# ---------------------------------------------------------------------------

def train_classifier(feature_rows: list[list[float]], labels: list[str]):
    from sklearn.ensemble import RandomForestClassifier
    import joblib

    if len(feature_rows) != len(labels):
        raise ValueError("feature_rows and labels must be the same length")
    if len(feature_rows) < 10:
        raise ValueError(f"Need at least 10 labeled samples to train, got {len(feature_rows)}")

    model = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42)
    model.fit(feature_rows, labels)

    os.makedirs(os.path.dirname(settings.CLASSIFIER_MODEL_PATH), exist_ok=True)
    joblib.dump(model, settings.CLASSIFIER_MODEL_PATH)
    return model


def _load_classifier():
    global _classifier_cache, _classifier_mtime
    import joblib

    if not os.path.exists(settings.CLASSIFIER_MODEL_PATH):
        return None
    mtime = os.path.getmtime(settings.CLASSIFIER_MODEL_PATH)
    if _classifier_cache is None or mtime != _classifier_mtime:
        _classifier_cache = joblib.load(settings.CLASSIFIER_MODEL_PATH)
        _classifier_mtime = mtime
    return _classifier_cache


def classify_attack(feature_vector: list[float]):
    """Returns (predicted_label, confidence 0-1) — Feature 69: AI
    Confidence Score is literally the model's own max class probability,
    not a separate fabricated number, so it's honest about how sure the
    model actually is."""
    model = _load_classifier()
    if model is None:
        return None, None
    proba = model.predict_proba([feature_vector])[0]
    classes = model.classes_
    best_idx = int(np.argmax(proba))
    return classes[best_idx], float(proba[best_idx])


# ---------------------------------------------------------------------------
# Feature 68: Attack Clustering
# ---------------------------------------------------------------------------

def cluster_attacks(feature_rows: list[list[float]], n_clusters: int = 4) -> list[int]:
    """Groups sessions by behavioral similarity — returns a cluster label
    (0..n_clusters-1) per input row, same order as feature_rows. Standard-
    scales first since these features are on wildly different scales
    (a 0/1 flag next to a duration in seconds), which would otherwise let
    duration alone dominate the distance metric."""
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler

    if len(feature_rows) < n_clusters:
        # not enough data to form the requested number of clusters — put
        # everything in cluster 0 rather than erroring
        return [0] * len(feature_rows)

    scaled = StandardScaler().fit_transform(feature_rows)
    model = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = model.fit_predict(scaled)
    return labels.tolist()


# ---------------------------------------------------------------------------
# Feature 67: Session Similarity Analysis
# ---------------------------------------------------------------------------

def session_similarity(feature_vector_a: list[float], feature_vector_b: list[float]) -> float:
    """Cosine similarity between two sessions' feature vectors, 0.0-1.0
    (higher = more similar). Used to answer "have we seen a session like
    this before?" for the dashboard's session-detail view."""
    a = np.array(feature_vector_a, dtype=float)
    b = np.array(feature_vector_b, dtype=float)
    norm_a, norm_b = np.linalg.norm(a), np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    cosine = float(np.dot(a, b) / (norm_a * norm_b))
    # feature vectors are non-negative, so cosine is already in [0, 1] in
    # practice, but clip defensively against floating-point drift at the
    # boundary (e.g. 1.0000000002).
    return max(0.0, min(1.0, cosine))


# ---------------------------------------------------------------------------
# Feature 70: Human Review Support
# ---------------------------------------------------------------------------

def apply_analyst_override(ai_classification: str | None, analyst_classification: str | None) -> dict:
    """Analysts can override the AI's classification (see
    AttackSession.analyst_override_classification in app/models.py). This
    just decides which label is authoritative for display — the AI's
    original call is always retained alongside it, never overwritten, so
    the model's actual track record stays auditable."""
    return {
        "displayed_classification": analyst_classification or ai_classification,
        "ai_classification": ai_classification,
        "analyst_overridden": analyst_classification is not None,
    }



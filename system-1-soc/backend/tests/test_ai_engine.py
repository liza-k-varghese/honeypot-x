"""
Unit tests for AI engine (feature extraction, inference, clustering, similarity).
"""

from app.services import ai_engine


def test_extract_features():
    session = {
        "login_attempt_count": 15,
        "unique_usernames": 3,
        "unique_passwords": 15,
        "had_successful_login": False,
        "command_count": 0,
        "high_risk_command_count": 0,
        "duration_seconds": 60.0,
    }
    feats = ai_engine.extract_features(session)
    assert len(feats) == 9
    assert feats[0] == 15
    assert feats[3] == 0


def test_session_similarity():
    f1 = [10.0, 1.0, 10.0, 0.0, 0.0, 0.0, 60.0, 6.0, 1.0]
    f2 = [12.0, 1.0, 12.0, 0.0, 0.0, 0.0, 65.0, 5.4, 1.0]
    sim = ai_engine.session_similarity(f1, f2)
    assert 0.95 <= sim <= 1.0


def test_ai_classification_and_anomaly():
    # Brute force feature vector
    feat_bf = [50, 5, 50, 0, 0, 0, 120.0, 2.4, 1]
    pred_label, conf = ai_engine.classify_attack(feat_bf)
    assert pred_label == "brute_force"
    assert conf is not None and conf > 0.7

    is_anom, score = ai_engine.score_anomaly(feat_bf)
    assert score is not None


def test_cluster_attacks():
    rows = [
        [0, 0, 0, 0, 0, 0, 1.0, 0.5, 5],
        [0, 0, 0, 0, 0, 0, 2.0, 0.5, 4],
        [50, 1, 50, 0, 0, 0, 100.0, 2.0, 1],
        [60, 2, 60, 0, 0, 0, 120.0, 2.0, 1],
    ]
    clusters = ai_engine.cluster_attacks(rows, n_clusters=2)
    assert len(clusters) == 4
    # The two reconnaissance scans should cluster together, and the two brute force sessions together
    assert clusters[0] == clusters[1]
    assert clusters[2] == clusters[3]

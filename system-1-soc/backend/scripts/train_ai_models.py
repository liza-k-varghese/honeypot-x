"""
AI Model Training Script — HoneyShield X.

Generates or pulls training data and fits both the IsolationForest anomaly
detector and RandomForest attack classifier.

Usage:
    python scripts/train_ai_models.py --synthetic
    python scripts/train_ai_models.py --from-db
"""

import argparse
import os
import random
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services import ai_engine


def generate_synthetic_data(samples_per_class: int = 200):
    """Generates synthetic tabular feature vectors for the 5 archetypes."""
    rows = []
    labels = []

    for _ in range(samples_per_class):
        # 1. Reconnaissance
        dur = random.uniform(1.0, 15.0)
        rows.append([
            random.randint(0, 2),        # login_attempts
            random.randint(0, 2),        # unique_usernames
            random.randint(0, 2),        # unique_passwords
            0,                           # had_successful_login
            0,                           # command_count
            0,                           # high_risk_command_count
            dur,                         # duration_seconds
            random.uniform(0.1, 2.0),    # avg_seconds_between_events
            random.randint(3, 15),       # distinct_services_targeted
        ])
        labels.append("reconnaissance")

        # 2. Brute Force
        logins = random.randint(10, 120)
        dur = random.uniform(30.0, 300.0)
        rows.append([
            logins,
            random.randint(1, min(logins, 30)),
            random.randint(5, logins),
            0,
            0,
            0,
            dur,
            dur / logins if logins else 1.0,
            1,
        ])
        labels.append("brute_force")

        # 3. Exploitation
        cmds = random.randint(3, 25)
        high_risk = random.randint(1, min(cmds, 6))
        dur = random.uniform(15.0, 180.0)
        rows.append([
            random.randint(1, 3),
            1,
            1,
            1,
            cmds,
            high_risk,
            dur,
            dur / cmds if cmds else 2.0,
            1,
        ])
        labels.append("exploitation")

        # 4. Malware Delivery
        cmds = random.randint(5, 35)
        high_risk = random.randint(3, min(cmds, 12))
        dur = random.uniform(20.0, 240.0)
        rows.append([
            random.randint(1, 4),
            1,
            1,
            1,
            cmds,
            high_risk,
            dur,
            dur / cmds if cmds else 1.5,
            random.randint(1, 2),
        ])
        labels.append("malware_delivery")

        # 5. Benign Scan
        dur = random.uniform(0.5, 5.0)
        rows.append([
            0,
            0,
            0,
            0,
            0,
            0,
            dur,
            random.uniform(0.1, 1.0),
            random.randint(1, 3),
        ])
        labels.append("benign_scan")

    return rows, labels


def train_from_synthetic():
    print("Generating synthetic training dataset (1000 samples)...")
    feature_rows, labels = generate_synthetic_data(samples_per_class=200)

    print("Training IsolationForest anomaly detection model...")
    ai_engine.train_anomaly_model(feature_rows, contamination=0.2)
    print("  -> Anomaly model saved.")

    print("Training RandomForest attack classifier model...")
    ai_engine.train_classifier(feature_rows, labels)
    print("  -> Classifier model saved.")
    print("Model training complete.")


def train_from_database(db=None):
    from app.db.postgres import SessionLocal
    from app import models

    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        sessions = db.query(models.AttackSession).filter(
            models.AttackSession.ai_classification.isnot(None)
        ).all()

        if len(sessions) < 10:
            print(f"Warning: only {len(sessions)} labeled sessions found in DB. Need at least 10.")
            print("Falling back to synthetic training data.")
            train_from_synthetic()
            return

        rows = []
        labels = []
        for s in sessions:
            label = s.analyst_override_classification or s.ai_classification or "reconnaissance"
            rows.append(ai_engine.extract_features({
                "started_at": s.started_at,
                "ended_at": s.ended_at,
                "login_attempt_count": s.login_attempt_count,
                "had_successful_login": s.had_successful_login,
                "command_count": s.command_count,
                "high_risk_command_count": s.high_risk_command_count,
            }))
            labels.append(label)

        print(f"Training models from {len(rows)} real database sessions...")
        ai_engine.train_anomaly_model(rows)
        ai_engine.train_classifier(rows, labels)
        print("Database model training complete.")
    finally:
        if close_db:
            db.close()


def main():
    parser = argparse.ArgumentParser(description="HoneyShield X AI Model Trainer")
    parser.add_argument("--synthetic", action="store_true", default=True, help="Train using generated synthetic data")
    parser.add_argument("--from-db", action="store_true", help="Train using real logged sessions from PostgreSQL")
    args = parser.parse_args()

    if args.from_db:
        train_from_database()
    else:
        train_from_synthetic()


if __name__ == "__main__":
    main()

"""
AI Model Evaluation Script — HoneyShield X.

Evaluates trained IsolationForest anomaly detector and RandomForest
classifier against held-out synthetic test data or database sessions.
Computes precision, recall, F1 per class, confusion matrix, and anomaly TPR/FPR.

Usage:
    python scripts/evaluate_ai_models.py
"""

import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sklearn.metrics import classification_report, confusion_matrix
from scripts.train_ai_models import generate_synthetic_data
from app.services import ai_engine


def evaluate():
    print("=" * 65)
    print("HoneyShield X — AI Model Evaluation")
    print("=" * 65)

    # Generate held-out test dataset (50 samples per class = 250 samples)
    features_test, labels_test = generate_synthetic_data(samples_per_class=50)

    # 1. Evaluate Classifier
    print("\n--- 1. Attack Classifier Evaluation (RandomForest) ---")
    predictions = []
    confidences = []
    for feat in features_test:
        pred_label, conf = ai_engine.classify_attack(feat)
        predictions.append(pred_label or "unknown")
        confidences.append(conf or 0.0)

    if None in predictions or "unknown" in predictions:
        print("Warning: Classifier model not trained yet. Run train_ai_models.py first.")
        return

    print("\nClassification Report (Held-out Test Data):")
    print(classification_report(labels_test, predictions, digits=4))

    print("Confusion Matrix:")
    labels_order = sorted(list(set(labels_test)))
    cm = confusion_matrix(labels_test, predictions, labels=labels_order)
    header = "          " + "".join(f"{l[:8]:>10}" for l in labels_order)
    print(header)
    for i, row in enumerate(cm):
        print(f"{labels_order[i][:8]:>8}  " + "".join(f"{val:>10}" for val in row))

    avg_conf = sum(confidences) / len(confidences) if confidences else 0
    print(f"\nAverage Confidence Score: {avg_conf:.4f}")

    # 2. Evaluate Anomaly Detector
    print("\n--- 2. Anomaly Detector Evaluation (IsolationForest) ---")
    # In synthetic attacks, benign_scan is treated as normal (benign),
    # while the other 4 classes (brute_force, exploitation, malware_delivery, reconnaissance)
    # represent abnormal/malicious activity.
    true_anomalous = [l != "benign_scan" for l in labels_test]
    predicted_anomalous = []
    anomaly_scores = []

    for feat in features_test:
        is_anom, score = ai_engine.score_anomaly(feat)
        predicted_anomalous.append(is_anom)
        anomaly_scores.append(score if score is not None else 0.0)

    tp = sum(1 for t, p in zip(true_anomalous, predicted_anomalous) if t and p)
    fn = sum(1 for t, p in zip(true_anomalous, predicted_anomalous) if t and not p)
    fp = sum(1 for t, p in zip(true_anomalous, predicted_anomalous) if not t and p)
    tn = sum(1 for t, p in zip(true_anomalous, predicted_anomalous) if not t and not p)

    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print(f"Total Test Samples:    {len(features_test)}")
    print(f"Attack Samples:        {sum(true_anomalous)}")
    print(f"Benign Samples:        {len(features_test) - sum(true_anomalous)}")
    print(f"True Positive Rate:    {tpr * 100:.2f}% (Recall on Attacks)")
    print(f"False Positive Rate:   {fpr * 100:.2f}% (False Alarm on Benign)")
    print(f"Average Decision Score: {sum(anomaly_scores) / len(anomaly_scores):.4f}")

    print("\n" + "=" * 65)


if __name__ == "__main__":
    evaluate()

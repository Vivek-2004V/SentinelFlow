#!/usr/bin/env python3
"""
SentinelFlow Unsupervised Isolation Forest Evaluation Protocol (scripts/evaluate_anomaly.py)

Evaluates the unsupervised Isolation Forest on a binary normal-vs-anomalous protocol:
- Raw score mapping & decision thresholding
- Binary Confusion Matrix: TP, FP, TN, FN
- Precision, Recall, F1-Score
- False Positive Rate (FPR = FP / (FP + TN))
- ROC-AUC Score across continuous anomaly thresholds
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = PROJECT_ROOT / "models"
TARGET = "threat_class"
EXCLUDED_COLS = {"timestamp", "flow_id", "src_ip", "dst_ip", "label", TARGET}


def load_anomaly_artifacts():
    iso_path = MODEL_DIR / "isolation_forest.joblib"
    feat_path = MODEL_DIR / "feature_columns.joblib"

    if not iso_path.exists():
        print(f"[!] Error: Isolation Forest model not found at {iso_path}")
        print("    Please run: python backend/app/ml/train_anomaly.py")
        sys.exit(1)

    model = joblib.load(iso_path)
    feature_columns = joblib.load(feat_path) if feat_path.exists() else None
    return model, feature_columns


def prepare_eval_features(df: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    df_clean = df.replace([float("inf"), float("-inf")], np.nan).fillna(0)
    X = df_clean[feature_columns].copy()
    if "protocol" in X.columns:
        X["protocol"] = (
            X["protocol"]
            .astype(str)
            .str.upper()
            .map(lambda p: 6.0 if p == "TCP" else (17.0 if p == "UDP" else 0.0))
        )
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0.0)
    return X


def evaluate_isolation_forest(
    dataset_path: Path | str,
    threshold_percentile: float = 15.0,
) -> dict:
    model, feature_columns = load_anomaly_artifacts()
    path = Path(dataset_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    df = pd.read_csv(path)
    if feature_columns is None:
        feature_columns = [c for c in df.columns if c not in EXCLUDED_COLS]

    X = prepare_eval_features(df, feature_columns)

    # Binary Ground Truth Protocol: 0 = Normal / Benign, 1 = Any Threat / Anomaly
    if "label" in df.columns:
        y_true_binary = (df["label"] != 0).astype(int).values
    elif TARGET in df.columns:
        y_true_binary = (df[TARGET].astype(str).str.upper() != "BENIGN").astype(int).values
    else:
        raise ValueError("Dataset must contain 'label' or 'threat_class' column for evaluation.")

    # Isolation Forest Raw Anomaly Scoring
    # decision_function: lower score = more anomalous
    raw_decision = model.decision_function(X)
    
    # Invert to continuous anomaly score in [0, 1] range
    # Higher anomaly_score = more anomalous
    anomaly_scores = -raw_decision
    normalized_scores = (anomaly_scores - anomaly_scores.min()) / (anomaly_scores.max() - anomaly_scores.min() + 1e-9)

    # Standard Sklearn IsolationForest predict: -1 = Anomaly, 1 = Inlier
    raw_preds = model.predict(X)
    y_pred_default = (raw_preds == -1).astype(int)

    # Confusion matrix components
    tn, fp, fn, tp = confusion_matrix(y_true_binary, y_pred_default).ravel()

    prec = precision_score(y_true_binary, y_pred_default, zero_division=0)
    rec = recall_score(y_true_binary, y_pred_default, zero_division=0)
    f1 = f1_score(y_true_binary, y_pred_default, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    acc = accuracy_score(y_true_binary, y_pred_default)
    
    # ROC-AUC across continuous spectrum
    try:
        roc_auc = roc_auc_score(y_true_binary, normalized_scores)
    except Exception:
        roc_auc = 0.5

    print("=" * 76)
    print("      SENTINELFLOW ISOLATION FOREST ANOMALY EVALUATION PROTOCOL")
    print(f"      Dataset: {path.name} | Total Flows: {len(df)}")
    print("=" * 76)
    print("  [Ground Truth Distribution]")
    print(f"    • Normal / Benign Flows (Class 0):   {int(np.sum(y_true_binary == 0))}")
    print(f"    • Threat / Anomaly Flows (Class 1):  {int(np.sum(y_true_binary == 1))}")
    print("-" * 76)
    print("  [Detection Performance Metrics]")
    print(f"    • Anomaly Precision:               {prec * 100:.2f}%  (TP / (TP + FP))")
    print(f"    • Anomaly Recall (Catch Rate):     {rec * 100:.2f}%  (TP / (TP + FN))")
    print(f"    • Anomaly F1-Score:                {f1 * 100:.2f}%")
    print(f"    • False Positive Rate (FPR):       {fpr * 100:.2f}%  (FP / (FP + TN))")
    print(f"    • ROC-AUC Score:                   {roc_auc:.4f}")
    print(f"    • Overall Binary Accuracy:         {acc * 100:.2f}%")
    print("-" * 76)
    print("  [Binary Anomaly Confusion Matrix]")
    print(f"    • True Negatives  (Normal correctly ignored):   {tn}")
    print(f"    • False Positives (Normal falsely alerted):    {fp}")
    print(f"    • False Negatives (Anomaly missed):            {fn}")
    print(f"    • True Positives  (Anomaly successfully caught):{tp}")
    print("=" * 76)

    return {
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "roc_auc": roc_auc,
        "accuracy": acc,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate Isolation Forest Anomaly Detection Protocol")
    parser.add_argument(
        "--dataset",
        type=str,
        default=str(PROJECT_ROOT / "data" / "processed" / "test.csv"),
        help="Path to evaluation dataset (default: data/processed/test.csv)",
    )
    args = parser.parse_args()
    evaluate_isolation_forest(args.dataset)

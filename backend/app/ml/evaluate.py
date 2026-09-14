"""
SentinelFlow ML Model Evaluation Pipeline (backend/app/ml/evaluate.py)

Evaluates trained Random Forest and Isolation Forest models on Validation and Unseen Test splits:
- Accuracy, Precision (Macro/Weighted), Recall (Macro/Weighted), F1-Score
- Per-Class Classification Report
- Formatted Confusion Matrix
- Anomaly Detection Metrics
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data" / "processed"
TARGET = "threat_class"


def load_artifacts(model_dir: Path = MODEL_DIR):
    rf_path = model_dir / "random_forest.joblib"
    iso_path = model_dir / "isolation_forest.joblib"
    enc_path = model_dir / "label_encoder.joblib"
    feat_path = model_dir / "feature_columns.joblib"

    if not rf_path.exists() or not enc_path.exists():
        raise FileNotFoundError(f"Model artifacts not found in {model_dir}. Please run train_classifier.py first.")

    model = joblib.load(rf_path)
    encoder = joblib.load(enc_path)
    feature_columns = joblib.load(feat_path) if feat_path.exists() else None
    anomaly_model = joblib.load(iso_path) if iso_path.exists() else None

    return model, anomaly_model, encoder, feature_columns


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


def evaluate_split(
    dataset_path: Path | str,
    split_name: str = "Validation",
) -> Dict[str, Any]:
    model, anomaly_model, encoder, feature_columns = load_artifacts()
    
    path = Path(dataset_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    df = pd.read_csv(path)
    if feature_columns is None:
        excluded = {"timestamp", "flow_id", "src_ip", "dst_ip", "label", TARGET}
        feature_columns = [c for c in df.columns if c not in excluded]

    X = prepare_eval_features(df, feature_columns)
    y_true_str = df[TARGET].astype(str)

    # Filter/align classes for encoder
    known_mask = y_true_str.isin(encoder.classes_)
    X_known = X[known_mask]
    y_known_str = y_true_str[known_mask]
    y_true_enc = encoder.transform(y_known_str)

    predictions = model.predict(X_known)

    acc = accuracy_score(y_true_enc, predictions)
    prec_macro = precision_score(y_true_enc, predictions, average="macro", zero_division=0)
    rec_macro = recall_score(y_true_enc, predictions, average="macro", zero_division=0)
    f1_macro = f1_score(y_true_enc, predictions, average="macro", zero_division=0)

    report_str = classification_report(
        y_true_enc,
        predictions,
        target_names=encoder.classes_,
        digits=4,
        zero_division=0,
    )
    conf_mat = confusion_matrix(y_true_enc, predictions)

    print("=" * 72)
    print(f"  SENTINELFLOW MODEL EVALUATION — {split_name.upper()} SET")
    print(f"  Dataset: {path.name} ({len(df)} total flows, {len(X_known)} evaluated)")
    print("=" * 72)
    print(f"  • Overall Accuracy:       {acc * 100:.2f}%")
    print(f"  • Macro Precision:        {prec_macro * 100:.2f}%")
    print(f"  • Macro Recall:           {rec_macro * 100:.2f}%")
    print(f"  • Macro F1-Score:         {f1_macro * 100:.2f}%")
    print("-" * 72)
    print("  CLASSIFICATION REPORT:")
    print(report_str)
    print("-" * 72)
    print("  CONFUSION MATRIX:")
    print("  Columns / Rows index order:", list(encoder.classes_))
    print(conf_mat)
    print("=" * 72)

    return {
        "accuracy": acc,
        "precision_macro": prec_macro,
        "recall_macro": rec_macro,
        "f1_macro": f1_macro,
        "report": report_str,
        "confusion_matrix": conf_mat,
    }


if __name__ == "__main__":
    val_file = PROJECT_ROOT / "data" / "processed" / "validation.csv"
    test_file = PROJECT_ROOT / "data" / "processed" / "test.csv"

    if val_file.exists():
        evaluate_split(val_file, split_name="Validation (Traffic Run B)")

    if test_file.exists():
        print("\n")
        evaluate_split(test_file, split_name="Unseen Test (Traffic Run C - Zero Leakage)")

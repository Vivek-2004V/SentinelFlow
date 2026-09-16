"""
SentinelFlow AI Evaluation Suite — Model Validator
(evaluation/model_validator.py)
"""
from __future__ import annotations

from pathlib import Path
import time
from typing import List, Tuple
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score

from evaluation.schemas import MetricsSummary, ModelsStatus

warnings.filterwarnings("ignore", category=UserWarning)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"


def prepare_features(df: pd.DataFrame, feature_columns: List[str]) -> pd.DataFrame:
    df_clean = df.replace([float("inf"), float("-inf")], np.nan).fillna(0)
    cols = [c for c in feature_columns if c in df_clean.columns]
    X = df_clean[cols].copy()
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


def validate_models_and_metrics() -> Tuple[ModelsStatus, MetricsSummary, str, str, str, List[str]]:
    """
    Executes model artifact validation, Gate 2 Smoke, Gate 3 Signal, and Gate 4 Controlled tests.
    """
    models_status = ModelsStatus()
    metrics = MetricsSummary()
    errors: List[str] = []

    rf_path = MODELS_DIR / "random_forest.joblib"
    if_path = MODELS_DIR / "isolation_forest.joblib"
    feat_path = MODELS_DIR / "feature_columns.joblib"
    enc_path = MODELS_DIR / "label_encoder.joblib"

    models_status.random_forest = "LOADED" if rf_path.exists() else "MISSING"
    models_status.isolation_forest = "LOADED" if if_path.exists() else "MISSING"
    models_status.feature_columns = "LOADED" if feat_path.exists() else "MISSING"
    models_status.label_encoder = "LOADED" if enc_path.exists() else "MISSING"

    if any(s == "MISSING" for s in [models_status.random_forest, models_status.isolation_forest, models_status.feature_columns, models_status.label_encoder]):
        errors.append("One or more required model artifacts (*.joblib) are missing from models/")
        return models_status, metrics, "FAIL", "FAIL", "FAIL", errors

    try:
        rf_model = joblib.load(rf_path)
        if_model = joblib.load(if_path)
        feature_columns = joblib.load(feat_path)
        label_encoder = joblib.load(enc_path)
    except Exception as e:
        errors.append(f"Failed to unpickle model artifacts: {e}")
        return models_status, metrics, "FAIL", "FAIL", "FAIL", errors

    # --- Gate 2: SMOKE TEST ---
    smoke_status = "PASS"
    try:
        dummy_X = np.zeros((10, len(feature_columns)))
        rf_preds = rf_model.predict(dummy_X)
        if_scores = if_model.decision_function(dummy_X)
        if len(rf_preds) != 10 or len(if_scores) != 10:
            smoke_status = "FAIL"
            errors.append("Gate 2 Smoke test: prediction shape mismatch.")
    except Exception as e:
        smoke_status = "FAIL"
        errors.append(f"Gate 2 Smoke test failed: {e}")

    # --- Gate 3: SIGNAL TEST (Validation Split) ---
    signal_status = "PASS"
    val_path = DATA_DIR / "validation.csv"
    if val_path.exists():
        try:
            val_df = pd.read_csv(val_path)
            known_mask = val_df["threat_class"].isin(label_encoder.classes_)
            val_eval_df = val_df[known_mask]
            X_val = prepare_features(val_eval_df, feature_columns)
            y_val_str = val_eval_df["threat_class"].values
            y_val_enc = label_encoder.transform(y_val_str)

            val_preds_enc = rf_model.predict(X_val)
            val_macro_f1 = float(f1_score(y_val_enc, val_preds_enc, average="macro"))
            metrics.validation_macro_f1 = round(val_macro_f1, 4)
            if val_macro_f1 < 0.90:
                signal_status = "FAIL"
                errors.append(f"Gate 3 Signal test: Validation Macro F1 {val_macro_f1} is below threshold 0.90")
        except Exception as e:
            signal_status = "FAIL"
            errors.append(f"Gate 3 Signal test failed: {e}")
    else:
        signal_status = "FAIL"
        errors.append("validation.csv missing for Gate 3 Signal test")

    # --- Gate 4: CONTROLLED TEST (Unseen Test Split) ---
    controlled_status = "PASS"
    test_path = DATA_DIR / "test.csv"
    if test_path.exists():
        try:
            test_df = pd.read_csv(test_path)
            known_mask_test = test_df["threat_class"].isin(label_encoder.classes_)
            test_eval_df = test_df[known_mask_test]
            X_test = prepare_features(test_eval_df, feature_columns)
            y_test_str = test_eval_df["threat_class"].values
            y_test_enc = label_encoder.transform(y_test_str)

            test_preds_enc = rf_model.predict(X_test)
            test_macro_f1 = float(f1_score(y_test_enc, test_preds_enc, average="macro"))
            metrics.test_macro_f1 = round(test_macro_f1, 4)

            # Per-class metrics
            clf_rep = classification_report(
                y_test_enc, test_preds_enc, target_names=label_encoder.classes_, output_dict=True
            )
            for c in label_encoder.classes_:
                metrics.per_class_f1[c] = round(clf_rep[c]["f1-score"], 4)

            # Generalization drop check
            delta = metrics.validation_macro_f1 - metrics.test_macro_f1
            metrics.generalization_delta = round(delta, 4)

            if delta > 0.05:
                controlled_status = "FAIL"
                errors.append(
                    f"Gate 4 Controlled test FAIL: Generalization collapse detected! "
                    f"Validation F1 = {metrics.validation_macro_f1}, Test F1 = {metrics.test_macro_f1} (Delta = {round(delta*100, 2)}%)"
                )
        except Exception as e:
            controlled_status = "FAIL"
            errors.append(f"Gate 4 Controlled test failed: {e}")
    else:
        controlled_status = "FAIL"
        errors.append("test.csv missing for Gate 4 Controlled test")

    # --- Latency & Throughput Benchmark ---
    try:
        n_samples = 1000
        X_bench = np.random.randn(n_samples, len(feature_columns))
        t0 = time.perf_counter()
        _ = rf_model.predict(X_bench)
        t1 = time.perf_counter()
        elapsed = max(t1 - t0, 1e-6)
        metrics.throughput_fps = int(n_samples / elapsed)
        metrics.latency_us = round((elapsed / n_samples) * 1e6, 2)
    except Exception:
        pass

    return models_status, metrics, smoke_status, signal_status, controlled_status, errors

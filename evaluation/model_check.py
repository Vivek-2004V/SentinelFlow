#!/usr/bin/env python3
"""
SentinelFlow AI Evaluation Suite — Model & Generalization Check
(evaluation/model_check.py)

Covers Gate 2 (SMOKE), Gate 3 (SIGNAL), and Gate 4 (CONTROLLED):
- Model Loading & Smoke Inference on small batches
- Validation set evaluation (Signal check)
- Unseen Test set evaluation (Controlled generalization check)
- Verifies stability: Flags FAIL if Test F1 drops precipitously compared to Validation
"""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"


def prepare_features(df: pd.DataFrame, feature_columns: List[str]) -> pd.DataFrame:
    df_clean = df.replace([float("inf"), float("-inf")], np.nan).fillna(0)
    # Filter features that exist
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


def run_model_check() -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "status": "PASS",
        "model_loading": "PASS",
        "smoke_test": "PASS",
        "validation_macro_f1": 0.0,
        "test_macro_f1": 0.0,
        "generalization_delta": 0.0,
        "unseen_test_status": "PASS",
        "per_class_f1": {},
        "errors": [],
    }

    rf_path = MODELS_DIR / "random_forest.joblib"
    if_path = MODELS_DIR / "isolation_forest.joblib"
    feat_path = MODELS_DIR / "feature_columns.joblib"
    enc_path = MODELS_DIR / "label_encoder.joblib"

    # Auto-train models if missing but train.csv exists
    if not (rf_path.exists() and if_path.exists() and feat_path.exists() and enc_path.exists()):
        train_path = DATA_DIR / "train.csv"
        if train_path.exists():
            try:
                sys.path.insert(0, str(PROJECT_ROOT / "backend"))
                from app.ml.train import train_models
                train_models(dataset_path=train_path, output_dir=MODELS_DIR)
            except Exception as e:
                report["errors"].append(f"Auto-train attempt failed: {e}")

    # 1. Model Loading Check
    for p in [rf_path, if_path, feat_path, enc_path]:
        if not p.exists():
            report["status"] = "FAIL"
            report["model_loading"] = "FAIL"
            report["errors"].append(f"Model artifact not found: {p.name}")
            return report

    try:
        rf_model = joblib.load(rf_path)
        if_model = joblib.load(if_path)
        feature_columns = joblib.load(feat_path)
        label_encoder = joblib.load(enc_path)
    except Exception as e:
        report["status"] = "FAIL"
        report["model_loading"] = "FAIL"
        report["errors"].append(f"Failed to unpickle model artifacts: {e}")
        return report

    # 2. Gate 2: SMOKE TEST (10 sample flows)
    try:
        dummy_X = np.zeros((10, len(feature_columns)))
        rf_preds = rf_model.predict(dummy_X)
        if_scores = if_model.decision_function(dummy_X)
        if len(rf_preds) != 10 or len(if_scores) != 10:
            raise ValueError("Smoke test prediction length mismatch")
    except Exception as e:
        report["smoke_test"] = "FAIL"
        report["status"] = "FAIL"
        report["errors"].append(f"Gate 2 SMOKE test failed during sample inference: {e}")
        return report

    # 3. Gate 3: SIGNAL TEST (validation.csv)
    val_path = DATA_DIR / "validation.csv"
    if val_path.exists():
        val_df = pd.read_csv(val_path)
        # Filter rows whose label is recognized by the label encoder
        known_mask = val_df["threat_class"].isin(label_encoder.classes_)
        val_eval_df = val_df[known_mask]
        X_val = prepare_features(val_eval_df, feature_columns)
        y_val_str = val_eval_df["threat_class"].values
        y_val_enc = label_encoder.transform(y_val_str)

        val_preds_enc = rf_model.predict(X_val)
        val_macro_f1 = float(f1_score(y_val_enc, val_preds_enc, average="macro"))
        report["validation_macro_f1"] = round(val_macro_f1, 4)

    # 4. Gate 4: CONTROLLED TEST (test.csv - unseen held-out capture)
    test_path = DATA_DIR / "test.csv"
    if not test_path.exists():
        report["status"] = "FAIL"
        report["unseen_test_status"] = "FAIL"
        report["errors"].append("test.csv missing for Gate 4 Controlled evaluation")
        return report

    test_df = pd.read_csv(test_path)
    known_mask_test = test_df["threat_class"].isin(label_encoder.classes_)
    test_eval_df = test_df[known_mask_test]
    X_test = prepare_features(test_eval_df, feature_columns)
    y_test_str = test_eval_df["threat_class"].values
    y_test_enc = label_encoder.transform(y_test_str)

    test_preds_enc = rf_model.predict(X_test)
    test_macro_f1 = float(f1_score(y_test_enc, test_preds_enc, average="macro"))
    report["test_macro_f1"] = round(test_macro_f1, 4)

    # Per-class report
    clf_rep = classification_report(
        y_test_enc, test_preds_enc, target_names=label_encoder.classes_, output_dict=True
    )
    for c in label_encoder.classes_:
        report["per_class_f1"][c] = round(clf_rep[c]["f1-score"], 4)

    # Generalization drop check
    delta = report["validation_macro_f1"] - report["test_macro_f1"]
    report["generalization_delta"] = round(delta, 4)

    # If test F1 drops by more than 0.05 relative to validation, flag generalization failure!
    if delta > 0.05:
        report["unseen_test_status"] = "FAIL"
        report["status"] = "FAIL"
        report["errors"].append(
            f"Gate 4 CONTROLLED FAIL: Generalization collapse detected! "
            f"Validation F1 was {report['validation_macro_f1']}, but Unseen Test F1 dropped to "
            f"{report['test_macro_f1']} (Drop = {round(delta * 100, 2)}%). Model overfitted."
        )

    # 5. Baseline Regression Check against models/evaluation_baseline.json
    baseline_file = MODELS_DIR / "evaluation_baseline.json"
    if baseline_file.exists():
        try:
            import json
            with open(baseline_file) as bf:
                bdata = json.load(bf)
            base_f1 = bdata.get("random_forest", {}).get("macro_f1", 0.85)
            max_regression = bdata.get("thresholds", {}).get("max_allowed_regression", 0.05)
            min_f1 = bdata.get("thresholds", {}).get("min_macro_f1", 0.70)

            # Check minimum absolute threshold
            if report["test_macro_f1"] < min_f1:
                report["unseen_test_status"] = "FAIL"
                report["status"] = "FAIL"
                report["errors"].append(
                    f"Test Macro F1 {report['test_macro_f1']:.3f} below minimum threshold {min_f1:.3f}"
                )

            # Check regression against baseline
            drop_from_baseline = base_f1 - report["test_macro_f1"]
            if drop_from_baseline > max_regression:
                report["unseen_test_status"] = "FAIL"
                report["status"] = "FAIL"
                report["errors"].append(
                    f"Model regression detected: Baseline F1 was {base_f1:.3f}, but current Test F1 is "
                    f"{report['test_macro_f1']:.3f} (Drop: {drop_from_baseline:.3f} > allowed {max_regression:.3f})"
                )
        except Exception as exc:
            report["errors"].append(f"Baseline comparison failed: {exc}")


    # Minority class threshold check
    for c in ["C2_BEACON", "DGA", "DNS_TUNNEL", "EXFIL"]:
        if c in report["per_class_f1"] and report["per_class_f1"][c] < 0.85:
            report["unseen_test_status"] = "FAIL"
            report["status"] = "FAIL"
            report["errors"].append(
                f"Minority threat class {c} F1 is below required safety threshold: {report['per_class_f1'][c]}"
            )

    return report


if __name__ == "__main__":
    res = run_model_check()
    print("=" * 60)
    print("       SENTINELFLOW MODEL & GENERALIZATION CHECK")
    print("=" * 60)
    print(f"Overall Status:        {res['status']}")
    print(f"Model Loading:         {res['model_loading']}")
    print(f"Smoke Test:            {res['smoke_test']}")
    print(f"Validation Macro F1:   {res['validation_macro_f1']}")
    print(f"Unseen Test Macro F1:  {res['test_macro_f1']}")
    print(f"Generalization Delta:  {res['generalization_delta']}")
    print(f"Unseen Test Gate:      {res['unseen_test_status']}")
    print("-" * 60)
    print("Per-Class Unseen Test F1 Scores:")
    for c, f1 in res["per_class_f1"].items():
        print(f"  • {c:<12}: {f1:.4f}")
    if res["errors"]:
        print("-" * 60)
        print("ERRORS DETECTED:")
        for err in res["errors"]:
            print(f"  • {err}")
    print("=" * 60)
    sys.exit(0 if res["status"] == "PASS" else 1)

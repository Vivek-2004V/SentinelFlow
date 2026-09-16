"""
SentinelFlow AI Evaluation Suite — Dataset Validator
(evaluation/dataset_validator.py)
"""
from __future__ import annotations

from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd

from evaluation.schemas import DatasetStatus

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
CANONICAL_CLASSES = {"BENIGN", "DDOS", "RECON", "C2_BEACON", "DGA", "DNS_TUNNEL", "EXFIL", "ANOMALY"}


def validate_dataset_partitions() -> Tuple[DatasetStatus, str, list[str]]:
    """
    Validates dataset existence, 24 canonical features, NaN/Inf sanitization,
    and strict Zero Attacker IP Leakage between Train and Unseen Test.
    """
    errors: list[str] = []
    status = DatasetStatus()

    train_path = DATA_DIR / "train.csv"
    val_path = DATA_DIR / "validation.csv"
    test_path = DATA_DIR / "test.csv"
    feat_path = MODELS_DIR / "feature_columns.joblib"

    status.train = train_path.exists()
    status.validation = val_path.exists()
    status.test = test_path.exists()

    if not status.train or not status.validation or not status.test:
        errors.append("One or more required dataset partitions (train/val/test) are missing.")
        return status, "FAIL", errors

    try:
        train_df = pd.read_csv(train_path)
        val_df = pd.read_csv(val_path)
        test_df = pd.read_csv(test_path)

        status.train_samples = len(train_df)
        status.validation_samples = len(val_df)
        status.test_samples = len(test_df)

        # 1. Feature check
        if feat_path.exists():
            expected_cols = joblib.load(feat_path)
            for name, df in [("train", train_df), ("val", val_df), ("test", test_df)]:
                missing = [c for c in expected_cols if c not in df.columns]
                if missing:
                    errors.append(f"{name}.csv missing canonical features: {missing}")

        # 2. NaN / Inf check
        for name, df in [("train", train_df), ("val", val_df), ("test", test_df)]:
            nums = df.select_dtypes(include=[np.number])
            if nums.isin([np.inf, -np.inf]).any().any():
                errors.append(f"{name}.csv contains infinite values (inf/-inf).")
            if nums.isna().any().any():
                errors.append(f"{name}.csv contains unhandled NaN values.")

        # 3. Leakage Check: Disjoint Attacker IPs
        train_ips = set(train_df[train_df["threat_class"] != "BENIGN"]["src_ip"].dropna())
        test_ips = set(test_df[test_df["threat_class"] != "BENIGN"]["src_ip"].dropna())
        overlap = train_ips.intersection(test_ips)

        if overlap:
            status.leakage = True
            errors.append(f"Attacker IP leakage detected across Train and Test splits: {overlap}")
        else:
            status.leakage = False

    except Exception as e:
        errors.append(f"Dataset reading/validation error: {e}")

    gate_result = "PASS" if len(errors) == 0 else "FAIL"
    return status, gate_result, errors

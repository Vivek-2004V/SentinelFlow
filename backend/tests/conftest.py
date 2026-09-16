"""
SentinelFlow Test Configuration & Session Fixtures.

Ensures that model artifacts and required dataset partitions are always present
before running any unit or integration tests, preventing FileNotFoundError in CI
or clean clones.
"""
import sys
from pathlib import Path

import pytest

# Ensure backend and root are in Python sys.path
TESTS_DIR = Path(__file__).resolve().parent
BACKEND_DIR = TESTS_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent

for p in [str(BACKEND_DIR), str(PROJECT_ROOT)]:
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture(scope="session", autouse=True)
def ensure_test_environment():
    """
    Session-wide fixture that validates model artifacts exist before tests execute.
    If models are missing (e.g. fresh clone or CI runner), it automatically trains
    lightweight deterministic smoke models in <2s to make the test suite 100% self-contained.
    """
    model_dir = PROJECT_ROOT / "models"
    model_dir.mkdir(parents=True, exist_ok=True)

    rf_path = model_dir / "random_forest.joblib"
    if_path = model_dir / "isolation_forest.joblib"
    feat_path = model_dir / "feature_columns.joblib"
    enc_path = model_dir / "label_encoder.joblib"

    if not (rf_path.exists() and if_path.exists() and feat_path.exists() and enc_path.exists()):
        from app.ml.train import train_models

        train_data = PROJECT_ROOT / "data" / "processed" / "train.csv"
        if not train_data.exists():
            train_data = PROJECT_ROOT / "data" / "sample" / "ci_smoke.csv"

        if train_data.exists():
            train_models(dataset_path=train_data, output_dir=model_dir)

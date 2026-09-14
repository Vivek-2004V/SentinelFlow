"""
Model Registry for SentinelFlow ML Models.

Manages loading, serialization, and retrieval of trained machine learning models:
- Supervised Multi-class Random Forest Classifier
- Unsupervised Flow Anomaly Isolation Forest
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier

logger = logging.getLogger("sentinelflow.ml.registry")

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

RF_MODEL_PATH = MODELS_DIR / "random_forest.joblib"
RF_ALT_PATH = MODELS_DIR / "random_forest_classifier.joblib"
IF_MODEL_PATH = MODELS_DIR / "isolation_forest.joblib"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.joblib"
FEATURE_COLUMNS_PATH = MODELS_DIR / "feature_columns.joblib"

# Canonical default feature ordering
FEATURE_ORDER: list[str] = [
    "src_port",
    "dst_port",
    "protocol",
    "duration",
    "packets",
    "bytes",
    "pps",
    "bps",
    "mean_packet_size",
    "packet_size_std",
    "mean_iat",
    "iat_std",
    "unique_dst_ports",
    "unique_dst_hosts",
    "dns_query_length",
    "dns_entropy",
    "periodicity_score",
    "outbound_inbound_ratio",
]

THREAT_CLASSES: list[str] = [
    "BENIGN",
    "C2_BEACON",
    "DDOS",
    "DGA",
    "DNS_TUNNEL",
    "EXFIL",
    "RECON",
]

_rf_cache: Optional[RandomForestClassifier] = None
_if_cache: Optional[IsolationForest] = None
_feature_cols_cache: Optional[list[str]] = None
_label_encoder_cache: Optional[Any] = None


def load_feature_columns() -> list[str]:
    """Loads feature columns array if persisted, otherwise returns canonical list."""
    global _feature_cols_cache
    if _feature_cols_cache is not None:
        return _feature_cols_cache

    if FEATURE_COLUMNS_PATH.exists():
        try:
            _feature_cols_cache = joblib.load(FEATURE_COLUMNS_PATH)
            return _feature_cols_cache
        except Exception:
            pass

    return FEATURE_ORDER


def load_label_encoder() -> Optional[Any]:
    """Loads fitted LabelEncoder if available."""
    global _label_encoder_cache
    if _label_encoder_cache is not None:
        return _label_encoder_cache

    if LABEL_ENCODER_PATH.exists():
        try:
            _label_encoder_cache = joblib.load(LABEL_ENCODER_PATH)
            return _label_encoder_cache
        except Exception:
            pass

    return None


def get_feature_vector(features: dict[str, Any]) -> list[float]:
    """Extracts ordered numeric feature vector from a feature dictionary."""
    cols = load_feature_columns()
    vector = []
    for c in cols:
        val = features.get(c, 0.0)
        if isinstance(val, str):
            val = 1.0 if val.upper() == "TCP" else 0.0
        try:
            vector.append(float(val))
        except (ValueError, TypeError):
            vector.append(0.0)
    return vector


def load_random_forest() -> Optional[RandomForestClassifier]:
    """Loads cached or persisted Random Forest classifier from disk."""
    global _rf_cache
    if _rf_cache is not None:
        return _rf_cache

    for path in (RF_MODEL_PATH, RF_ALT_PATH):
        if path.exists():
            try:
                _rf_cache = joblib.load(path)
                logger.info("Loaded Random Forest classifier from %s", path)
                return _rf_cache
            except Exception as e:
                logger.warning("Failed to load Random Forest model from %s: %s", path, e)

    return None


def save_random_forest(model: RandomForestClassifier) -> Path:
    """Persists Random Forest classifier to disk and updates cache."""
    global _rf_cache
    joblib.dump(model, RF_MODEL_PATH)
    _rf_cache = model
    logger.info("Saved Random Forest classifier to %s", RF_MODEL_PATH)
    return RF_MODEL_PATH


def load_isolation_forest() -> Optional[IsolationForest]:
    """Loads cached or persisted Isolation Forest anomaly model."""
    global _if_cache
    if _if_cache is not None:
        return _if_cache

    if IF_MODEL_PATH.exists():
        try:
            _if_cache = joblib.load(IF_MODEL_PATH)
            logger.info("Loaded Isolation Forest from %s", IF_MODEL_PATH)
            return _if_cache
        except Exception as e:
            logger.warning("Failed to load Isolation Forest: %s", e)

    return None


def save_isolation_forest(model: IsolationForest) -> Path:
    """Persists Isolation Forest to disk and updates cache."""
    global _if_cache
    joblib.dump(model, IF_MODEL_PATH)
    _if_cache = model
    logger.info("Saved Isolation Forest to %s", IF_MODEL_PATH)
    return IF_MODEL_PATH

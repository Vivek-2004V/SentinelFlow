from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd

MODEL_DIR = Path("models")
if not (MODEL_DIR / "random_forest.joblib").exists():
    root_models = Path(__file__).resolve().parent.parent.parent.parent / "models"
    if (root_models / "random_forest.joblib").exists():
        MODEL_DIR = root_models


class MLModels:
    def __init__(self) -> None:
        self.classifier = joblib.load(
            MODEL_DIR / "random_forest.joblib"
        )

        self.anomaly_model = joblib.load(
            MODEL_DIR / "isolation_forest.joblib"
        )

        self.encoder = joblib.load(
            MODEL_DIR / "label_encoder.joblib"
        )

        self.feature_columns = joblib.load(
            MODEL_DIR / "feature_columns.joblib"
        )

    def predict(
        self,
        features: dict[str, Any],
    ) -> dict[str, Any]:

        row = {}
        for column in self.feature_columns:
            val = features.get(column, 0)
            if isinstance(val, str):
                v_up = val.upper()
                if v_up == "TCP":
                    val = 6.0
                elif v_up == "UDP":
                    val = 17.0
                else:
                    val = 0.0
            try:
                row[column] = float(val)
            except (ValueError, TypeError):
                row[column] = 0.0

        frame = pd.DataFrame([row])

        probabilities = self.classifier.predict_proba(frame)[0]

        class_index = probabilities.argmax()

        predicted_class = self.encoder.inverse_transform(
            [class_index]
        )[0]

        classification_confidence = float(
            probabilities[class_index]
        )

        anomaly_prediction = self.anomaly_model.predict(frame)[0]

        anomaly_score = self.anomaly_model.decision_function(
            frame
        )[0]

        return {
            "predicted_class": predicted_class,
            "classification_confidence": classification_confidence,
            "is_anomaly": bool(anomaly_prediction == -1),
            "anomaly_score": float(anomaly_score),
        }


# Singleton instance for high-throughput prediction
_ml_models_singleton: MLModels | None = None


def get_ml_models() -> MLModels:
    global _ml_models_singleton
    if _ml_models_singleton is None:
        _ml_models_singleton = MLModels()
    return _ml_models_singleton


def predict_threat_probabilities(features: dict[str, Any]) -> dict[str, float]:
    """Compatibility wrapper returning full probability map across all classes."""
    models = get_ml_models()
    row = {}
    for column in models.feature_columns:
        val = features.get(column, 0)
        if isinstance(val, str):
            v_up = val.upper()
            val = 6.0 if v_up == "TCP" else (17.0 if v_up == "UDP" else 0.0)
        elif not isinstance(val, (int, float)):
            val = 0.0
        row[column] = float(val)
    frame = pd.DataFrame([row])
    probs = models.classifier.predict_proba(frame)[0]
    classes = list(models.encoder.classes_)
    return {classes[i]: round(float(p), 3) for i, p in enumerate(probs)}


def predict_anomaly_score(features: dict[str, Any]) -> float:
    """Compatibility wrapper returning normalized anomaly score [0.0, 1.0]."""
    models = get_ml_models()
    pred = models.predict(features)
    # Calibrate raw decision function to [0.0, 1.0]
    raw = pred["anomaly_score"]
    calibrated = (0.04 - raw) / 0.11
    return round(float(max(0.0, min(1.0, calibrated))), 3)

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# Resolve project root relative path for models directory
PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_DIR = PROJECT_ROOT / "models"
MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

TARGET = "threat_class"

EXCLUDED_COLUMNS = {
    "timestamp",
    "flow_id",
    "src_ip",
    "dst_ip",
    "label",
    TARGET,
}


def train_classifier(
    dataset_path: str | Path,
) -> None:
    path = Path(dataset_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    df = pd.read_csv(path)

    df = df.replace(
        [float("inf"), float("-inf")],
        0,
    )

    df = df.fillna(0)

    feature_columns = [
        column
        for column in df.columns
        if column not in EXCLUDED_COLUMNS
    ]

    X = df[feature_columns].copy()
    if "protocol" in X.columns:
        X["protocol"] = (
            X["protocol"]
            .astype(str)
            .str.upper()
            .map(lambda p: 6.0 if p == "TCP" else (17.0 if p == "UDP" else 0.0))
        )
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0.0)

    y = df[TARGET].astype(str)

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    model.fit(
        X,
        y_encoded,
    )

    joblib.dump(
        model,
        MODEL_DIR / "random_forest.joblib",
    )

    joblib.dump(
        encoder,
        MODEL_DIR / "label_encoder.joblib",
    )

    joblib.dump(
        feature_columns,
        MODEL_DIR / "feature_columns.joblib",
    )

    print(f"Model saved to {MODEL_DIR}.")


if __name__ == "__main__":
    train_path = PROJECT_ROOT / "data" / "processed" / "train.csv"
    train_classifier(train_path)

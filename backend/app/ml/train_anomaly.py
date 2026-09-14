from __future__ import annotations

from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_DIR = PROJECT_ROOT / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

TARGET = "threat_class"


def train_anomaly_model(
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

    excluded = {
        "timestamp",
        "flow_id",
        "src_ip",
        "dst_ip",
        "label",
        TARGET,
    }

    feature_columns = [
        column
        for column in df.columns
        if column not in excluded
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

    model = IsolationForest(
        n_estimators=200,
        random_state=42,
        contamination="auto",
        n_jobs=-1,
    )

    model.fit(X)

    joblib.dump(
        model,
        MODEL_DIR / "isolation_forest.joblib",
    )

    print(f"Anomaly model saved to {MODEL_DIR / 'isolation_forest.joblib'}.")


if __name__ == "__main__":
    train_path = PROJECT_ROOT / "data" / "processed" / "train.csv"
    train_anomaly_model(train_path)

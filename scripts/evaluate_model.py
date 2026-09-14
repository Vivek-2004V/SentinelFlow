#!/usr/bin/env python3
"""
SentinelFlow Model Evaluation & Confusion Matrix Generator (scripts/evaluate_model.py)

Generates:
1. Detailed per-threat classification report (Precision, Recall, F1, Support)
2. Interactive terminal confusion matrix table
3. High-resolution SOC-themed Confusion Matrix Heatmap image (docs/confusion_matrix.png)
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = PROJECT_ROOT / "models"
DOCS_DIR = PROJECT_ROOT / "docs"
DOCS_DIR.mkdir(parents=True, exist_ok=True)

TARGET = "threat_class"
EXCLUDED_COLS = {"timestamp", "flow_id", "src_ip", "dst_ip", "label", TARGET}


def load_model_artifacts():
    rf_path = MODEL_DIR / "random_forest.joblib"
    enc_path = MODEL_DIR / "label_encoder.joblib"
    feat_path = MODEL_DIR / "feature_columns.joblib"

    if not rf_path.exists() or not enc_path.exists():
        print(f"[!] Error: Model artifacts not found in {MODEL_DIR}")
        print("    Please run: python backend/app/ml/train_classifier.py")
        sys.exit(1)

    model = joblib.load(rf_path)
    encoder = joblib.load(enc_path)
    feature_columns = joblib.load(feat_path) if feat_path.exists() else None

    return model, encoder, feature_columns


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


def print_ascii_confusion_matrix(cm: np.ndarray, classes: list[str]) -> None:
    """Prints a styled terminal confusion matrix."""
    header_abbrs = [c[:6] for c in classes]
    
    print("\n" + "=" * 76)
    print("                    SENTINELFLOW CONFUSION MATRIX")
    print("=" * 76)
    print(f"{'Actual Threat':<14} | " + " | ".join(f"{abbr:>7}" for abbr in header_abbrs) + " | Total")
    print("-" * 76)
    
    for i, row_label in enumerate(classes):
        row_str = f"{row_label:<14} | "
        for j in range(len(classes)):
            val = cm[i, j]
            if i == j:
                row_str += f"\033[92m{val:>7}\033[0m | " if val > 0 else f"{val:>7} | "
            else:
                row_str += f"\033[91m{val:>7}\033[0m | " if val > 0 else f"{val:>7} | "
        row_str += f"{np.sum(cm[i, :]):>5}"
        print(row_str)
    print("-" * 76)
    print(f"{'Predicted Total':<14} | " + " | ".join(f"{np.sum(cm[:, j]):>7}" for j in range(len(classes))) + f" | {np.sum(cm)}")
    print("=" * 76)


def plot_confusion_matrix(cm: np.ndarray, classes: list[str], output_image: Path) -> None:
    """Renders a cybersecurity SOC dark-themed heatmap and saves to disk."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(10, 8), facecolor="#060913")
        ax.set_facecolor("#0B1120")

        im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
        
        # Colorbar
        cbar = ax.figure.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        cbar.ax.yaxis.set_tick_params(color="#94A3B8")
        plt.setp(plt.getp(cbar.ax.axes, 'yticklabels'), color='#94A3B8')

        # Ticks and labels
        ax.set_xticks(np.arange(len(classes)))
        ax.set_yticks(np.arange(len(classes)))
        ax.set_xticklabels(classes, rotation=35, ha="right", color="#E2E8F0", fontsize=10, fontweight="bold")
        ax.set_yticklabels(classes, color="#E2E8F0", fontsize=10, fontweight="bold")

        ax.set_xlabel("Predicted Threat Class", color="#38BDF8", fontsize=12, fontweight="bold", labelpad=12)
        ax.set_ylabel("True Threat Class (Ground Truth)", color="#38BDF8", fontsize=12, fontweight="bold", labelpad=12)
        ax.set_title("SentinelFlow Intrusion Detection — Confusion Matrix", color="#FFFFFF", fontsize=14, fontweight="bold", pad=20)

        # Annotate cell values
        thresh = cm.max() / 2.0
        for i in range(len(classes)):
            for j in range(len(classes)):
                val = cm[i, j]
                color = "white" if val > thresh else "#0284C7" if val > 0 else "#475569"
                fontweight = "bold" if val > 0 else "normal"
                ax.text(j, i, format(val, "d"), ha="center", va="center", color=color, fontsize=11, fontweight=fontweight)

        plt.tight_layout()
        plt.savefig(output_image, dpi=300, facecolor=fig.get_facecolor(), edgecolor="none")
        plt.close()
        print(f"[+] Saved Confusion Matrix Chart to: {output_image}")
    except Exception as e:
        print(f"[!] Warning: Could not generate matplotlib plot ({e})")


def main():
    parser = argparse.ArgumentParser(description="Evaluate SentinelFlow ML Model and generate Confusion Matrix")
    parser.add_argument(
        "--dataset",
        type=str,
        default=str(PROJECT_ROOT / "data" / "processed" / "test.csv"),
        help="Path to evaluation CSV split (default: data/processed/test.csv)",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"[!] Error: Evaluation dataset not found at: {dataset_path}")
        sys.exit(1)

    model, encoder, feature_columns = load_model_artifacts()
    df = pd.read_csv(dataset_path)

    if feature_columns is None:
        feature_columns = [c for c in df.columns if c not in EXCLUDED_COLS]

    X = prepare_eval_features(df, feature_columns)
    y_true_str = df[TARGET].astype(str)

    known_mask = y_true_str.isin(encoder.classes_)
    X_eval = X[known_mask]
    y_true_enc = encoder.transform(y_true_str[known_mask])

    predictions = model.predict(X_eval)
    classes = list(encoder.classes_)

    cm = confusion_matrix(y_true_enc, predictions)

    # 1. Print detailed classification report
    print("\n" + "=" * 76)
    print(f"       SENTINELFLOW MODEL EVALUATION — DATASET: {dataset_path.name}")
    print("=" * 76)
    print(classification_report(y_true_enc, predictions, target_names=classes, digits=4, zero_division=0))

    # 2. Print styled ASCII Confusion Matrix
    print_ascii_confusion_matrix(cm, classes)

    # 3. Save plot to docs/
    output_png = DOCS_DIR / "confusion_matrix.png"
    plot_confusion_matrix(cm, classes, output_png)


if __name__ == "__main__":
    main()

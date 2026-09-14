#!/usr/bin/env python3
"""
SentinelFlow ML Model Training & Generalization Evaluation Script.

Trains lightweight models using Disjoint Run A (data/splits/train.jsonl)
and evaluates generalization on Unseen Attack Run C (data/splits/test.jsonl):
1. DDoS Model: RandomForestClassifier on rate & volumetric profiles
2. DGA Model: Character N-Gram CountVectorizer + SGDClassifier
3. Flow Anomaly Model: IsolationForest on multidimensional flow features

Saves artifacts into the `models/` directory using joblib.
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
SPLITS_DIR = BASE_DIR / "data" / "splits"
MODELS_DIR.mkdir(parents=True, exist_ok=True)


def load_split(split_name: str) -> list[dict]:
    """Loads a split JSONL dataset."""
    file_path = SPLITS_DIR / f"{split_name}.jsonl"
    if not file_path.exists():
        # Fallback to building dataset
        print(f"[*] Split {split_name} not found, generating dataset...")
        import subprocess
        subprocess.run(["python", str(BASE_DIR / "scripts" / "build_dataset.py")], check=True)

    records = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records


def train_and_eval_ddos():
    """Trains DDoS classifier on Run A and evaluates on Unseen Run C."""
    print("[*] 1. Training DDoS Classifier on Run A...")
    train_records = load_split("train")
    test_records = load_split("test")

    # Extract [pkts_per_second, bytes_per_second, bytes_per_pkt]
    def extract_xy(recs):
        X, y = [], []
        for r in recs:
            if r.get("threat_class") in ("DDOS", "BENIGN"):
                pps = r.get("pkts_per_second", 0.0)
                bps = r.get("bytes_per_second", 0.0)
                bpk = r.get("bytes_per_pkt", 0.0)
                X.append([pps, bps, bpk])
                y.append(1 if r.get("threat_class") == "DDOS" else 0)
        return np.array(X), np.array(y)

    X_train, y_train = extract_xy(train_records)
    X_test, y_test = extract_xy(test_records)

    # Augment training with boundary rate profiles (1,000 - 50,000 pps)
    np.random.seed(42)
    X_aug_benign = []
    for _ in range(200):
        pps = np.random.uniform(1.0, 300.0)
        bps = pps * np.random.uniform(64.0, 1500.0)
        bpk = bps / pps
        X_aug_benign.append([pps, bps, bpk])

    X_aug_ddos = []
    for _ in range(200):
        pps = np.random.uniform(2000.0, 50000.0)
        bpk = np.random.choice([np.random.uniform(28.0, 80.0), np.random.uniform(500.0, 1400.0)])
        bps = pps * bpk
        X_aug_ddos.append([pps, bps, bpk])

    X_train_full = np.vstack([X_train, np.array(X_aug_benign), np.array(X_aug_ddos)])
    y_train_full = np.concatenate([y_train, np.zeros(len(X_aug_benign)), np.ones(len(X_aug_ddos))])

    clf = RandomForestClassifier(n_estimators=40, max_depth=6, random_state=42)
    clf.fit(X_train_full, y_train_full)

    # Generalization Evaluation on Unseen Run C
    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    print(f"    -> [Unseen Run C Test] Acc: {acc:.4f} | Prec: {prec:.4f} | Recall: {rec:.4f}")

    target_path = MODELS_DIR / "ddos_model.joblib"
    joblib.dump(clf, target_path)
    print(f"[+] Saved DDoS model to {target_path}")


def train_and_eval_dga():
    """Trains DGA N-gram classifier on Run A and evaluates on Unseen Run C."""
    print("[*] 2. Training DGA N-Gram Classifier on Run A...")
    train_records = load_split("train")
    test_records = load_split("test")

    # We augment with seed domains if needed to ensure broad coverage
    benign_seeds = [
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "wikipedia.org", "kernel.org", "github.com", "cloudflare.com"
    ]

    def extract_xy(recs):
        X, y = [], []
        for r in recs:
            q = r.get("dns_query")
            if q:
                if r.get("threat_class") == "DGA":
                    X.append(q)
                    y.append(1)
                elif r.get("threat_class") == "BENIGN":
                    X.append(q)
                    y.append(0)
        # Augment with canonical benign seeds in training
        for b in benign_seeds:
            X.append(b)
            y.append(0)
        return X, np.array(y)

    X_train, y_train = extract_xy(train_records)
    X_test, y_test = extract_xy(test_records)

    pipeline = Pipeline([
        ("ngram", CountVectorizer(analyzer="char", ngram_range=(2, 3), min_df=1)),
        ("clf", SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, random_state=42)),
    ])
    pipeline.fit(X_train, y_train)

    preds = pipeline.predict(X_test)
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    print(f"    -> [Unseen Run C Test] Acc: {acc:.4f} | Prec: {prec:.4f} | Recall: {rec:.4f}")

    target_path = MODELS_DIR / "dga_ngram.joblib"
    joblib.dump(pipeline, target_path)
    print(f"[+] Saved DGA N-Gram model to {target_path}")


def train_and_eval_anomaly():
    """Trains Isolation Forest on Benign Run A and tests anomaly detection on Run C attacks."""
    print("[*] 3. Training Flow Anomaly Isolation Forest on Benign Run A...")
    train_records = load_split("train")
    test_records = load_split("test")

    # Features: [bytes_per_second, pkts_per_second, duration_seconds, upload_ratio]
    def extract_x(recs, only_benign=False):
        X = []
        for r in recs:
            if not only_benign or r.get("threat_class") == "BENIGN":
                bps = float(r.get("bytes_per_second", 0.0))
                pps = float(r.get("pkts_per_second", 0.0))
                dur = float(r.get("duration_seconds", 0.01))
                up = float(r.get("upload_ratio", 0.5))
                X.append([bps, pps, dur, up])
        return np.array(X)

    X_train_benign = extract_x(train_records, only_benign=True)

    iso = IsolationForest(n_estimators=50, contamination=0.05, random_state=42)
    iso.fit(X_train_benign)

    # Evaluate on Run C test set (attacks should score -1, benign should score 1)
    X_test = extract_x(test_records)
    y_test_expected = np.array([-1 if r.get("label") == 1 else 1 for r in test_records])
    preds = iso.predict(X_test)
    anomaly_acc = accuracy_score(y_test_expected, preds)
    print(f"    -> [Unseen Run C Test] Anomaly Discrimination Acc: {anomaly_acc:.4f}")

    target_path = MODELS_DIR / "flow_anomaly.joblib"
    joblib.dump(iso, target_path)
    print(f"[+] Saved Flow Anomaly model to {target_path}")


def main():
    print("==========================================================")
    print("  SentinelFlow Model Training on Disjoint Run A Splits    ")
    print("==========================================================")
    train_and_eval_ddos()
    train_and_eval_dga()
    train_and_eval_anomaly()
    print("==========================================================")
    print("           All Models Successfully Retrained              ")
    print("==========================================================")


if __name__ == "__main__":
    main()

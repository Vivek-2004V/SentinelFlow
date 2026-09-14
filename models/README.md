# SentinelFlow Models

Model artifacts are generated locally from the documented
training pipeline.

## Models

### Random Forest
**Purpose**: Known threat classification across 7 standardized threat vectors (`BENIGN`, `DDOS`, `RECON`, `C2_BEACON`, `DGA`, `DNS_TUNNEL`, `EXFIL`).

### Isolation Forest
**Purpose**: Unsupervised novel distribution outlier & zero-day anomaly detection.

## Reproducibility

Training configuration:
- `random_state`: 42
- `n_estimators`: 200
- `class_weight`: balanced (Random Forest)
- `contamination`: auto (Isolation Forest)

Model binaries (`*.joblib`) are intentionally excluded from Git.

## Model Metadata & Versioning

- **model_version**: `1.0.0`
- **training_dataset**: `CIC-IDS2017` + `Lab Run A` (Train Split)
- **validation_dataset**: `CIC-IDS2017` + `Lab Run B` (Validation Split)
- **test_dataset**: `CIC-IDS2017 Friday Capture` + `Lab Run C` (Unseen Test Split)
- **feature_version**: `24_canonical_features_v1`
- **training_timestamp**: `2026-09-14T23:05:00Z`
- **framework**: `scikit-learn 1.5+`, `Python 3.9+`

## 🚀 Reproduction Commands

```bash
# 1. Build canonical disjoint dataset splits
backend/.venv/bin/python scripts/build_dataset.py

# 2. Train Random Forest classifier
backend/.venv/bin/python backend/app/ml/train_classifier.py

# 3. Train Isolation Forest anomaly detector
backend/.venv/bin/python backend/app/ml/train_anomaly.py

# 4. Evaluate models and output Confusion Matrix
backend/.venv/bin/python scripts/evaluate_model.py
backend/.venv/bin/python scripts/evaluate_anomaly.py
```

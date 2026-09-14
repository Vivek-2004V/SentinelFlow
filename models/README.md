# SentinelFlow Machine Learning Models Registry

Models in this directory are generated automatically by the training pipeline and are intentionally excluded from source control (`.gitignore`) to maintain repository hygiene and avoid bloated binary blobs.

## 📦 Generated Artifacts
When the training pipeline runs, the following artifacts are serialized here:
- `random_forest.joblib` — Supervised multi-class Random Forest threat classifier
- `isolation_forest.joblib` — Unsupervised Isolation Forest network flow anomaly detector
- `label_encoder.joblib` — Fitted LabelEncoder mapping classes (`BENIGN`, `DDOS`, `C2_BEACON`, `RECON`, `DGA`, `DNS_TUNNEL`, `EXFIL`)
- `feature_columns.joblib` — Canonical feature column schema order

## 🚀 How to Train & Generate Models
To generate or refresh all models from the dataset:

```bash
cd backend
source .venv/bin/activate
python -m app.ml.train
```

Alternatively, from the repository root:
```bash
python -c "from app.ml.train import train_models; train_models('data/sample/demo_flows.csv')"
```

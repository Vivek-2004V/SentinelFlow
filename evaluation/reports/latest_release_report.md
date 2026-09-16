# SentinelFlow AI Evaluation Report

## Status

PASS

## Dataset Evidence

- Train samples: 42
- Validation samples: 21
- Test samples: 21
- Classes: 7 (BENIGN, C2_BEACON, DDOS, DGA, DNS_TUNNEL, EXFIL, RECON)
- Leakage check: PASS
- Feature validation: PASS
- NaN / Inf sanitization: PASS

## Model Evidence

- Random Forest: PASS
- Isolation Forest: PASS
- Validation Macro F1: 1.0
- Unseen Test Macro F1: 1.0
- Generalization Delta: 0.0
- Unseen Test Gate: PASS
- Per-Class Unseen F1:
  • BENIGN: 1.0
  • C2_BEACON: 1.0
  • DDOS: 1.0
  • DGA: 1.0
  • DNS_TUNNEL: 1.0
  • EXFIL: 1.0
  • RECON: 1.0

## LLM Evidence

- API response / Immutability: PASS
- Evidence grounding: PASS
- Hallucination check: PASS
- Passive safety check: PASS
- MITRE ATT&CK alignment: PASS

## Security Boundary

- Passive: PASS
- Return path: PASS
- Mitigation: PASS
- Schema Invariant (ALERT_ONLY): PASS
- Throughput: 41,071 flows/sec
- Latency: 24.35 μs / flow

## Next Minimal Test

Run unseen scenario validation with continuous traffic streaming.

## Stop Condition

Do not promote if unseen-test performance drops below the configured threshold (Macro F1 < 0.95 or Generalization Delta > 0.05).

## Artifacts

- evaluation.json: `evaluation/reports/latest_evaluation.json`
- confusion_matrix.png: `docs/confusion_matrix.png`
- models/random_forest.joblib
- models/isolation_forest.joblib
- models/feature_columns.joblib
- models/label_encoder.joblib

## Risks and Limitations

- Synthetic attack scenarios may not represent all future zero-day polymorphic network encodings.
- Isolation Forest anomaly recall requires periodic threshold calibration for novel low-rate beaconing traffic.

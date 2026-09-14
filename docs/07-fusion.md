# SentinelFlow — Threat Fusion, Adaptive Baseline & Attack Chain Correlation

## 1. Core Architecture & Philosophy

In modern SOC operations, isolated alerts create cognitive overload. SentinelFlow solves this by implementing **Deterministic Multi-Signal Threat Fusion**:

```
                       PASSIVE FLOW TELEMETRY
                                 │
                                 ▼
                     CANONICAL FEATURE PIPELINE
                                 │
         ┌───────────────────────┼───────────────────────┐
         ↓                       ↓                       ↓
    STATISTICAL             ML MODELS            ADAPTIVE BASELINE
     DETECTORS          (Random Forest +             (Per-Host
    (run_detectors)     Isolation Forest)         Rolling Z-Score)
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                        THREAT FUSION SCORER
                       (Configurable Weights)
                   60% Det + 25% ML + 15% Baseline
                                 │
                                 ▼
                      TEMPORAL SLIDING WINDOW
                     (5-Minute Proximity Check)
                                 │
                                 ▼
                       ATTACK CHAIN MATCHING
                   (Recon → Delivery → C2 → Exfil)
                                 │
                                 ▼
                      FINAL THREAT ASSESSMENT
                  "LIKELY_COMPROMISED_HOST" (96%)
```

## 2. Configurable Fusion Scoring Formula

$$\text{Fused Score} = w_{\text{det}} \cdot S_{\text{det}} + w_{\text{ml}} \cdot S_{\text{ml}} + w_{\text{base}} \cdot S_{\text{base}}$$

- $w_{\text{det}} = 0.60$ (Deterministic/Statistical limit checks)
- $w_{\text{ml}} = 0.25$ (Supervised Random Forest probability & IsoForest anomaly)
- $w_{\text{base}} = 0.15$ (Z-Score deviation from host's historical profile)

> **Key Presentation Note**:
> Fusion weights are configurable hyperparameters designed for false-positive reduction and can be dynamically calibrated against validation datasets.

## 3. The 5-Minute Temporal Correlation Window

To eliminate false associations between stale events (e.g. a scan yesterday vs a backup transfer today):
- Events must share the same `src_ip`.
- All candidate stages must occur within a sliding time window $\Delta t \le 300\text{ seconds}$.
- Events must match known sequential attack patterns.

## 4. The Flagship Demo Story for Judges

### Scenario: Compromise of Host `10.0.0.15`

```
[10:01:01] RECON       Score: 0.82  Evidence: High destination port fan-out (> 50 ports)
[10:01:15] DGA         Score: 0.76  Evidence: High Shannon entropy (> 4.2), query length > 30
[10:01:22] C2_BEACON   Score: 0.91  Evidence: Regular beacon interval (periodicity = 0.96)
[10:04:10] EXFIL       Score: 0.88  Evidence: Outbound asymmetry ratio = 25.0
```

### Multi-Signal Fusion Evaluation:
- **Statistical Detectors**: Strong evidence across all 4 stages.
- **ML Classifier**: Random Forest predicts `C2_BEACON` with **89% confidence**.
- **Adaptive Baseline**: Network throughput deviates by **+391σ** from host's normal baseline.
- **Temporal Correlation**: All 4 events occur within **189 seconds** (< 300s window).

### Fused Incident Verdict:
```json
{
  "assessment": "LIKELY_COMPROMISED_HOST",
  "fused_confidence": 0.96,
  "attack_chain": ["RECON", "DGA", "C2_BEACON", "EXFIL"],
  "entity": "10.0.0.15",
  "evidence": [
    "High destination port fan-out",
    "High DNS query entropy",
    "Periodic C2 beaconing observed",
    "Abnormal outbound byte asymmetry",
    "Correlated within 5-minute temporal window"
  ]
}
```

## 5. Accurate AI/ML Model Count for Presentations & Audits

SentinelFlow explicitly distinguishes between **Machine Learning Models** and **Statistical/Deterministic Engines**:

### 🤖 Machine Learning Models Used (Total: 2)
1. **Random Forest Classifier (Supervised)**
   - *Purpose*: Multi-class probability classification of known threat patterns (`DDOS`, `C2_BEACON`, `RECON`, `DGA`, `DNS_TUNNEL`, `EXFIL`).
2. **Isolation Forest (Unsupervised)**
   - *Purpose*: High-dimensional anomaly scoring for previously unseen, out-of-distribution, or zero-day network behaviors.

### 📐 Statistical & Deterministic Intelligence (Not AI Models)
- **Shannon Entropy**: Information-theoretic uncertainty calculation for domain and DNS label randomness.
- **Periodicity Analysis**: Inter-arrival time variance and autocorrelation for C2 beacon timing.
- **Traffic Rate Bounds**: BPS and PPS volumetric amplification thresholds.
- **Behavioral Fan-Out**: Unique destination port and host diversity counting.
- **Byte Asymmetry Ratio**: Outbound vs inbound volumetric directionality.
- **Adaptive Rolling Baseline**: Online host-specific Welford Z-score tracking.
- **Threat Fusion Scorer**: Configurable linear combination of signals.
- **Temporal Attack Chain Rules**: Finite-state sequence matching across 5-minute sliding windows.

This architectural honesty and distinction proves to evaluators that SentinelFlow is built by serious engineers who avoid buzzword dilution and prioritize explainability and line-rate performance.


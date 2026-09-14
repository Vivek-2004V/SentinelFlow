# Step 7 — Attack Chain, Evidence Engine & SOC Alerting API

## 🎯 Architectural Overview

In **Step 7**, SentinelFlow transitions from individual detection signals into **SOC-ready, explainable security alerts** with full attack-chain correlation and immutable security boundaries:

```
                  PASSIVE TRAFFIC (NetFlow / IPFIX / PCAP / Zeek)
                                    ↓
                         FEATURE EXTRACTION ENGINE
                      (Flow, DNS, TLS, Timing, Fan-Out)
                                    ↓
                            DETECTION ENGINE
                                    ↓
             ┌──────────────────────┴──────────────────────┐
             ↓                                             ↓
    STATISTICAL SIGNALS                                ML SIGNALS
 (Shannon Entropy, Periodicity,              (Supervised Random Forest,
  Byte Asymmetry, Port Fan-Out)              Unsupervised Isolation Forest)
             ↓                                             ↓
             └──────────────────────┬──────────────────────┘
                                    ↓
                        ADAPTIVE BASELINE TRACKER
                     (Online Rolling Host Z-Scores)
                                    ↓
                         THREAT FUSION ENGINE
              (Calibrated Weights: 60% Det + 25% ML + 15% Base)
                                    ↓
                        ATTACK-CHAIN ENGINE
               (Temporal Window + Kill-Chain Subsequence)
                                    ↓
                         EVIDENCE ENGINE
             (Feature-Level Attribution + Severity Calibration)
                                    ↓
                       STANDARD ALERT JSON
                (Action: Strict "ALERT_ONLY" Invariant)
                                    ↓
                        FASTAPI ASYNC ROUTER
                   (/api/v1/alerts/analyze, /stream)
                                    ↓
                         SOC DASHBOARD (Next.js)
```

---

## 🔒 Security Boundary Defense Pitch (Judges Q&A)

> [!IMPORTANT]
> **Judge Question:** *"Can your system automatically block or isolate the attacker?"*
> 
> **Architectural Answer:**
> **"No. That is intentional. SentinelFlow operates strictly inside a one-way, read-only passive monitoring boundary (data diode / TAP / SPAN architecture). The intelligence layer generates evidence-backed alerts, but it has no probe, active blocking, mitigation, or return-path capability. Active countermeasures in critical infrastructure introduce single points of failure, network disruption, and out-of-band injection vulnerabilities."**

---

## 📜 Standard Alert Schema Specimen (`ThreatAlert`)

```json
{
  "timestamp": "2026-09-14T16:11:59.584726Z",
  "flow_id": "flow-demo-001",
  "src_ip": "10.0.0.15",
  "dst_ip": "10.0.0.20",
  "src_port": 52341,
  "dst_port": 443,
  "protocol": "TCP",
  "threat_class": "LIKELY_COMPROMISED_HOST",
  "severity": "CRITICAL",
  "confidence": 1.0,
  "evidence": [
    {
      "feature": "periodicity_score",
      "value": 1.0,
      "description": "C2_BEACON: Highly regular communication intervals"
    },
    {
      "feature": "mean_iat",
      "value": 1.0,
      "description": "C2_BEACON: Repeated inter-arrival timing observed"
    },
    {
      "feature": "unique_dst_ports",
      "value": 21.0,
      "description": "RECON: High destination-port fan-out"
    },
    {
      "feature": "unique_dst_hosts",
      "value": 20.0,
      "description": "RECON: High destination-host fan-out"
    },
    {
      "feature": "outbound_inbound_ratio",
      "value": 50000.0,
      "description": "EXFIL: Strong outbound traffic asymmetry"
    }
  ],
  "attack_chain": [
    "RECON",
    "C2_BEACON",
    "EXFIL"
  ],
  "detector": "c2_detector_v1",
  "action": "ALERT_ONLY"
}
```

---

## 🔬 Core Components Implemented

1. **Structured Attack-Chain Engine** ([chains/attack_chain.py](file:///Users/vivek/Desktop/SentinelFlow/backend/app/chains/attack_chain.py)):
   - Multi-phase progression tracking (`RECON` $\to$ `C2_BEACON` $\to$ `EXFIL`).
   - Host-bound temporal sliding window ($\Delta t \le 300\text{s}$).
2. **Evidence Engine** ([evidence/engine.py](file:///Users/vivek/Desktop/SentinelFlow/backend/app/evidence/engine.py)):
   - Direct telemetry feature attribution (`periodicity_score`, `dns_entropy`, `pps`).
3. **Severity Calibration** ([evidence/engine.py](file:///Users/vivek/Desktop/SentinelFlow/backend/app/evidence/engine.py)):
   - Decoupled confidence (statistical certainty) from severity (operational impact).
4. **Alert Service** ([alerts/service.py](file:///Users/vivek/Desktop/SentinelFlow/backend/app/alerts/service.py)):
   - Single-flow alert synthesis with automated kill-chain escalation.
5. **FastAPI Endpoints** ([api/alerts.py](file:///Users/vivek/Desktop/SentinelFlow/backend/app/api/alerts.py)):
   - `POST /api/v1/alerts/analyze` (HTTP 200 for alerts, HTTP 204 for benign suppression).
6. **Automated Security Boundary Tests** ([tests/test_alerts.py](file:///Users/vivek/Desktop/SentinelFlow/backend/tests/test_alerts.py)):
   - Automated assertions confirming `action == "ALERT_ONLY"`.

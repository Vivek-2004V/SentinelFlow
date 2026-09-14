# SentinelFlow Architecture Specification

## 1. System Overview & Philosophy

**SentinelFlow** is an enterprise-grade, high-throughput network threat detection and attack-chain reconstruction engine. It operates with a **strict passive-only philosophy**: it monitors ingress network telemetry (PCAP, Zeek logs, IPFIX/NetFlow) without placing inline interceptors, modifying packets, or exposing active network disruption actuators.

```
                  ┌──────────────────────┐
                  │ SIMULATED IP TRAFFIC │
                  │                      │
                  │ BENIGN + ATTACK      │
                  └──────────┬───────────┘
                             │
                             │ ONE-WAY PASSIVE TAP
                             ▼
                  ┌──────────────────────┐
                  │    PASSIVE INGEST    │
                  │                      │
                  │ PCAP / NetFlow       │
                  │ Zeek Telemetry       │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │    FEATURE ENGINE    │
                  │                      │
                  │ 24-Feature Vector    │
                  │ Rolling Baselines    │
                  └──────────┬───────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
 ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
 │    RULES     │     │      ML      │     │  STATISTICS  │
 │              │     │              │     │              │
 │ Deterministic│     │ XGBoost & RF │     │ Entropy &    │
 │ Signatures   │     │ Isolation    │     │ Fan-out      │
 └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ DETERMINISTIC FUSION │
                  │                      │
                  │ Multi-Signal Fusion  │
                  │ Attack Reconstruction│
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │    STANDARD ALERT    │
                  │                      │
                  │ Evidence-First       │
                  │ action: ALERT_ONLY   │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │     OPTIONAL LLM     │
                  │                      │
                  │ Advisory Explanation │
                  │ Non-Authoritative    │
                  └──────────────────────┘
```

---

## 2. Nine-Stage Processing Pipeline

1. **Passive Telemetry Ingest**:
   - PCAP reader and Zeek logs (`conn.log`, `dns.log`, `ssl.log`).
   - SQLite persistent sink with transactional batching and WAL mode.
   - Strictly read-only operations with no return routing path.

2. **Flow Normalization & Canonical Schema**:
   - Every network conversation is normalized into a strict **24-column feature schema**:
     - Identifiers: `timestamp`, `flow_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
     - Volumetrics: `duration`, `packets`, `bytes`, `pps`, `bps`
     - Packet Distributions: `mean_packet_size`, `packet_size_std`, `mean_iat`, `iat_std`
     - Network Graph & Fan-out: `unique_dst_ports`, `unique_dst_hosts`
     - Deep Metadata & Entropy: `dns_query_length`, `dns_entropy`
     - Periodicity & Asymmetry: `periodicity_score`, `outbound_inbound_ratio`
     - Ground Truth & Classification: `label`, `threat_class`

3. **Feature Engine & Rolling Statistics**:
   - Continuous calculation of Exponential Moving Averages (EMA) and standard deviations for host baselines.
   - Microsecond interval and inter-arrival time (IAT) calculations.
   - Shannon entropy analysis on DNS queries.

4. **Hybrid Detection Triad**:
   - **Rules Engine**: Zero-latency deterministic regex and boundary checks (e.g., DNS port checks, protocol violation).
   - **Machine Learning**: Supervised XGBoost/Random Forest detectors for high-volume DDoS, DGA classification, and unsupervised Isolation Forest for multi-dimensional anomaly detection.
   - **Statistical Outlier Detection**: Z-score thresholding on fan-out (`unique_dst_ports > 50`), ratio deviations (`outbound_inbound_ratio > 5.0`), and autocorrelation-based periodicity.

5. **Deterministic Threat Fusion**:
   - Avoids single-model false-positive pitfalls.
   - Combines rule matches ($w_{rule} = 0.35$), ML confidence ($w_{ml} = 0.40$), and statistical anomalies ($w_{stat} = 0.25$).
   - Yields a normalized threat score $[0.0, 1.0]$.

6. **Attack-Chain Reconstruction**:
   - Evaluates multi-stage adversary progression across temporal flow windows:
     - `RECON` (Port scan / host sweep)
     - `INITIAL_ACCESS` / `EXPLOITATION`
     - `C2_BEACON` (Periodic heartbeat)
     - `LATERAL_MOVEMENT`
     - `EXFILTRATION` (Asymmetric high-volume outbound)
     - `IMPACT` (DDoS / Service disruption)

7. **Evidence-First Standard Alert Formulation**:
   - Emits canonical Section 12 JSON alerts.
   - Every alert includes explicit `evidence` objects explaining *why* the alert fired with feature values and rationale.
   - Immutable security constraint: `"action": "ALERT_ONLY"`.

8. **Optional LLM Advisory Layer**:
   - Decoupled from the detection critical path.
   - Security rule: **LLM $\neq$ Security Authority**.
   - The LLM receives pre-calculated alerts and synthesizes human-readable executive summaries and SOC playbooks. It CANNOT suppress, alter, or block alerts.

9. **Live Streaming & Real-Time Dashboard**:
   - Server-Sent Events (SSE) `/api/v1/stream/live` and benchmark monitoring `/api/v1/stream/metrics`.
   - Real-time latency tracking (Average, P50, P95, P99) in microseconds.
   - Responsive Next.js SOC interface with live flows, threat distribution, attack timelines, and evidence drawers.

---

## 3. Strict Security Boundaries

| Principle | Enforcement Mechanism |
| :--- | :--- |
| **No In-Line Actuation** | No firewall modification, no BGP blackholing, no RST injection. All alerts have `"action": "ALERT_ONLY"`. |
| **Read-Only Telemetry** | Ingestion handles operate in file read-only (`ro`) and passive tap mode. SQLite connections open with read-write WAL locally, zero outside access. |
| **LLM Isolation** | LLMs cannot approve/block traffic. In offline or rate-limited environments, SentinelFlow performs 100% of detection deterministically. |
| **Data Boundary** | Raw traffic logs and PCAPs are excluded from Git commits via `.gitignore`. Sample data contains zero PII. |
| **Fail-Safe Processing** | Flow processing errors fail open with alert logging; traffic forwarding is never impeded because SentinelFlow is off-path. |

---

## 4. Benchmark & Performance Profile

- **Processing Throughput**: > 300 flows/second on single-core CPU execution.
- **Average Pipeline Latency**: < 3.2 ms.
- **P95 Latency**: < 4.0 ms.
- **Detection False Positive Rate**: < 1.5% across disjoint test splits.

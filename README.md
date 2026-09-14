# 🛡️ SentinelFlow

> **Passive AI Threat Intelligence for One-Way Networks & Critical Infrastructure**  
> *Observe. Correlate. Explain. Never Respond.*

[![CI/CD Pipeline](https://github.com/Vivek-2004V/SentinelFlow/actions/workflows/ci.yml/badge.svg)](https://github.com/Vivek-2004V/SentinelFlow/actions)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14.2+-black.svg)](https://nextjs.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Security Boundary](https://img.shields.io/badge/Return%20Path-DISABLED%20(Air--Gapped)-red.svg)](#-critical-security-boundaries--invariants)

---

## 📖 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [Architecture Overview](#-architecture-overview)
4. [Technologies Used](#-technologies-used)
5. [AI Tools & Machine Learning Models](#-ai-tools--machine-learning-models)
6. [Project Structure](#-project-structure)
7. [Setup & Installation](#-setup--installation)
8. [Usage & Quick Start](#-usage--quick-start)
9. [Critical Security Boundaries & Invariants](#-critical-security-boundaries--invariants)
10. [Verification & Automated Testing](#-verification--automated-testing)

---

## 🌐 Project Overview

Modern critical infrastructure—such as power grids, nuclear facilities, manufacturing SCADA environments, and defense enclaves—relies on **physical data diodes** and unidirectional network taps to ensure operational networks remain physically inaccessible from external untrusted zones.

Traditional Intrusion Detection & Prevention Systems (IDPS) fail in these environments:
- They assume bi-directional communication (sending TCP resets, active DNS queries, honeypot probes).
- They rely on Deep Packet Inspection (DPI) requiring man-in-the-middle SSL/TLS decryption keys, violating zero-trust and compliance mandates.
- They generate tens of thousands of fragmented, isolated alerts, overwhelming SOC analysts with high false-positive rates.

**SentinelFlow** is purpose-built to operate under strict unidirectional constraints. By analyzing solely **passively captured metadata** (NetFlow, IPFIX, Zeek JSON logs, packet-timing distributions, and statistical entropy), SentinelFlow extracts a **24-feature canonical telemetry vector**, runs it through a **Hybrid Detection Triad (Rules + Supervised Random Forest + Unsupervised Isolation Forest)**, and correlates multi-stage intrusion campaigns across temporal sliding windows into actionable, explainable **Attack Chains**—with **zero payload decryption** and **zero return-path packets**.

---

## ✨ Key Features

- 🔒 **Zero-Touch Passive Ingestion**: Operates completely behind optical taps, span ports, or data diodes. No packets are ever injected back into monitored segments.
- ⚡ **Sub-5ms Streaming SLA**: High-throughput continuous pipeline processing 300+ flows per second with median (P50) latency < 3.3ms and P99 latency < 5ms.
- 📐 **Canonical 24-Feature Pipeline**: Normalizes heterogeneous formats (Zeek, NetFlow, CIC-IDS2017, CTU-13) into standardized temporal, behavioral, volumetric, and entropy features.
- 🎯 **Frozen 7-Threat Detection Engine**:
  1. **DDoS Flood** (Volumetric amplification, PPS/BPS bounds, asymmetric packet size)
  2. **C2 Beaconing** (High periodicity score via FFT/autocorrelation, tight IAT variance)
  3. **Domain Generation Algorithms (DGA)** (High Shannon entropy, query length, digit ratios)
  4. **DNS Tunneling** (Nested subdomains, base32/hex payloads, high-entropy label length)
  5. **Network Reconnaissance** (Port and host fan-out, horizontal/vertical SYN scan signatures)
  6. **Data Exfiltration** (Outbound/inbound byte asymmetry, sustained upload throughput)
  7. **TLS Behavioral Anomalies** (Encrypted session packet size/timing variance, missing SNI, non-standard port encapsulation—*without decryption*)
- 🧠 **Multi-Signal Threat Fusion**: Correlates isolated alerts from the same host across a sliding time window (60s–300s), reducing false alarms by up to 90%.
- ⛓️ **MITRE ATT&CK Kill-Chain Mapping**: Automatically reconstructs sequential intrusion stages:
  $$\text{Reconnaissance} \longrightarrow \text{Delivery (DGA)} \longrightarrow \text{Command \& Control (C2)} \longrightarrow \text{Exfiltration}$$
- 🖥️ **SOC Analyst Glassmorphic Dashboard**: Real-time interactive UI built with Next.js 14 and Tailwind CSS featuring attack velocity timelines, threat distribution charts, and granular feature audit trails.

---

## 🏗️ Architecture Overview

```
                          PASSIVE NETWORK TAP / DATA DIODE
                                         │  (RX only - TX physically disconnected)
                                         ▼
                     ┌────────────────────────────────────────┐
                     │   24-Feature Telemetry Normalizer      │
                     │  (Volume, Timing, Entropy, Fan-out)    │
                     └───────────────────┬────────────────────┘
                                         │
                                         ▼
                     ┌────────────────────────────────────────┐
                     │         HYBRID DETECTION TRIAD         │
                     │                                        │
                     │  ┌──────────────┐  ┌────────────────┐  │
                     │  │ Deterministic│  │ Random Forest  │  │
                     │  │ Rule Engine  │  │ Classifier     │  │
                     │  └──────┬───────┘  └───────┬────────┘  │
                     │         │                  │           │
                     │  ┌──────┴───────┐  ┌───────┴────────┐  │
                     │  │ Statistical  │  │ Isolation      │  │
                     │  │ Z-Score Engine│  │ Forest Anomaly │  │
                     │  └──────────────┘  └────────────────┘  │
                     └───────────────────┬────────────────────┘
                                         │ 7 Threat Detector Outputs
                                         ▼
                     ┌────────────────────────────────────────┐
                     │          ADAPTIVE BASELINE             │
                     │   (Rolling host & network norms)       │
                     └───────────────────┬────────────────────┘
                                         │ Behavior Deviations
                                         ▼
                     ┌────────────────────────────────────────┐
                     │       THREAT FUSION & CORRELATION      │
                     │   (Sliding Temporal Windows: 60s–300s) │
                     └───────────────────┬────────────────────┘
                                         │ High-Confidence Incidents
                                         ▼
                     ┌────────────────────────────────────────┐
                     │     ATTACK CHAIN RECONSTRUCTION        │
                     │     (MITRE ATT&CK Kill-Chain Stages)   │
                     └───────────────────┬────────────────────┘
                                         │
                         ┌───────────────┴───────────────┐
                         ▼                               ▼
               FastAPI SQLite Storage          Next.js 14 SOC UI
               (/api/v1/alerts)                (localhost:3000)
```

---

## 💻 Technologies Used

### Backend Engine & API
- **Python 3.9+** — Core engine and analytics runtime.
- **FastAPI** — High-performance asynchronous REST API framework.
- **Pydantic V2** — Strict data validation, schema enforcement, and serialization.
- **Uvicorn** — Lightning-fast ASGI production web server.
- **SQLite (WAL Mode)** — Embedded zero-maintenance persistence for alerts and telemetry.

### Machine Learning & Data Science
- **Scikit-Learn** — Random Forest and Isolation Forest model training, evaluation, and inference.
- **Pandas & NumPy** — High-speed vectorized numerical feature engineering.
- **Joblib** — High-efficiency binary model serialization and warm-cache loading.

### Frontend Dashboard
- **Next.js 14 (App Router)** — React framework for modern server/client UI rendering.
- **React 18 & TypeScript** — Type-safe, component-driven interactive user experience.
- **Tailwind CSS** — Modern dark-mode glassmorphic interface design system.
- **Lucide React** — Minimalist cybersecurity icon set.

### Security, Code Quality & DevOps
- **Docker & Docker Compose** — Containerized multi-service deployment.
- **GitHub Actions** — Continuous Integration (test automation, linting, vulnerability auditing).
- **Ruff** — High-performance Python linter and code formatter.
- **Bandit** — Automated Python AST static security vulnerability scanner.
- **pip-audit** — Known dependency vulnerability inspection via PyPA Advisory Database.
- **Pytest & AnyIO** — Comprehensive unit and asynchronous integration test suite.

---

## 🤖 AI Tools & Machine Learning Models

Rather than deploying heavyweight, unexplainable deep learning models that saturate line-rate network links, SentinelFlow employs a **balanced, pragmatic ML architecture**:

```
                 FEATURE VECTOR
                       │
       ┌───────────────┴───────────────┐
       ↓                               ↓
 SUPERVISED CLASSIFIER       UNSUPERVISED ANOMALY
(Random Forest - 200 Trees) (Isolation Forest - 200 Trees)
       │                               │
       ▼                               ▼
Known Multi-Class Probability     Novel Outlier Anomaly Score
  (DDOS, C2, RECON, DGA, etc.)      (Zero-days, Tunneling)
       │                               │
       └───────────────┬───────────────┘
                       │
                       ▼
              THREAT FUSION ENGINE
        (Deterministic Security Authority)
```

### 1. Supervised Random Forest Classifier (`models/random_forest.joblib`)
- **Purpose**: Classifies known attack vectors into discrete probability distributions (`BENIGN`, `DDOS`, `C2_BEACON`, `RECON`, `DGA`, `DNS_TUNNEL`, `EXFIL`).
- **Why Random Forest?**:
  - Provides instant **feature importance rankings** (e.g. MDI), enabling SOC analysts to inspect *why* a threat was classified.
  - Sub-millisecond inference per flow.
  - Resilient against collinear network telemetry (e.g., packet rate vs byte throughput).

### 2. Unsupervised Isolation Forest Anomaly Detector (`models/isolation_forest.joblib`)
- **Purpose**: Detects zero-day exploits, novel malware beacons, and encrypted tunneling that lack prior signatures.
- **Mechanism**: Learns the multidimensional boundary of normal traffic; outliers that isolate at shallow tree depths receive high anomaly scores $[0.0, 1.0]$.
- **Why Isolation Forest?**:
  - Requires **zero attack labels** during baseline training.
  - Effectively flags unusual encrypted-session metadata distributions **without decrypting TLS payloads**.

### 3. Core Principle: "ML as an Advisor, Not the Judge"
In SentinelFlow, machine learning outputs are treated as **probabilistic signals**. The final security assessment is determined through **deterministic Threat Fusion**:
$$\text{Alert Triggered} \iff (\text{Multi-Signal Correlation}) \land (\text{Baseline Deviation}) \land (\text{Temporal Proximity})$$
This guarantees explainability, prevents alert hallucination, and complies with safety standards in critical environments.

---

## 📁 Project Structure

```text
SentinelFlow/
├── backend/
│   ├── app/
│   │   ├── api/v1/             # REST endpoints (health, alerts, streams, zeek)
│   │   ├── baseline/           # Rolling adaptive statistical baselines
│   │   ├── core/               # Configuration, security boundaries, settings
│   │   ├── data/               # Public parsers (CIC-IDS2017, CTU-13, Zeek)
│   │   ├── db/                 # SQLite database connection & migrations
│   │   ├── detectors/          # 7 Modular threat detectors & engine orchestrator
│   │   │   ├── base.py         # Standard DetectionResult schema & base classes
│   │   │   ├── c2.py           # C2 Beaconing detector
│   │   │   ├── ddos.py         # DDoS Flood detector
│   │   │   ├── dga.py          # Domain Generation Algorithm detector
│   │   │   ├── dns_tunnel.py   # DNS Tunneling detector
│   │   │   ├── engine.py       # Central 7-detector execution orchestrator
│   │   │   ├── exfil.py        # Data Exfiltration detector
│   │   │   ├── recon.py        # Network Reconnaissance & Port Scan detector
│   │   │   └── tls_anomaly.py  # Zero-decryption TLS metadata anomaly detector
│   │   ├── features/           # 24-feature extraction pipeline (flow, timing, dns, behavior)
│   │   ├── fusion/             # Multi-signal correlation, temporal windows, attack chains
│   │   ├── ingest/             # Zeek and streaming telemetry log correlation
│   │   ├── ml/                 # Machine learning models, registry, training, inference
│   │   │   ├── model_registry.py
│   │   │   ├── predict.py      # MLModels prediction class
│   │   │   └── train.py        # Supervised & unsupervised model training scripts
│   │   ├── schemas/            # Pydantic data schemas (alerts, flows, detections)
│   │   ├── services/           # End-to-end detection and alert pipeline services
│   │   └── main.py             # FastAPI entrypoint application
│   ├── tests/                  # Pytest test suite (35+ automated tests)
│   ├── pyproject.toml          # Ruff and Pytest project configuration
│   └── requirements.txt        # Production backend Python dependencies
│
├── frontend/                   # Next.js 14 SOC Web Dashboard
│   ├── src/
│   │   ├── app/                # Next.js App Router pages
│   │   ├── components/         # Reusable glassmorphic UI components
│   │   └── lib/                # API client and WebSocket streaming hooks
│   ├── package.json            # Node.js dependencies
│   └── tailwind.config.ts      # Tailwind CSS theme configuration
│
├── data/                       # Datasets, samples, and schema fixtures
│   ├── raw/public/             # CIC-IDS2017 & CTU-13 test sample fixtures
│   └── sample/                 # 24-column demo flows dataset (demo_flows.csv)
│
├── models/                     # Serialized machine learning artifacts (.joblib)
│   ├── random_forest.joblib
│   ├── isolation_forest.joblib
│   ├── label_encoder.joblib
│   └── feature_columns.joblib
│
├── scripts/                    # Utilities for benchmarking, normalization, replay
│   ├── benchmark_streaming.py  # Line-rate streaming benchmark utility
│   ├── normalize_dataset.py    # Public dataset normalization script
│   └── train_detectors.py      # Model training utility
│
├── docs/                       # Architecture specifications and documentation
│   ├── 04-dataset.md           # Dataset architecture & canonical 24 features
│   ├── 05-features.md          # Feature engineering taxonomy
│   └── 06-detectors.md         # Detector engine & AI/ML integration spec
│
├── docker-compose.yml          # Containerized orchestration for local/staging runs
└── README.md                   # Project documentation
```

---

## ⚙️ Setup & Installation

### Prerequisites
- **Python**: Version 3.9, 3.10, or 3.11 installed.
- **Node.js**: Version 18.x or 20.x installed.
- **Git**: Installed and configured.

### 1. Clone the Repository
```bash
git clone https://github.com/Vivek-2004V/SentinelFlow.git
cd SentinelFlow
```

### 2. Backend Setup
```bash
# Navigate to backend
cd backend

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run database & initial model artifacts check
python -m app.ml.train
```

### 3. Frontend Setup
```bash
# From repository root
cd frontend

# Install dependencies
npm install

# Create environment configuration (optional defaults to port 8000)
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
```

---

## 🚀 Usage & Quick Start

### 1. Start the Backend API Server
```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- Interactive Swagger API Documentation: [http://localhost:8000/docs](http://localhost:8000/docs)
- OpenAPI Schema: [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

### 2. Start the Frontend SOC Dashboard
```bash
cd frontend
npm run dev
```
- Open your browser at [http://localhost:3000](http://localhost:3000) to view the live dashboard.

### 3. Run Line-Rate Streaming Benchmark
Verify throughput and latency SLA against 50 real telemetry flows:
```bash
cd backend
PYTHONPATH=. python ../scripts/benchmark_streaming.py --file ../data/sample/demo_flows.csv --count 50
```
**Measured Benchmark Performance**:
- **Throughput**: ~315 flows/second (single CPU worker)
- **Average Latency**: ~3.17 ms
- **P95 Latency**: ~3.75 ms
- **P99 Latency**: ~4.43 ms (SLA < 5ms guaranteed)

### 4. Train Models on Custom Datasets
Train the Random Forest and Isolation Forest models on any CSV dataset:
```bash
cd backend
python -c "from app.ml.train import train_models; train_models('../data/sample/demo_flows.csv')"
```

---

## 🔒 Critical Security Boundaries & Invariants

To guarantee compliance with air-gapped data diode and OT security architectures, SentinelFlow enforces hard physical and logical constraints:

| Security Invariant | System Guarantee | Enforcement Mechanism |
|---|---|---|
| **Return Path Disabled** | The system NEVER transmits packets back to the network. | Physical RX-only data diode taps; zero egress socket creation in core engine. |
| **Payload Decryption Prohibited** | Never intercepts or decrypts TLS/QUIC session payloads. | Analyzes behavioral metadata exclusively (IAT, entropy, packet sizes, SNI length). |
| **Response Mode Alert-Only** | Never issues firewall commands, TCP resets, or BGP blackholes. | Architectural boundary (`response_mode = "alert-only"`); no orchestration hooks. |
| **Air-Gapped Operation** | Zero outbound internet calls or cloud dependency. | All ML models run local in-process (`joblib` / `scikit-learn`); zero external telemetry calls. |

---

## 🧪 Verification & Automated Testing

SentinelFlow maintains rigorous automated test suites covering dataset normalization, feature engineering, detector accuracy, streaming SLAs, and security boundaries.

### Run All Unit & Integration Tests
```bash
cd backend
pytest -v --tb=short
```

### Code Quality & Static Security Scans
```bash
cd backend

# Linting & import sorting check
ruff check app tests

# Static application security analysis (AST inspection)
bandit -r app -ll -ii

# Known dependency vulnerability audit
pip-audit
```

---

## 📄 License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

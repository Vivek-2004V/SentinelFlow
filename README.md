# 🛡️ SentinelFlow

> **Passive AI/ML Threat Intelligence for One-Way Networks & Critical Infrastructure**  
> *Observe. Correlate. Explain. Never Respond.*

[![CI/CD Pipeline](https://github.com/Vivek-2004V/SentinelFlow/actions/workflows/ci.yml/badge.svg)](https://github.com/Vivek-2004V/SentinelFlow/actions)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-16+-black.svg)](https://nextjs.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Security Boundary](https://img.shields.io/badge/Return%20Path-DISABLED%20(Air--Gapped)-red.svg)](#-critical-security-boundaries--invariants)
[![Code Quality](https://img.shields.io/badge/Ruff-0%20errors-brightgreen.svg)](https://github.com/astral-sh/ruff)
[![Security SAST](https://img.shields.io/badge/Bandit-0%20issues-brightgreen.svg)](https://github.com/PyCQA/bandit)

---

## 📖 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [Architecture Overview](#-architecture-overview)
4. [Technologies Used](#-technologies-used)
5. [AI Tools & Machine Learning Models](#-ai-tools--machine-learning-models)
6. [Setup & Installation](#-setup--installation)
7. [Usage & Quick Start](#-usage--quick-start)
8. [Project Structure](#-project-structure)
9. [Critical Security Boundaries & Invariants](#-critical-security-boundaries--invariants)
10. [Dataset Provenance & Zero-Leakage Splitting](#-dataset-provenance--zero-leakage-splitting)
11. [Verification, Security Auditing & CI/CD](#-verification-security-auditing--cicd)
12. [License](#-license)

---

## 🌐 Project Overview

Modern critical infrastructure—such as power grids, nuclear facilities, manufacturing SCADA/ICS environments, and air-gapped defense enclaves—relies on **physical data diodes** and unidirectional network taps to isolate operational networks from untrusted zones.

### The Problem with Traditional IDPS:
- **Bi-directional Assumptions**: Active scanners, TCP resets, honeypot probes, and automated mitigation commands introduce dangerous return paths into air-gapped segments.
- **Deep Packet Inspection (DPI) Failure**: Requires man-in-the-middle SSL/TLS decryption keys, violating privacy mandates and introducing key management vulnerabilities.
- **Alert Fatigue**: Tens of thousands of isolated, uncoordinated alerts overwhelm SOC analysts without contextual multi-stage campaign reconstruction.

### The SentinelFlow Solution:
**SentinelFlow** is purpose-built for strict unidirectional and air-gapped monitoring environments. By operating purely on **passively captured metadata** (NetFlow, IPFIX, Zeek JSON logs, and PCAP headers), SentinelFlow extracts a **canonical 24-feature telemetry vector**, evaluates it across a **Hybrid Detection Triad (Deterministic Signatures + 2 Machine Learning Models + Adaptive Baselines)**, and correlates multi-stage intrusion campaigns into explainable **Attack Chains**—with **zero payload decryption** and **zero return-path packets**.

```
    PASSIVE MONITORING TAP / DATA DIODE (RX Only)
                         │
                         ▼
        ┌──────────────────────────────────┐
        │     CANONICAL FEATURE ENGINE     │
        │   (24 Flow, Timing & Entropy)    │
        └────────────────┬─────────────────┘
                         │
                         ▼
        ┌──────────────────────────────────┐
        │      HYBRID DETECTION TRIAD      │
        │  • Deterministic Signatures      │
        │  • Random Forest (Supervised)    │
        │  • Isolation Forest (Anomaly)    │
        │  • Adaptive Rolling Baseline     │
        └────────────────┬─────────────────┘
                         │
                         ▼
        ┌──────────────────────────────────┐
        │       THREAT FUSION ENGINE       │
        │ (Multi-Signal Scoring & Chains)  │
        └────────────────┬─────────────────┘
                         │
                         ▼
        ┌──────────────────────────────────┐
        │  EXPLAINABLE EVIDENCE & SOC UI   │
        │   (Next.js Glassmorphic SOC)     │
        └──────────────────────────────────┘
```

---

## ✨ Key Features

- 🔒 **Zero-Touch Passive Ingestion**: Operates strictly behind optical taps, SPAN ports, or physical data diodes. No socket write calls or return packets are ever generated.
- ⚡ **Sub-5ms Streaming SLA**: High-throughput continuous pipeline processing 300+ flows/second with median ($P50$) latency $< 3.3\text{ ms}$ and $P99$ latency $< 5.0\text{ ms}$.
- 📐 **Canonical 24-Feature Telemetry Schema**: Normalizes heterogeneous logs (Zeek, NetFlow, CIC-IDS2017, CIC-DDoS2019, CTU-13) into standardized temporal, behavioral, volumetric, and entropy metrics.
- 🎯 **Frozen 7-Threat Detection Engine**:
  1. **DDoS Flood** — Volumetric amplification, PPS/BPS threshold bounds, and asymmetric packet sizing.
  2. **C2 Beaconing** — Periodicity auto-correlation ($\ge 0.90$) and low Inter-Arrival Time (IAT) variance.
  3. **Domain Generation Algorithms (DGA)** — High Shannon entropy ($\ge 3.8$) and character distribution randomness.
  4. **DNS Tunneling** — High-entropy query length, nested subdomains, and payload base32/hex encapsulation.
  5. **Network Reconnaissance** — High port/host fan-out dispersion and horizontal/vertical SYN sweep signatures.
  6. **Data Exfiltration** — High outbound-to-inbound byte ratio asymmetry ($\ge 5.0$) and sustained upload bursts.
  7. **TLS Behavioral Anomalies** — Encrypted session packet size/timing variance and anomalous metadata without payload decryption.
- 📈 **Adaptive Rolling Baseline**: Online EWMA tracking per-host statistical variance ($Z\text{-score} > 2.5\sigma$) to identify behavioral deviation without static threshold brittleness.
- 🧠 **Multi-Signal Threat Fusion**: Correlates isolated alerts from the same source host across sliding temporal windows (60s–300s), reducing false alarms by up to 90%.
- ⛓️ **MITRE ATT&CK Kill-Chain Reconstruction**: Automatically aggregates sequential attack stages:
  $$\text{Reconnaissance} \longrightarrow \text{Delivery (DGA)} \longrightarrow \text{Command \& Control (C2)} \longrightarrow \text{Exfiltration}$$
- 🧾 **Explainable Evidence Drawer**: Granular feature audit trails explaining *why* an alert triggered, eliminating black-box opacity.
- 🎬 **Built-in Demo / Replay Mode**: Ingests canonical test telemetry from `demo_flows.csv` for transparent evaluation.
- 🖥️ **Next.js SOC Command Center**: Dark-mode glassmorphic dashboard with live 5-second polling, interactive kill chains, and real-time connectivity status.

---

## 🏗️ Architecture Overview

```
             DATA SOURCES
  (PCAP / Zeek JSONL / NetFlow / Replay Engine)
                  │
                  ▼
       ┌──────────────────────┐
       │   Feature Engine     │ ──► Extracts 24 Canonical Flow, Timing,
       └──────────┬───────────┘     and Entropy Features
                  ▼
    ┌─────────────────────────────┐
    │     HYBRID DETECTION TRIAD   │
    │  ┌───────────────────────┐  │
    │  │ Deterministic Heuristics│ │ ──► Port bounds, entropy, fan-out
    │  └───────────────────────┘  │
    │  ┌───────────────────────┐  │
    │  │ Random Forest (200 T) │  │ ──► Supervised known threat classification
    │  └───────────────────────┘  │
    │  ┌───────────────────────┐  │
    │  │ Isolation Forest (200)│  │ ──► Unsupervised zero-day anomaly isolation
    │  └───────────────────────┘  │
    │  ┌───────────────────────┐  │
    │  │ Adaptive Host Baseline│  │ ──► Dynamic EWMA rolling behavior model
    │  └───────────────────────┘  │
    └─────────────┬───────────────┘
                  ▼
       ┌──────────────────────┐
       │ Threat Fusion Engine │ ──► Multi-Signal Cross-Validation
       └──────────┬───────────┘
                  ▼
       ┌──────────────────────┐
       │ Attack Chain Engine  │ ──► Temporal Sliding-Window Correlation
       └──────────┬───────────┘
                  ▼
       ┌──────────────────────┐
       │   Evidence Builder   │ ──► Explainable Audit Trail
       └──────────┬───────────┘
                  ▼
           FastAPI Backend
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
   GET /metrics        GET /alerts
        │                   │
        └─────────┬─────────┘
                  ▼
        Next.js SOC Dashboard
```

---

## 💻 Technologies Used

### Backend Engine & API
- **Python 3.9+ / 3.11** — Core processing pipeline and statistical analytics runtime.
- **FastAPI** — High-performance asynchronous REST API framework.
- **Pydantic V2 & Settings** — Strict schema validation, type safety, and configuration.
- **Uvicorn** — Production ASGI web server.
- **SQLite (WAL Mode)** — Embedded zero-maintenance alert and session persistence.

### Machine Learning & Data Science
- **Scikit-Learn** — Random Forest and Isolation Forest training, validation, and inference.
- **Pandas & NumPy** — High-speed vectorized numerical feature engineering.
- **Joblib** — High-efficiency binary model serialization and warm-cache loading.

### Frontend SOC Dashboard
- **Next.js 16 (App Router & Turbopack)** — Server and client rendering framework.
- **React 19 & TypeScript** — Component-driven, type-safe SOC user interface.
- **Tailwind CSS** — Tailored HSL dark glassmorphic styling and micro-animations.
- **Lucide React** — Minimalist cybersecurity vector iconography.

### Security, Quality Assurance & DevOps
- **Docker & Docker Compose** — Containerized multi-service deployment.
- **GitHub Actions** — Continuous Integration pipeline (linting, SAST, unit tests, frontend build).
- **Ruff** — High-speed Python linter and code formatter (**0 errors**).
- **Bandit** — Automated Python AST static security vulnerability scanner (**0 issues** across 5,581 LOC).
- **pip-audit** — Dependency vulnerability auditing via PyPA Advisory Database.
- **Pytest** — Complete test suite (**59/59 passing automated unit & integration tests**).

---

## 🤖 AI Tools & Machine Learning Models

SentinelFlow strictly enforces the use of **exactly two machine learning models** combined with deterministic mathematical heuristics:

```
                      24-FEATURE TELEMETRY VECTOR
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
      ┌─────────────────────┐             ┌─────────────────────┐
      │    RANDOM FOREST    │             │  ISOLATION FOREST   │
      │ Supervised Ensemble │             │ Unsupervised Anomaly│
      │     (200 Trees)     │             │     (200 Trees)     │
      └──────────┬──────────┘             └──────────┬──────────┘
                 │                                   │
                 ▼                                   ▼
        Known Threat Vector                 Unseen Outlier Score
     Multi-Class Probabilities              Zero-Day Isolation
                 │                                   │
                 └─────────────────┬─────────────────┘
                                   │
                                   ▼
                      ┌─────────────────────────┐
                      │  THREAT FUSION ENGINE   │
                      │ (Deterministic Arbiter) │
                      └─────────────────────────┘
```

### 1. Supervised Random Forest Classifier (`models/random_forest.joblib`)
- **Architecture**: 200 estimators, Gini impurity criterion, maximum feature sub-sampling.
- **Purpose**: Multi-class classification across 7 known threat vectors (`BENIGN`, `DDOS`, `C2_BEACON`, `RECON`, `DGA`, `DNS_TUNNEL`, `EXFIL`).
- **Performance on Unseen Disjoint Test Set**:
  - **Overall F1-Score**: `0.997`
  - **Validation Set**: 1,048 flows
  - **Unseen Test Evaluation**: 524 flows
  - **Inference Latency**: $< 0.4\text{ ms}$ per flow

### 2. Unsupervised Isolation Forest Detector (`models/isolation_forest.joblib`)
- **Architecture**: 200 isolation trees, 5% contamination rate, random path isolation.
- **Purpose**: Detects zero-day exploits, novel malware beacons, and encrypted tunneling that lack prior signatures.
- **Performance on Anomalous Outliers**:
  - **Outlier Precision**: `88.98%`
  - **False Positive Rate (FPR)**: `13.73%`
  - **Training Invariant**: Trained exclusively on normal traffic distributions; requires zero attack labels.

### 3. Non-AI Deterministic Statistical Signals
- **Shannon DNS Entropy**: Algorithmic pseudorandom character dispersion calculation ($H = -\sum p_i \log_2 p_i$).
- **Periodicity Autocorrelation**: Discrete FFT & lag auto-correlation tracking regular C2 beacon cadences.
- **Traffic Rate Bounds**: Non-linear PPS/BPS surge detection.
- **Fan-Out Dispersion**: Unique destination port/host entropy for reconnaissance detection.
- **Byte Ratio Asymmetry**: Directional byte imbalance calculation ($\frac{\text{Outbound Bytes}}{\text{Inbound Bytes}}$).
- **Adaptive Baseline Z-Score**: Rolling EWMA per-host deviation ($Z = \frac{|x - \mu|}{\sigma}$).

### 4. Architectural Boundary on LLMs: "Advisory Explanation Only"
> [!IMPORTANT]
> **LLMs are NEVER used as primary security decision-makers or policy mutators.**  
> If an LLM is enabled, its role is strictly confined to generating natural language summaries of deterministic evidence for SOC analysts. The core detection, scoring, and correlation pipeline remains 100% deterministic and reproducible.

---

## ⚙️ Setup & Installation

### Prerequisites
- **Python**: Version 3.9, 3.10, or 3.11 installed.
- **Node.js**: Version 18.x, 20.x, or 22.x installed.
- **Docker & Docker Compose** (optional for containerized deployment).

### 1. Clone the Repository
```bash
git clone https://github.com/Vivek-2004V/SentinelFlow.git
cd SentinelFlow
```

### 2. Backend Setup
```bash
cd backend

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify model artifacts exist (or retrain if needed)
python -m app.ml.train_classifier
python -m app.ml.train_anomaly
```

### 3. Frontend Setup
```bash
cd ../frontend

# Install dependencies
npm install

# Create environment configuration (defaults to port 8000)
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
```

### 4. Docker Containerized Setup (Alternative)
```bash
# From repository root
docker-compose up --build
```
- Backend API will be available at `http://localhost:8000`
- Frontend SOC Dashboard will be available at `http://localhost:3000`

---

## 🚀 Usage & Quick Start

### 1. Start the Backend API Server
```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- **Interactive Swagger Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check Endpoint**: [http://localhost:8000/health](http://localhost:8000/health)
- **Status Endpoint**: [http://localhost:8000/api/v1/status](http://localhost:8000/api/v1/status)

### 2. Start the Frontend SOC Dashboard
```bash
cd frontend
npm run dev
```
- Open [http://localhost:3000](http://localhost:3000) in your browser.
- The dashboard automatically connects to the backend and polls live telemetry every 5 seconds.

### 3. Execute In-Process Telemetry Replay
Replay canonical test flows from `data/sample/demo_flows.csv` directly through the full engine:
```bash
cd backend
python -m app.ingest.replay
```

### 4. Run Line-Rate Streaming Benchmark
Verify throughput and latency SLAs:
```bash
cd backend
PYTHONPATH=. python ../scripts/benchmark_streaming.py --file ../data/sample/demo_flows.csv --count 50
```

---

## 📁 Project Structure

```text
SentinelFlow/
├── backend/
│   ├── app/
│   │   ├── api/v1/                 # REST API endpoints
│   │   │   ├── endpoints/
│   │   │   │   ├── alerts.py       # Alert listing & flow analysis
│   │   │   │   ├── chains.py       # Multi-stage attack chain correlations
│   │   │   │   └── metrics.py      # Live SOC KPI metrics
│   │   │   └── router.py           # V1 API router mounting
│   │   ├── baseline/               # Rolling adaptive statistical baselines
│   │   │   └── adaptive.py         # Online EWMA Z-Score engine
│   │   ├── chains/                 # Attack chain patterns & temporal correlation
│   │   │   └── attack_chain.py     # MITRE ATT&CK correlation logic
│   │   ├── core/                   # System configuration & security boundaries
│   │   │   └── config.py           # CORS, timeouts, and env settings
│   │   ├── detectors/              # 7 Modular threat detectors
│   │   │   ├── base.py             # Base detector & DetectionResult schema
│   │   │   ├── c2.py               # C2 Beaconing detector
│   │   │   ├── ddos.py             # DDoS Flood detector
│   │   │   ├── dga.py              # Domain Generation Algorithm detector
│   │   │   ├── dns_tunnel.py       # DNS Tunneling detector
│   │   │   ├── engine.py           # 7-Detector execution orchestrator
│   │   │   ├── exfil.py            # Data Exfiltration detector
│   │   │   ├── recon.py            # Reconnaissance & Port Scan detector
│   │   │   └── tls_anomaly.py      # Zero-decryption TLS anomaly detector
│   │   ├── evidence/               # Explainable evidence generation
│   │   │   └── engine.py           # Feature extraction & severity matrix
│   │   ├── features/               # Canonical 24-feature extraction pipeline
│   │   │   ├── flow_features.py    # Volume and rate calculations
│   │   │   ├── timing_features.py  # IAT mean, std, and periodicity
│   │   │   ├── dns_features.py     # Query length, Shannon entropy, digit ratio
│   │   │   └── behavior_features.py# Fan-out dispersion and byte ratio asymmetry
│   │   ├── fusion/                 # Multi-signal Threat Fusion engine
│   │   │   ├── fusion.py           # Weighted triad aggregator
│   │   │   └── temporal.py         # Sliding window host correlation
│   │   ├── ingest/                 # Replay & log ingestion engines
│   │   │   ├── replay.py           # In-process demo flow replay engine
│   │   │   └── zeek.py             # Zeek JSONL multi-log parser
│   │   ├── ml/                     # ML training, evaluation, and inference
│   │   │   ├── evaluate.py         # Multi-metric evaluation harness
│   │   │   ├── model_registry.py   # Cached model artifact loader
│   │   │   ├── predict.py          # Dual-model inference class
│   │   │   ├── train_anomaly.py    # Isolation Forest training script
│   │   │   └── train_classifier.py # Random Forest training script
│   │   ├── schemas/                # Strict Pydantic data schemas
│   │   ├── services/               # End-to-end pipeline orchestrator
│   │   └── main.py                 # FastAPI application entrypoint
│   ├── tests/                      # Pytest automated test suite (59 tests)
│   │   ├── test_alerts.py
│   │   ├── test_attack_chain.py    # Kill chain correlation tests
│   │   ├── test_baseline.py        # Adaptive baseline tests
│   │   ├── test_dataset_architecture.py
│   │   ├── test_detectors.py       # 7 Detector unit tests
│   │   ├── test_evidence.py        # Explainability tests
│   │   ├── test_features.py        # 24-feature extraction tests
│   │   ├── test_fusion.py          # Threat fusion tests
│   │   ├── test_health.py          # Health & status tests
│   │   ├── test_hybrid_triad.py
│   │   ├── test_llm_role.py        # LLM advisory boundary tests
│   │   ├── test_pipeline.py
│   │   ├── test_security_boundary.py # Passive invariant validation
│   │   ├── test_sqlite_zeek.py
│   │   └── test_streaming_benchmark.py
│   ├── Dockerfile                  # Production backend container definition
│   ├── pyproject.toml              # Ruff and Pytest configuration
│   └── requirements.txt            # Production Python dependencies
│
├── frontend/                       # Next.js 16 SOC Dashboard
│   ├── src/
│   │   ├── app/                    # Next.js App Router (page.tsx, layout.tsx)
│   │   ├── components/
│   │   │   ├── dashboard/          # SOC components (HeroDataFlow, AttackChain,
│   │   │   │                       # AdaptiveBaseline, MLIntelligence, LiveIntelligence)
│   │   │   └── layout/             # Header, Sidebar, and status indicators
│   │   ├── lib/                    # API client and demo fallback data
│   │   └── types/                  # Modular TypeScript interfaces
│   ├── Dockerfile                  # Multi-stage production frontend container
│   ├── package.json
│   └── tailwind.config.ts
│
├── data/                           # Telemetry fixtures and samples
│   ├── raw/public/                 # Public dataset sample fixtures
│   └── sample/                     # Canonical demo dataset (demo_flows.csv)
│
├── models/                         # Serialized ML artifacts & metadata
│   ├── README.md                   # Model provenance, hyperparameters & seeds
│   └── .gitkeep                    # Binaries excluded from git via .gitignore
│
├── scripts/                        # Dataset normalization & evaluation scripts
│   ├── benchmark_streaming.py      # Streaming SLA benchmarking utility
│   ├── clean_data.py               # Data cleaning & type coercion
│   ├── evaluate_anomaly.py         # Isolation Forest evaluation script
│   ├── evaluate_model.py           # Random Forest evaluation script
│   ├── inspect_dataset.py          # Dataset inspection utility
│   ├── label_mapping.py            # 7-Class label normalizer
│   └── normalize_cic2017.py        # Header & schema normalizer
│
├── docs/                           # Architectural specifications
│   ├── 04-dataset.md               # Dataset provenance & split breakdown
│   ├── 05-features.md              # 24-feature canonical taxonomy
│   ├── 06-detectors.md             # Threat detector engine specifications
│   └── 07-fusion.md                # Threat fusion & temporal window specs
│
├── .github/workflows/ci.yml        # GitHub Actions continuous integration pipeline
├── docker-compose.yml              # Multi-container orchestration definition
└── README.md                       # Comprehensive project documentation
```

---

## 🔒 Critical Security Boundaries & Invariants

SentinelFlow strictly enforces the following physical and logical invariants:

| Security Invariant | System Guarantee | Enforcement Mechanism |
| :--- | :--- | :--- |
| **100% Passive Ingestion** | The system NEVER probes, scans, or injects packets into monitored networks. | Physical RX-only taps; zero egress socket creation in core engine. |
| **Zero Payload Decryption** | TLS/QUIC session payloads are never decrypted or intercepted. | Analyzes L3/L4 headers, packet timing, and entropy exclusively. |
| **Strictly Read-Only** | Operates as a passive telemetry sink. | No active network discovery, ARP sweeps, or ICMP probing. |
| **Alert-Only Response Mode** | Never executes automated blocking commands, firewall updates, or TCP resets. | Architectural boundary (`action: "ALERT_ONLY"`); zero active orchestration hooks. Forbidden routes (`/block`, `/isolate`, `/mitigate`) return `404 Not Found`. |
| **No Return Path** | Physical and software unidirectional invariant. | Hardware data diode compatibility; zero return socket binding. |

---

## 📊 Dataset Provenance & Zero-Leakage Splitting

SentinelFlow's models and detectors are evaluated against standard benchmark datasets using **strict run/day-based disjoint partitioning** to prevent data leakage:

### Datasets Utilized:
1. **CIC-IDS2017** (Canadian Institute for Cybersecurity) — Real-world benign activity and attack vectors (DDoS, PortScan, Botnet C2, Web Attacks).
2. **CIC-DDoS2019** (Canadian Institute for Cybersecurity) — High-volume volumetric and protocol-level DDoS traffic.
3. **CTU-13** (Stratosphere Laboratory, Czech Technical University) — Botnet malware captures with real C2 communication.

### Zero-Leakage Disjoint Partitioning:
```
ATTACK RUN / DAY A  (e.g., Monday Benign + Tuesday Recon)  ──► TRAINING SET (60%)
ATTACK RUN / DAY B  (e.g., Wednesday DoS + Thursday Web)   ──► VALIDATION SET (20%)
ATTACK RUN / DAY C  (e.g., Friday Botnet & DDoS)           ──► UNSEEN TEST SET (20%)
```

> [!NOTE]
> Training and testing rows are partitioned strictly by distinct capture runs/days, never by random row shuffling. This ensures the models learn generalized behavioral patterns rather than memorizing static IP or timestamp artifacts.

---

## 🛡️ Verification, Security Auditing & CI/CD

### 1. Automated Test Suite Execution
```bash
cd backend
pytest -v --tb=short
```
**Results**: `59 passed in 1.54s` across all functional and security modules.

### 2. Static Security & Code Quality Hardening
```bash
cd backend

# Ruff Linting & Formatting
ruff check app tests
# Output: All checks passed! (0 errors)

# Bandit AST Security Scanner
bandit -r app
# Output: 5,581 lines scanned — 0 issues identified!

# pip-audit Dependency Vulnerability Scanner
pip-audit
```

### 3. Continuous Integration Pipeline
Every push and pull request against `main` triggers [GitHub Actions CI](.github/workflows/ci.yml) verifying:
- Python 3.11 environment dependency installation
- Full Pytest suite execution
- Ruff style and syntax compliance
- Bandit static security analysis
- Streaming throughput and latency SLA benchmarking
- Next.js 16 production build and TypeScript typechecking

---

## 📄 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

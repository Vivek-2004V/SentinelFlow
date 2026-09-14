# 🛡️ SentinelFlow

> **Passive AI Threat Intelligence for One-Way Networks & Critical Infrastructure**  
> *Observe. Correlate. Explain. Never Respond.*

[![CI/CD Pipeline](https://github.com/Vivek-2004V/SentinelFlow/actions/workflows/ci.yml/badge.svg)](https://github.com/Vivek-2004V/SentinelFlow/actions)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-16+-black.svg)](https://nextjs.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Security Invariant](https://img.shields.io/badge/Return%20Path-DISABLED%20(Air--Gapped)-red.svg)](#-critical-security-boundaries--invariants)
[![Code Quality](https://img.shields.io/badge/Ruff-0%20errors-brightgreen.svg)](https://github.com/astral-sh/ruff)
[![Security SAST](https://img.shields.io/badge/Bandit-0%20issues-brightgreen.svg)](https://github.com/PyCQA/bandit)

---

## 📖 Table of Contents
1. [🌟 Project Overview](#-project-overview)
2. [✨ Key Features](#-key-features)
3. [🏗️ System Architecture](#️-system-architecture)
4. [🛠️ Technologies Used](#️-technologies-used)
5. [🤖 AI Tools & Machine Learning Models](#-ai-tools--machine-learning-models)
6. [⚙️ Setup & Installation Instructions](#️-setup--installation-instructions)
7. [🚀 Usage & Quick Start Guide](#-usage--quick-start-guide)
8. [📁 Project Structure](#-project-structure)
9. [🔒 Critical Security Boundaries & Invariants](#-critical-security-boundaries--invariants)
10. [📊 Dataset Provenance & Zero-Leakage Validation](#-dataset-provenance--zero-leakage-validation)
11. [🧪 Testing, Security Hardening & CI/CD](#-testing-security-hardening--cicd)
12. [📄 License](#-license)

---

## 🌟 Project Overview

Critical infrastructure—such as power grids, nuclear facilities, industrial manufacturing plants, and defense networks—often operates behind **physical data diodes** and optical network taps. In these environments, data can only travel in one direction to prevent remote attackers from sending malicious commands back into protected networks.

### The Problem
Traditional Intrusion Detection and Prevention Systems (IDPS) are not built for these environments:
- **Active Scanning Risks**: They often try to probe devices, send TCP resets, or trigger firewall actions, which violates one-way isolation.
- **Payload Decryption Limitations**: They require decrypting TLS/SSL traffic, which compromises privacy, introduces key management risks, and breaks compliance mandates.
- **Alert Overload**: They produce thousands of disconnected alerts, creating massive alert fatigue for SOC analysts.

### The SentinelFlow Solution
**SentinelFlow** is an open-source, passive cybersecurity platform designed specifically for one-way and air-gapped network monitoring.

- **100% Passive & Read-Only**: Analyzes network metadata (packet sizes, flow timing, DNS queries, entropy) without ever sending a single packet back into the network.
- **Zero Payload Decryption**: Detects threats purely from statistical patterns and flow behavior without inspecting encrypted payloads.
- **Hybrid Threat Intelligence**: Combines deterministic rules, **two purpose-built ML models** (Random Forest & Isolation Forest), and adaptive baselines to accurately detect and explain complex cyber attacks.

```text
    PASSIVE NETWORK TAP / DATA DIODE (RX Only)
                         │
                         ▼
        ┌──────────────────────────────────┐
        │     24-FEATURE FEATURE ENGINE    │
        │  (Volume, Timing, DNS, Entropy)  │
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
        │  (Multi-Signal Attack Chains)    │
        └────────────────┬─────────────────┘
                         │
                         ▼
        ┌──────────────────────────────────┐
        │      NEXT.JS SOC COMMAND UI      │
        │  (Explainable Evidence Drawer)   │
        └──────────────────────────────────┘
```

---

## ✨ Key Features

- 🔒 **Zero-Touch Passive Ingestion**: Listens strictly to passive telemetry feeds (PCAP, Zeek JSON logs, NetFlow, or Replay). Operates with zero return-path sockets.
- ⚡ **High-Speed Real-Time Processing**: Analyzes over 300 flows per second with a sub-5ms latency guarantee ($P50 < 3.3\text{ ms}$, $P99 < 5.0\text{ ms}$).
- 📐 **Standardized 24-Feature Schema**: Normalizes network data into 24 canonical features across flow volume, timing, DNS metadata, and host behavior.
- 🎯 **7 Core Threat Detection Vectors**:
  1. **DDoS Floods** — Volumetric spikes, abnormal packet rates, and asymmetric traffic.
  2. **C2 Beaconing** — Regular periodic intervals detected via auto-correlation ($\ge 0.90$) and low timing variance.
  3. **Domain Generation Algorithms (DGA)** — High Shannon entropy ($\ge 3.8$) and randomized domain name patterns.
  4. **DNS Tunneling** — Abnormally long queries, high entropy, and encoded data exfiltration via DNS.
  5. **Network Reconnaissance** — Vertical port scans and horizontal host sweep detection.
  6. **Data Exfiltration** — High outbound-to-inbound byte ratios ($\ge 5.0$) and sustained data transfers.
  7. **TLS Behavioral Anomalies** — Unusual encrypted session metadata and timing patterns *without decrypting traffic*.
- 📈 **Adaptive Rolling Baseline**: Continuously learns per-host normal behavior using online EWMA statistical tracking ($Z\text{-score} > 2.5\sigma$) to flag abnormal shifts.
- 🧠 **Threat Fusion Engine**: Correlates multiple detection signals from the same host across a bounded sliding time window (60s–300s), reducing false alarms by up to 90%.
- ⛓️ **MITRE ATT&CK Kill-Chain Reconstruction**: Automatically links sequential multi-stage attacks:
  $$\text{Reconnaissance} \longrightarrow \text{Delivery (DGA)} \longrightarrow \text{Command \& Control (C2)} \longrightarrow \text{Exfiltration}$$
- 🧾 **Explainable Evidence Drawer**: Gives SOC analysts clear, human-readable explanations and feature values behind every single alert.
- 🎬 **Integrated Demo / Replay Mode**: Includes a flow replay engine with `demo_flows.csv` for realistic, instant demonstration.
- 🖥️ **Modern SOC Command Center**: Dark-mode glassmorphic Next.js dashboard with live 5-second polling, interactive charts, and real-time connectivity status.

---

## 🏗️ System Architecture

```text
               DATA INGRESS
 (PCAP / Zeek JSONL / NetFlow / Demo Replay)
                    │
                    ▼
         ┌─────────────────────┐
         │   Feature Engine    │ ──► Extracts 24 canonical features
         └──────────┬──────────┘
                    ▼
     ┌─────────────────────────────┐
     │    HYBRID DETECTION TRIAD   │
     │ ┌─────────────────────────┐ │
     │ │ Deterministic Rules     │ │ ──► Port bounds, entropy, fan-out
     │ └─────────────────────────┘ │
     │ ┌─────────────────────────┐ │
     │ │ Random Forest (200 T)   │ │ ──► Supervised known threat classifier
     │ └─────────────────────────┘ │
     │ ┌─────────────────────────┐ │
     │ │ Isolation Forest (200 T)│ │ ──► Unsupervised zero-day anomaly detector
     │ └─────────────────────────┘ │
     │ ┌─────────────────────────┐ │
     │ │ Adaptive Baseline (EWMA)│ │ ──► Rolling per-host behavior deviation
     │ └─────────────────────────┘ │
     └──────────────┬──────────────┘
                    ▼
         ┌─────────────────────┐
         │ Threat Fusion Engine│ ──► Multi-signal aggregation & scoring
         └──────────┬──────────┘
                    ▼
         ┌─────────────────────┐
         │ Attack Chain Engine │ ──► Multi-stage temporal correlation
         └──────────┬──────────┘
                    ▼
         ┌─────────────────────┐
         │  Evidence Builder   │ ──► Explainable audit trail
         └──────────┬──────────┘
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

## 🛠️ Technologies Used

### Backend API & Core Processing
- **Python 3.9+ / 3.11**: Core telemetry processing pipeline and analytics runtime.
- **FastAPI**: High-performance asynchronous REST API framework.
- **Pydantic V2**: Strict schema validation, data serialization, and configuration management.
- **Uvicorn**: High-performance ASGI production server.
- **SQLite (WAL Mode)**: Lightweight embedded database for alert logging and multi-log correlation.

### Machine Learning & Data Science
- **Scikit-Learn**: Implementation of Random Forest and Isolation Forest models.
- **Pandas & NumPy**: Vectorized feature extraction and dataset processing.
- **Joblib**: Efficient model serialization and in-memory artifact loading.

### Frontend SOC Dashboard
- **Next.js 16 (App Router & Turbopack)**: Fast, modern React application framework.
- **React 19 & TypeScript**: Type-safe, modular component architecture.
- **Tailwind CSS**: Glassmorphic dark-theme UI with responsive layouts and smooth micro-animations.
- **Lucide React**: Clean cybersecurity iconography.

### Security, Quality Assurance & DevOps
- **Docker & Docker Compose**: Multi-service containerized deployment.
- **GitHub Actions**: Automated Continuous Integration (CI) pipeline.
- **Ruff**: Fast Python linter and code formatter (**0 errors**).
- **Bandit**: Static application security testing (SAST) (**0 issues** across 5,581 LOC).
- **pip-audit**: Automated dependency vulnerability scanner.
- **Pytest**: Full automated unit and integration testing (**59/59 tests passing**).

---

## 🤖 AI Tools & Machine Learning Models

SentinelFlow uses **exactly two machine learning models** working alongside deterministic mathematical rules:

```text
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
- **Purpose**: Classifies known network threats into 7 frozen categories (`BENIGN`, `DDOS`, `C2_BEACON`, `RECON`, `DGA`, `DNS_TUNNEL`, `EXFIL`).
- **Configuration**: 200 decision trees, Gini criterion, max feature sub-sampling.
- **Measured Evaluation on Unseen Test Data**:
  - **F1-Score**: `0.997`
  - **Validation Set**: 1,048 flows
  - **Unseen Test Set**: 524 flows
  - **Inference Speed**: $< 0.4\text{ ms}$ per flow

### 2. Unsupervised Isolation Forest Detector (`models/isolation_forest.joblib`)
- **Purpose**: Detects novel, zero-day anomalies and stealthy encrypted channels without needing prior attack signatures.
- **Configuration**: 200 isolation trees, 5% contamination factor.
- **Measured Evaluation**:
  - **Outlier Precision**: `88.98%`
  - **False Positive Rate (FPR)**: `13.73%`
  - **Key Benefit**: Trained purely on normal network patterns; requires zero malicious labels.

### 3. Deterministic Mathematical Signals (Non-AI)
- **Shannon DNS Entropy**: Calculates character randomness in domain queries ($H = -\sum p_i \log_2 p_i$).
- **Periodicity Autocorrelation**: Uses lag correlation to detect regular beaconing cadences.
- **Traffic Rate Bounds**: Flags non-linear PPS and BPS surges.
- **Fan-Out Dispersion**: Tracks destination port and host connection spread.
- **Byte Ratio Asymmetry**: Calculates upload/download ratio imbalances ($\frac{\text{Outbound Bytes}}{\text{Inbound Bytes}}$).
- **Adaptive Baseline Z-Score**: Computes dynamic standard deviation distance ($Z = \frac{|x - \mu|}{\sigma}$).

### 4. Important LLM Invariant: "Advisory Explanation Only"
> [!IMPORTANT]
> **LLMs are NEVER allowed to make security decisions, block traffic, or alter threat scores.**  
> If an LLM is enabled, its purpose is strictly limited to generating plain-English explanations of deterministic evidence for SOC analysts. The core detection and correlation pipeline remains 100% deterministic, explainable, and reproducible.

---

## ⚙️ Setup & Installation Instructions

### Prerequisites
- **Python**: Version 3.9, 3.10, or 3.11 installed.
- **Node.js**: Version 18.x, 20.x, or 22.x installed.
- **Git**: Installed and configured.
- **Docker & Docker Compose** (optional for containerized deployment).

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/Vivek-2004V/SentinelFlow.git
cd SentinelFlow
```

---

### Step 2: Backend Setup
```bash
# Navigate to the backend directory
cd backend

# Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify model training artifacts exist (optional: re-train locally)
python -m app.ml.train_classifier
python -m app.ml.train_anomaly
```

---

### Step 3: Frontend Setup
```bash
# Navigate to the frontend directory
cd ../frontend

# Install dependencies
npm install

# Create local environment config pointing to the backend API
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
```

---

### Step 4: Docker Setup (One-Command Alternative)
If you prefer running the entire stack in containers:
```bash
# From the repository root
docker-compose up --build
```
- Backend API will start at `http://localhost:8000`
- Frontend Dashboard will start at `http://localhost:3000`

---

## 🚀 Usage & Quick Start Guide

### 1. Launch the Backend API
```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)
- **System Status**: [http://localhost:8000/api/v1/status](http://localhost:8000/api/v1/status)

### 2. Launch the SOC Web Dashboard
```bash
cd frontend
npm run dev
```
- Open [http://localhost:3000](http://localhost:3000) in your web browser.
- The dashboard will connect to the backend and automatically refresh telemetry every 5 seconds.

### 3. Replay Demo Network Traffic
Simulate realistic telemetry flows through the complete detection and correlation pipeline:
```bash
cd backend
python -m app.ingest.replay
```

### 4. Run the High-Speed Streaming Benchmark
Test throughput and latency on 50 sample network flows:
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
│   │   ├── api/v1/                 # REST API endpoints (alerts, metrics, chains)
│   │   │   ├── endpoints/
│   │   │   │   ├── alerts.py       # Alert queries and flow analysis
│   │   │   │   ├── chains.py       # Multi-stage attack chain correlations
│   │   │   │   └── metrics.py      # SOC dashboard metrics and KPIs
│   │   │   └── router.py           # API router mounting
│   │   ├── baseline/               # Adaptive baseline profiling (EWMA Z-Scores)
│   │   │   └── adaptive.py         # Rolling per-host behavior model
│   │   ├── chains/                 # Attack chain correlation engine
│   │   │   └── attack_chain.py     # MITRE ATT&CK multi-stage sequence logic
│   │   ├── core/                   # Configuration and security settings
│   │   │   └── config.py           # CORS origins, timeouts, environment config
│   │   ├── detectors/              # 7 Modular threat detectors
│   │   │   ├── base.py             # Base detector & DetectionResult schema
│   │   │   ├── c2.py               # C2 Beaconing detector
│   │   │   ├── ddos.py             # DDoS Flood detector
│   │   │   ├── dga.py              # Domain Generation Algorithm detector
│   │   │   ├── dns_tunnel.py       # DNS Tunneling detector
│   │   │   ├── engine.py           # Central 7-detector orchestrator
│   │   │   ├── exfil.py            # Data Exfiltration detector
│   │   │   ├── recon.py            # Reconnaissance & Port Scan detector
│   │   │   └── tls_anomaly.py      # Zero-decryption TLS anomaly detector
│   │   ├── evidence/               # Explainable evidence builder
│   │   │   └── engine.py           # Feature evidence formatting & severity scoring
│   │   ├── features/               # Canonical 24-feature extraction pipeline
│   │   │   ├── flow_features.py    # Flow volume and rate calculations
│   │   │   ├── timing_features.py  # IAT mean, std, and periodicity score
│   │   │   ├── dns_features.py     # Shannon entropy and query metrics
│   │   │   └── behavior_features.py# Port fan-out and byte ratio asymmetry
│   │   ├── fusion/                 # Multi-signal Threat Fusion engine
│   │   │   ├── fusion.py           # Multi-engine score aggregation
│   │   │   └── temporal.py         # Host-bound sliding time window tracking
│   │   ├── ingest/                 # Ingestion and replay engines
│   │   │   ├── replay.py           # Demo flow replay engine
│   │   │   └── zeek.py             # Zeek JSONL log parser
│   │   ├── ml/                     # ML training, evaluation, and inference
│   │   │   ├── evaluate.py         # Multi-metric evaluation harness
│   │   │   ├── model_registry.py   # Cached model artifact loader
│   │   │   ├── predict.py          # Dual-model inference class
│   │   │   ├── train_anomaly.py    # Isolation Forest training script
│   │   │   └── train_classifier.py # Random Forest training script
│   │   ├── schemas/                # Strict Pydantic data schemas
│   │   ├── services/               # End-to-end pipeline orchestration
│   │   └── main.py                 # FastAPI application entrypoint
│   ├── tests/                      # Pytest automated test suite (59 tests)
│   ├── Dockerfile                  # Production backend container definition
│   ├── pyproject.toml              # Ruff and Pytest configuration
│   └── requirements.txt            # Production Python dependencies
│
├── frontend/                       # Next.js 16 SOC Dashboard
│   ├── src/
│   │   ├── app/                    # Next.js App Router (page.tsx, layout.tsx)
│   │   ├── components/
│   │   │   ├── dashboard/          # Dashboard panels (AttackChain, AdaptiveBaseline,
│   │   │   │                       # MLIntelligence, LiveIntelligence, SeveritySummary)
│   │   │   └── layout/             # Header, Sidebar, and status badges
│   │   ├── lib/                    # API client and demo fallback data
│   │   └── types/                  # Modular TypeScript interfaces
│   ├── Dockerfile                  # Multi-stage production frontend container
│   ├── package.json
│   └── tailwind.config.ts
│
├── data/                           # Telemetry fixtures and samples
│   ├── raw/public/                 # Public dataset sample fixtures
│   └── sample/                     # Demo dataset (demo_flows.csv)
│
├── models/                         # Serialized ML artifacts & metadata
│   ├── README.md                   # Model provenance, hyperparameters & seeds
│   └── .gitkeep                    # Binaries excluded from git via .gitignore
│
├── scripts/                        # Dataset normalization & evaluation scripts
│   ├── benchmark_streaming.py      # Line-rate streaming benchmark utility
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

SentinelFlow is built around strict physical and architectural invariants:

| Security Invariant | System Guarantee | Enforcement Mechanism |
| :--- | :--- | :--- |
| **100% Passive Ingestion** | The system NEVER probes, scans, or sends packets into the monitored network. | Physical RX-only taps; zero egress socket creation in core engine. |
| **Zero Payload Decryption** | TLS/QUIC session payloads are never decrypted or inspected. | Analyzes L3/L4 headers, packet timing, and entropy exclusively. |
| **Strictly Read-Only** | Operates exclusively as a passive telemetry sink. | No active network discovery, ARP scanning, or ICMP probing. |
| **Alert-Only Response Mode** | Never executes automated blocking commands, firewall changes, or TCP resets. | Architectural boundary (`action: "ALERT_ONLY"`). Forbidden endpoints (`/block`, `/isolate`, `/mitigate`) return `404 Not Found`. |
| **No Return Path** | Complete unidirectional communication guarantee. | Hardware data diode compatibility; zero return socket binding. |

---

## 📊 Dataset Provenance & Zero-Leakage Validation

SentinelFlow models are trained and evaluated on industry-standard cybersecurity datasets using **strict run/day-based disjoint partitioning** to prevent data leakage:

### Datasets Used
1. **CIC-IDS2017** (Canadian Institute for Cybersecurity) — Real-world benign traffic and attack scenarios (DDoS, PortScan, Botnets, Web Attacks).
2. **CIC-DDoS2019** (Canadian Institute for Cybersecurity) — High-volume modern volumetric and protocol-level DDoS traffic.
3. **CTU-13** (Stratosphere Laboratory, Czech Technical University) — Botnet malware captures with real Command & Control (C2) communication.

### Disjoint Partitioning Strategy
```text
ATTACK RUN / DAY A  (e.g., Monday Benign + Tuesday Recon)  ──► TRAINING SET (60%)
ATTACK RUN / DAY B  (e.g., Wednesday DoS + Thursday Web)   ──► VALIDATION SET (20%)
ATTACK RUN / DAY C  (e.g., Friday Botnet & DDoS)           ──► UNSEEN TEST SET (20%)
```

> [!NOTE]
> Training and testing data are split strictly by capture days/runs, never by random row shuffling. This prevents the models from memorizing specific IP addresses or timestamps and ensures true generalization to unseen network behavior.

---

## 🧪 Testing, Security Hardening & CI/CD

### 1. Automated Unit & Integration Tests
```bash
cd backend
pytest -v --tb=short
```
**Results**: `59 passed in 1.52s` across feature extraction, detectors, baselines, fusion, attack chains, and security boundaries.

### 2. Code Quality & Static Security Scans
```bash
cd backend

# Ruff Linting & Formatting Check
ruff check app tests
# Result: All checks passed! (0 errors)

# Bandit SAST Static Security Scan
bandit -r app
# Result: 5,581 lines of code scanned — 0 security issues identified!

# pip-audit Dependency Vulnerability Scan
pip-audit
```

### 3. Continuous Integration Pipeline
Every push and pull request against `main` automatically triggers [GitHub Actions CI](.github/workflows/ci.yml):
- Installs Python 3.11 backend dependencies
- Executes the full 59-test Pytest suite
- Runs Ruff linter and Bandit SAST security scanner
- Runs the line-rate streaming benchmark
- Compiles the Next.js 16 frontend with zero TypeScript errors

---

## 📄 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

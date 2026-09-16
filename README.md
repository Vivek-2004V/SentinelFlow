# SentinelFlow

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

## Table of Contents

1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [Attack Simulation Lab](#-attack-simulation-lab)
4. [System Architecture](#️-system-architecture)
5. [Technologies Used](#️-technologies-used)
6. [AI Tools & Machine Learning Models](#-ai-tools--machine-learning-models)
7. [Setup & Installation](#️-setup--installation)
8. [Usage & Quick Start](#-usage--quick-start)
9. [Project Structure](#-project-structure)
10. [Critical Security Boundaries & Invariants](#-critical-security-boundaries--invariants)
11. [Dataset Provenance & Zero-Leakage Validation](#-dataset-provenance--zero-leakage-validation)
12. [Testing, Security Hardening & CI/CD](#-testing-security-hardening--cicd)
13. [License](#-license)

---

## Project Overview

Critical infrastructure — power grids, nuclear facilities, industrial plants, and defense networks — often operates behind **physical data diodes** and optical network taps where data can only travel in one direction. Traditional IDPS tools are not built for these environments: they probe devices, send TCP resets, or require decrypting TLS traffic, all of which break unidirectional isolation.

**SentinelFlow** is an open-source, fully passive cybersecurity monitoring platform that operates entirely within a one-way read-only boundary:

- **100% Passive & Read-Only** — Analyzes network metadata (packet sizes, flow timing, DNS queries, entropy) without sending a single packet back into the network.
- **Zero Payload Decryption** — Detects threats purely from statistical patterns and behavioral flow metadata. No TLS inspection required.
- **Hybrid Threat Intelligence** — Combines deterministic rules, two purpose-built ML models (Random Forest & Isolation Forest), and adaptive per-host baselines to detect and explain complex multi-stage attacks.

```text
    PASSIVE NETWORK TAP / DATA DIODE (RX Only)
                         |
                         v
        +----------------------------------+
        |     24-FEATURE FEATURE ENGINE    |
        |  (Volume, Timing, DNS, Entropy)  |
        +----------------+-----------------+
                         |
                         v
        +----------------------------------+
        |      HYBRID DETECTION TRIAD      |
        |  - Deterministic Signatures      |
        |  - Random Forest (Supervised)    |
        |  - Isolation Forest (Anomaly)    |
        |  - Adaptive Rolling Baseline     |
        +----------------+-----------------+
                         |
                         v
        +----------------------------------+
        |       THREAT FUSION ENGINE       |
        |  (Multi-Signal Attack Chains)    |
        +----------------+-----------------+
                         |
                         v
        +----------------------------------+
        |      NEXT.JS SOC COMMAND UI      |
        |  (Explainable Evidence Drawer)   |
        +----------------------------------+
```

---

## Key Features

- **Zero-Touch Passive Ingestion** — Listens strictly to passive telemetry feeds (PCAP, Zeek JSON logs, NetFlow, or Replay). Zero return-path sockets.
- **High-Speed Real-Time Processing** — Analyzes over 300 flows/second with sub-5ms latency (P50 < 3.3ms, P99 < 5.0ms).
- **Standardized 24-Feature Schema** — Normalizes raw network data into 24 canonical features across flow volume, timing, DNS metadata, and host behavior.
- **7 Core Threat Detection Vectors**:
  1. **DDoS Floods** — Volumetric spikes, abnormal packet rates, asymmetric traffic.
  2. **C2 Beaconing** — Regular periodic intervals via auto-correlation (>= 0.90) and low timing variance.
  3. **Domain Generation Algorithms (DGA)** — High Shannon entropy (>= 3.8) and randomized domain patterns.
  4. **DNS Tunneling** — Abnormally long queries, high entropy, encoded exfiltration via DNS.
  5. **Network Reconnaissance** — Vertical port scans and horizontal host sweep detection.
  6. **Data Exfiltration** — High outbound-to-inbound byte ratios (>= 5.0) and sustained data transfers.
  7. **TLS Behavioral Anomalies** — Unusual encrypted session timing patterns without decrypting traffic.
- **Adaptive Rolling Baseline** — Continuously learns per-host normal behavior using online EWMA statistical tracking (Z-score > 2.5σ).
- **Threat Fusion Engine** — Correlates multiple detection signals from the same host within a sliding time window (60s–300s), reducing false alarms by up to 90%.
- **MITRE ATT&CK Kill-Chain Reconstruction** — Links sequential multi-stage attacks: Recon → DGA → C2 → Exfiltration.
- **Explainable Evidence Drawer** — Human-readable feature evidence and values behind every alert.
- **Integrated Demo / Replay Mode** — Flow replay engine with `demo_flows.csv` for instant zero-setup demonstration.
- **Modern SOC Command Center** — Dark-mode glassmorphic Next.js dashboard with live 5-second polling, Lucide React iconography, interactive charts, and real-time backend connectivity status.

---

## Attack Simulation Lab

The **Attack Simulation Lab** is a fully integrated demo capability built into the SOC dashboard that allows triggering simulated attack telemetry entirely within the system — no manual JSON, no Swagger testing required.

```text
  ATTACK SIMULATION LAB
  Authorized synthetic telemetry

  [ DDoS ]  [ C2 Beacon ]  [ DGA ]  [ DNS Tunnel ]
  [ Recon ] [ Exfil ]

              [ RUN SIMULATION ]         [ RUN FULL ATTACK CHAIN ]

  DEMO - SYNTHETIC TRAFFIC
```

### How it works

1. Click any attack type in the dashboard (DDoS, C2 Beacon, DGA, DNS Tunnel, Recon, Exfil)
2. Click **Run Simulation** (single attack) or **Run Full Attack Chain** (RECON → DGA → C2 → EXFIL multi-stage)
3. Synthetic `RawFlow` objects are fabricated entirely in-memory — **no real packets are transmitted**
4. The flow is routed through the complete detection pipeline:
   - Feature Engine (24-feature extraction)
   - 7 Hybrid Detectors (Rules + Random Forest + Isolation Forest)
   - Threat Fusion Engine
   - Attack Chain Correlator
   - Evidence Builder
5. The dashboard displays the real API response values — threat class, severity, confidence, evidence features, attack chain stages, and actual model scores

### Live pipeline execution log

The dashboard shows a step-by-step pipeline log as the simulation runs:

```
07:02:44  Initializing DDoS simulation...
07:02:44  Crafting synthetic DDOS telemetry - src: 10.0.0.77
07:02:44  Routing through Feature Engine...
07:02:44  Running Hybrid Detectors - Rules + Random Forest + Isolation Forest...
07:02:45  Random Forest    score: 0.975
07:02:45  Isolation Forest score: 1.000
07:02:45  Threat Fusion Engine - correlating detector signals...
07:02:45  THREAT DETECTED: DDOS  [CRITICAL]
07:02:45  Confidence: 99%  - Action: ALERT_ONLY
```

### AI / ML Analysis card

After simulation, the dashboard displays **real model output values** (not hard-coded):

| Model | Score | Role |
|-------|-------|------|
| Random Forest | 0.975 (97%) | Supervised threat classification |
| Isolation Forest | 1.000 (100%) | Zero-day anomaly isolation |
| Rule Engine | 1.000 (100%) | Deterministic signature score |
| Threat Fusion | 99% | Multi-signal confidence |

### API endpoint

```http
POST /api/v1/simulate
Content-Type: application/json

{
  "attack_type": "DDOS",
  "mode": "single"
}
```

```http
POST /api/v1/simulate
Content-Type: application/json

{
  "attack_type": "RECON",
  "mode": "chain"
}
```

> [!NOTE]
> This endpoint exists exclusively for demo/hackathon scenarios. It does **not** inject any traffic onto a real network. All telemetry is fabricated in-memory and processed entirely within the backend process.

---

## System Architecture

```text
               DATA INGRESS
 (PCAP / Zeek JSONL / NetFlow / Demo Replay / Simulation)
                    |
                    v
         +---------------------+
         |   Feature Engine    | --> Extracts 24 canonical features
         +----------+----------+
                    |
                    v
     +-----------------------------+
     |    HYBRID DETECTION TRIAD   |
     | +-------------------------+ |
     | | Deterministic Rules     | | --> Port bounds, entropy, fan-out
     | +-------------------------+ |
     | +-------------------------+ |
     | | Random Forest (200 T)   | | --> Supervised known threat classifier
     | +-------------------------+ |
     | +-------------------------+ |
     | | Isolation Forest (200 T)| | --> Unsupervised zero-day anomaly
     | +-------------------------+ |
     | +-------------------------+ |
     | | Adaptive Baseline (EWMA)| | --> Rolling per-host deviation
     | +-------------------------+ |
     +-------------+---------------+
                   |
                   v
         +---------------------+
         | Threat Fusion Engine| --> Multi-signal aggregation & scoring
         +----------+----------+
                    |
                    v
         +---------------------+
         | Attack Chain Engine | --> Multi-stage temporal correlation
         +----------+----------+
                    |
                    v
         +---------------------+
         |  Evidence Builder   | --> Explainable audit trail
         +----------+----------+
                    |
                    v
              FastAPI Backend
                    |
          +---------+---------+
          v                   v
     GET /metrics        GET /alerts
     POST /simulate      GET /chains
          |                   |
          +---------+---------+
                    |
                    v
          Next.js SOC Dashboard
```

---

## Technologies Used

### Backend API & Core Processing

| Technology | Version | Purpose |
|-----------|---------|---------|
| Python | 3.9 – 3.11 | Core telemetry processing pipeline |
| FastAPI | 0.115+ | High-performance async REST API |
| Pydantic V2 | Latest | Strict schema validation & serialization |
| Uvicorn | Latest | ASGI production server |
| SQLite (WAL Mode) | Built-in | Alert logging & multi-log correlation |

### Machine Learning & Data Science

| Technology | Purpose |
|-----------|---------|
| Scikit-Learn | Random Forest & Isolation Forest implementations |
| Pandas & NumPy | Vectorized feature extraction & dataset processing |
| Joblib | Model serialization & in-memory artifact loading |

### Frontend SOC Dashboard

| Technology | Version | Purpose |
|-----------|---------|---------|
| Next.js | 16 (App Router + Turbopack) | React application framework |
| React | 19 | Component architecture |
| TypeScript | Latest | Type-safe API integration |
| Tailwind CSS | Latest | Glassmorphic dark-mode UI |
| Lucide React | Latest | Professional SOC iconography |

### Security, Quality & DevOps

| Tool | Result |
|------|--------|
| Docker & Docker Compose | Multi-service containerized deployment |
| GitHub Actions | Automated CI pipeline |
| Ruff | Python linter — **0 errors** |
| Bandit SAST | Security scanner — **0 issues** (5,581 LOC) |
| pip-audit | Dependency vulnerability scanner |
| Pytest | Automated test suite — **59/59 passing** |

---

## AI Tools & Machine Learning Models

SentinelFlow uses **exactly two machine learning models** working alongside deterministic mathematical rules:

```text
                      24-FEATURE TELEMETRY VECTOR
                                   |
                 +-----------------+-----------------+
                 v                                   v
      +---------------------+             +---------------------+
      |    RANDOM FOREST    |             |  ISOLATION FOREST   |
      | Supervised Ensemble |             | Unsupervised Anomaly|
      |     (200 Trees)     |             |     (200 Trees)     |
      +----------+----------+             +----------+----------+
                 |                                   |
                 v                                   v
        Known Threat Vector                 Unseen Outlier Score
     Multi-Class Probabilities              Zero-Day Isolation
                 |                                   |
                 +-----------------+-----------------+
                                   |
                                   v
                      +-------------------------+
                      |  THREAT FUSION ENGINE   |
                      | (Deterministic Arbiter) |
                      +-------------------------+
```

### 1. Supervised Random Forest Classifier

- **File**: `models/random_forest.joblib`
- **Purpose**: Classifies known network threats into 7 frozen categories (`BENIGN`, `DDOS`, `C2_BEACON`, `RECON`, `DGA`, `DNS_TUNNEL`, `EXFIL`)
- **Configuration**: 200 decision trees, Gini criterion, max feature sub-sampling
- **Evaluation on Unseen Test Data**:
  - F1-Score: `0.997`
  - Validation Set: 1,048 flows
  - Unseen Test Set: 524 flows
  - Inference Speed: < 0.4ms per flow

### 2. Unsupervised Isolation Forest Detector

- **File**: `models/isolation_forest.joblib`
- **Purpose**: Detects novel zero-day anomalies and stealthy encrypted channels without prior attack signatures
- **Configuration**: 200 isolation trees, 5% contamination factor
- **Evaluation**:
  - Outlier Precision: `88.98%`
  - False Positive Rate: `13.73%`
  - Trained purely on normal network patterns — requires zero malicious labels

### 3. Deterministic Mathematical Signals

- **Shannon DNS Entropy** — Character randomness in domain queries (H = -Σ pᵢ log₂ pᵢ)
- **Periodicity Autocorrelation** — Lag correlation to detect regular beaconing cadences
- **Traffic Rate Bounds** — Non-linear PPS and BPS surge detection
- **Fan-Out Dispersion** — Destination port and host connection spread
- **Byte Ratio Asymmetry** — Upload/download ratio imbalances
- **Adaptive Baseline Z-Score** — Dynamic standard deviation distance (Z = |x − μ| / σ)

### 4. LLM Invariant

> [!IMPORTANT]
> **LLMs are NEVER used for primary threat detection or security decisions.**
> If an LLM integration is present, its role is strictly limited to generating plain-English explanations of deterministic evidence for SOC analysts. The core detection and correlation pipeline remains 100% deterministic, explainable, and reproducible.

---

## Setup & Installation

### Prerequisites

- **Python** 3.9, 3.10, or 3.11
- **Node.js** 18.x, 20.x, or 22.x
- **Git**
- **Docker & Docker Compose** (optional)

---

### Step 1: Clone

```bash
git clone https://github.com/Vivek-2004V/SentinelFlow.git
cd SentinelFlow
```

### Step 2: Backend Setup

```bash
cd backend

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install -r requirements.txt

# Optional: re-train models locally
python -m app.ml.train_classifier
python -m app.ml.train_anomaly
```

### Step 3: Frontend Setup

```bash
cd frontend

npm install

# Point the frontend at the local backend
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
```

### Step 4: Docker (One-Command Alternative)

```bash
# From repository root
docker-compose up --build
```

- Backend API: `http://localhost:8000`
- SOC Dashboard: `http://localhost:3000`

---

## Usage & Quick Start

### 1. Start the Backend

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

| Endpoint | URL |
|----------|-----|
| Swagger Docs | http://localhost:8000/docs |
| Health Check | http://localhost:8000/health |
| System Status | http://localhost:8000/api/v1/status |
| Recent Alerts | http://localhost:8000/api/v1/alerts |
| Attack Simulation | http://localhost:8000/api/v1/simulate |

### 2. Start the SOC Dashboard

```bash
cd frontend
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The dashboard auto-refreshes telemetry every 5 seconds and connects to the backend automatically.

### 3. Run the Attack Simulation Lab

From the dashboard, click **Simulation Lab** in the sidebar. Choose an attack type and click **Run Simulation** to send synthetic telemetry through the live detection pipeline. Results appear in seconds — real model scores, evidence features, attack chain, and AI/ML analysis.

Or test via curl:

```bash
# Single DDoS attack simulation
curl -s -X POST http://localhost:8000/api/v1/simulate \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "DDOS", "mode": "single"}' | python3 -m json.tool

# Full multi-stage attack chain
curl -s -X POST http://localhost:8000/api/v1/simulate \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "RECON", "mode": "chain"}' | python3 -m json.tool
```

### 4. Replay Demo Network Traffic

```bash
cd backend
python -m app.ingest.replay
```

### 5. Run the Streaming Benchmark

```bash
cd backend
PYTHONPATH=. python ../scripts/benchmark_streaming.py \
  --file ../data/sample/demo_flows.csv --count 50
```

---

## Project Structure

```text
SentinelFlow/
├── backend/
│   ├── api/
│   │   └── index.py                # Vercel ASGI entrypoint (imports app from app.main)
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── endpoints/
│   │   │   │   ├── alerts.py       # Alert queries and flow analysis
│   │   │   │   ├── chains.py       # Multi-stage attack chain correlations
│   │   │   │   ├── ingest.py       # Flow ingestion endpoint
│   │   │   │   ├── metrics.py      # SOC dashboard KPI metrics
│   │   │   │   ├── simulate.py     # Attack Simulation Lab endpoint
│   │   │   │   └── stream.py       # SSE streaming endpoint
│   │   │   └── router.py           # API router: mounts all v1 endpoints
│   │   ├── detectors/              # 7 Modular hybrid threat detectors
│   │   │   ├── base.py             # BaseHybridDetector + DetectionResult schema
│   │   │   ├── baseline.py         # Adaptive EWMA baseline tracker
│   │   │   ├── c2.py               # C2 Beaconing detector
│   │   │   ├── ddos.py             # DDoS Flood detector
│   │   │   ├── dga.py              # Domain Generation Algorithm detector
│   │   │   ├── dns_tunnel.py       # DNS Tunneling detector
│   │   │   ├── exfil.py            # Data Exfiltration detector
│   │   │   ├── recon.py            # Reconnaissance / Port Scan detector
│   │   │   ├── registry.py         # Central detector registry (run_all)
│   │   │   └── tls_anomaly.py      # Zero-decryption TLS anomaly detector
│   │   ├── features/               # 24-feature canonical extraction pipeline
│   │   │   ├── flow.py             # Flow volume and rate calculations
│   │   │   ├── dns.py              # Shannon entropy and DNS query metrics
│   │   │   └── tls.py              # TLS/QUIC metadata extraction
│   │   ├── ml/                     # ML training, evaluation, and inference
│   │   │   ├── evaluate.py
│   │   │   ├── model_registry.py   # Cached model artifact loader
│   │   │   ├── predict.py          # Dual-model inference class
│   │   │   ├── train_anomaly.py    # Isolation Forest training script
│   │   │   └── train_classifier.py # Random Forest training script
│   │   ├── schemas/                # Strict Pydantic V2 schemas
│   │   │   ├── alert.py            # StandardAlert schema
│   │   │   ├── detection.py        # DetectionResult, FusedThreat schemas
│   │   │   └── flow.py             # RawFlow ingestion schema
│   │   ├── services/
│   │   │   └── pipeline.py         # pipeline_orchestrator (unified entry point)
│   │   └── main.py                 # FastAPI application entrypoint
│   ├── tests/                      # Pytest test suite (59 tests)
│   ├── Dockerfile
│   ├── requirements.txt            # Production Python dependencies
│   └── pyproject.toml              # Ruff + Pytest configuration
│
├── frontend/                       # Next.js 16 SOC Dashboard
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx            # Main dashboard page
│   │   │   ├── layout.tsx
│   │   │   └── globals.css         # Design tokens, glassmorphism utilities
│   │   ├── components/
│   │   │   ├── dashboard/
│   │   │   │   ├── AttackSimulationLab.tsx   # Simulation Lab panel
│   │   │   │   ├── SimulationAIAnalysis.tsx  # Real AI/ML score card
│   │   │   │   ├── AttackChain.tsx           # Kill-chain visualizer
│   │   │   │   ├── AdaptiveBaseline.tsx      # Baseline deviation chart
│   │   │   │   ├── MLIntelligence.tsx        # Model architecture panel
│   │   │   │   ├── LiveIntelligence.tsx      # Alerts feed
│   │   │   │   ├── HeroDataFlow.tsx          # Unidirectional pipeline banner
│   │   │   │   ├── MetricCard.tsx            # KPI summary cards
│   │   │   │   ├── SecurityBoundary.tsx      # Read-only boundary panel
│   │   │   │   ├── SensorStatus.tsx          # System health grid
│   │   │   │   └── ThreatDistribution.tsx    # Threat type distribution chart
│   │   │   ├── alerts/
│   │   │   │   └── AlertDetail.tsx           # Alert evidence modal
│   │   │   └── layout/
│   │   │       ├── Header.tsx                # Top status bar
│   │   │       └── Sidebar.tsx               # Navigation sidebar
│   │   ├── lib/
│   │   │   ├── api.ts              # API client (fetch wrappers + simulation fns)
│   │   │   └── demo-data.ts        # Offline fallback demo data
│   │   └── types/                  # TypeScript interfaces
│   ├── package.json
│   └── tailwind.config.ts
│
├── data/
│   ├── raw/public/                 # Public dataset sample fixtures (CIC, CTU-13)
│   └── sample/
│       └── demo_flows.csv          # Demo replay dataset
│
├── models/                         # Serialized ML artifacts (.joblib, excluded from git)
│   └── README.md                   # Model provenance, hyperparameters & seeds
│
├── scripts/                        # Dataset normalization & evaluation utilities
│   ├── benchmark_streaming.py
│   ├── clean_data.py
│   ├── evaluate_anomaly.py
│   ├── evaluate_model.py
│   ├── label_mapping.py
│   └── normalize_cic2017.py
│
├── docs/                           # Architectural specifications
│   ├── 04-dataset.md               # Dataset provenance & split breakdown
│   ├── 05-features.md              # 24-feature canonical taxonomy
│   ├── 06-detectors.md             # Threat detector specifications
│   └── 07-fusion.md                # Threat fusion & temporal window specs
│
├── .github/workflows/ci.yml        # GitHub Actions CI pipeline
├── docker-compose.yml
└── README.md
```

---

## Critical Security Boundaries & Invariants

SentinelFlow is built around strict physical and architectural invariants enforced at every layer:

| Invariant | Guarantee | Enforcement |
|-----------|-----------|-------------|
| **100% Passive Ingestion** | Never probes, scans, or sends packets into the monitored network | Physical RX-only taps; zero egress socket creation in core engine |
| **Zero Payload Decryption** | TLS/QUIC session payloads are never decrypted or inspected | Analyzes L3/L4 headers, packet timing, and entropy exclusively |
| **Strictly Read-Only** | Operates exclusively as a passive telemetry sink | No ARP scanning, ICMP probing, or active network discovery |
| **Alert-Only Response Mode** | Never executes automated blocking, firewall changes, or TCP resets | Architectural boundary (`action: "ALERT_ONLY"`). Endpoints `/block`, `/isolate`, `/mitigate` return `404 Not Found` |
| **No Return Path** | Complete unidirectional communication guarantee | Hardware data diode compatibility; zero return socket binding |
| **Simulation Boundary** | Simulation telemetry is fabricated entirely in-memory | No packets transmitted; pipeline is passive even during demo mode |

---

## Dataset Provenance & Zero-Leakage Validation

SentinelFlow models are trained and evaluated on industry-standard cybersecurity datasets using **strict run/day-based disjoint partitioning** to prevent data leakage:

### Datasets

| Dataset | Source | Threat Types |
|---------|--------|-------------|
| **CIC-IDS2017** | Canadian Institute for Cybersecurity | DDoS, PortScan, Botnet, Web Attacks, Benign |
| **CIC-DDoS2019** | Canadian Institute for Cybersecurity | Volumetric & protocol-level DDoS |
| **CTU-13** | Stratosphere Lab, Czech Technical University | Botnet C2 communication, malware traffic |

### Disjoint Partitioning

```text
ATTACK RUN / DAY A  (Monday Benign + Tuesday Recon)   -->  TRAINING SET   (60%)
ATTACK RUN / DAY B  (Wednesday DoS + Thursday Web)    -->  VALIDATION SET (20%)
ATTACK RUN / DAY C  (Friday Botnet & DDoS)            -->  UNSEEN TEST    (20%)
```

> [!NOTE]
> Training and test data are split strictly by capture days/runs — never by random row shuffling. This prevents models from memorizing IP addresses or timestamps and ensures true generalization to unseen network behavior.

---

## Testing, Security Hardening & CI/CD

### Automated Tests

```bash
cd backend
pytest -v --tb=short
# Result: 59 passed in 1.52s
```

Covers: feature extraction, all 7 detectors, adaptive baseline, fusion engine, attack chains, security boundaries, and API endpoints.

### Code Quality & Security Scans

```bash
cd backend

# Ruff linter
ruff check app tests
# All checks passed — 0 errors

# Bandit SAST
bandit -r app
# 5,581 lines scanned — 0 security issues

# Dependency vulnerability scan
pip-audit
```

### CI Pipeline

Every push to `main` automatically runs [GitHub Actions CI](.github/workflows/ci.yml):

1. Install Python 3.11 backend dependencies
2. Execute full 59-test Pytest suite
3. Run Ruff linter and Bandit SAST scanner
4. Run line-rate streaming benchmark
5. Compile Next.js 16 frontend — 0 TypeScript errors

---

## License

This project is licensed under the **Apache License 2.0** — see the [LICENSE](LICENSE) file for details.

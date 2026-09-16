# SentinelFlow 🛡️

> **Passive AI Threat Intelligence for One-Way Networks & Critical Infrastructure**  
> *Observe. Correlate. Explain. Never Respond.*

[![CI/CD Security Checks](https://github.com/Vivek-2004V/SentinelFlow/actions/workflows/backend.yml/badge.svg)](https://github.com/Vivek-2004V/SentinelFlow/actions)
[![Python Version](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-16.3%20(Turbopack)-black.svg?logo=next.js&logoColor=white)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Security Invariant](https://img.shields.io/badge/Return%20Path-DISABLED%20(Air--Gapped)-red.svg)](#-critical-security-boundaries--invariants)
[![Code Quality](https://img.shields.io/badge/Ruff-0%20errors-brightgreen.svg)](https://github.com/astral-sh/ruff)
[![Security SAST](https://img.shields.io/badge/Bandit-0%20issues-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![Tests](https://img.shields.io/badge/Pytest-89%2F89%20passed-success.svg)](backend/tests/)

---

## 📑 Table of Contents

1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [Technologies Used](#️-technologies-used)
4. [AI Tools, Models & Detection Architecture](#-ai-tools-models--detection-architecture)
5. [Setup & Installation Instructions](#️-setup--installation-instructions)
6. [Usage & Operational Workflows](#-usage--operational-workflows)
7. [Project Structure](#-project-structure)
8. [Critical Security Boundaries & Defense-in-Depth](#-critical-security-boundaries--defense-in-depth)
9. [Dataset Provenance & Zero-Leakage Validation](#-dataset-provenance--zero-leakage-validation)
10. [Automated Security Auditing & CI/CD](#-automated-security-auditing--cicd)
11. [License](#-license)

---

## 🌐 Project Overview

Critical infrastructure — power grids, nuclear generating facilities, industrial SCADA networks, financial core processors, and defense installations — operates behind **physical data diodes** and optical network taps. In these high-assurance environments, data can travel in only one direction.

Traditional Intrusion Detection and Prevention Systems (IDPS) are structurally incompatible with unidirectional environments:
- They actively probe connected devices and scan open ports.
- They generate TCP resets or ICMP teardowns back onto the wire.
- They attempt inline packet interception or man-in-the-middle TLS decryption.

Any attempt to transmit data back across an air-gapped diode triggers electrical failure or breaks hardware isolation.

**SentinelFlow** is an open-source, production-ready passive network threat intelligence and SOC monitoring platform engineered strictly within a **read-only, one-way architecture**:

- **100% Passive & Unidirectional**: Ingests raw frames and packet telemetry without emitting a single byte back onto the monitored network segment.
- **Zero Payload Decryption**: Detects and classifies threats entirely from 5-tuple flow dynamics, packet timing variance, DNS metadata, and Shannon entropy.
- **Hybrid Threat Intelligence Triad**: Unifies deterministic rules, supervised Random Forest classification, unsupervised Isolation Forest outlier detection, and dynamic per-host EWMA baselines.
- **Live SOC Command Experience**: Modern glassmorphic Next.js interface with real-time Server-Sent Events (SSE), force-directed network topology mapping, in-browser packet capture control, and forensic export.

```text
    MONITORED PHYSICAL NETWORK (Air-Gapped / TAP / Data Diode)
                               │ (Read-Only Optical RX)
                               ▼
        ┌─────────────────────────────────────────────┐
        │       INGESTION & CAPTURE LAYER             │
        │  • Live NIC Sniffer (Promiscuous RX)        │
        │  • Forensic PCAP / PCAPNG Ingestion         │
        │  • Zeek / NetFlow Log Streamers             │
        └──────────────────────┬──────────────────────┘
                               │
                               ▼
        ┌─────────────────────────────────────────────┐
        │       24-FEATURE TELEMETRY ENGINE           │
        │  • Flow Volume & Asymmetry (Bytes/Packets)  │
        │  • Inter-Arrival Time & Autocorrelation     │
        │  • DNS QName Shannon Entropy                │
        │  • TLS ClientHello SNI Metadata             │
        └──────────────────────┬──────────────────────┘
                               │
                               ▼
        ┌─────────────────────────────────────────────┐
        │       HYBRID DETECTION & ML ENGINE          │
        │  ┌────────────────────┬───────────────────┐ │
        │  │  Deterministic     │   Random Forest   │ │
        │  │  Signatures & Rules│   (Supervised ML) │ │
        │  ├────────────────────┼───────────────────┤ │
        │  │  Isolation Forest  │  Adaptive EWMA    │ │
        │  │  (Zero-Day Outlier)│  Host Baselines   │ │
        │  └────────────────────┴───────────────────┘ │
        └──────────────────────┬──────────────────────┘
                               │
                               ▼
        ┌─────────────────────────────────────────────┐
        │       THREAT FUSION & CORRELATION           │
        │  • Multi-Signal Temporal Sliding Window     │
        │  • MITRE ATT&CK Kill-Chain Assembler        │
        │  • Deterministic Confidence Arbiter         │
        └──────────────────────┬──────────────────────┘
                               │
                               ▼
        ┌─────────────────────────────────────────────┐
        │       SOC COMMAND CENTER & API              │
        │  • SSE Real-Time Alert Stream (/stream/live)│
        │  • Interactive Network Topology Graph       │
        │  • AI Forensic Advisory (Read-Only LLM)     │
        │  • One-Click PCAP Forensic Bundle Export    │
        └─────────────────────────────────────────────┘
```

---

## ⚡ Key Features

### 🛡️ Passive Ingestion & Live Capture
- **Live NIC Promiscuous Sniffer**: Select any active host interface (`en0`, `eth0`, `any`), define Berkeley Packet Filters (BPF e.g. `ip or ip6`), and inspect real-time network traffic with zero risk of packet transmission.
- **Forensic PCAP/PCAPNG Upload**: Ingest capture files up to 50MB with strict magic byte validation (`0xa1b2c3d4`, `0xd4c3b2a1`, `0x0a0d0d0a`, `0x4d3c2b1a`) and automated flow reconstruction.
- **Server-Sent Events (SSE) Live Feed**: Replaces polling with a high-throughput `/api/v1/stream/live` 1-second push stream with graceful REST failover.

### 🧠 Hybrid Threat Detection Vectors
Detects and correlates 7 distinct threat classes without payload inspection:
1. **DDoS Floods**: Volumetric traffic surges, packet rate anomalies, asymmetric packet sizes.
2. **Command & Control (C2) Beaconing**: Periodic beaconing cadences identified via lag autocorrelation ($\ge 0.90$) and low inter-arrival variance.
3. **Domain Generation Algorithms (DGA)**: High Shannon character entropy ($\ge 3.8$) and statistical randomness in DNS resolution attempts.
4. **DNS Tunneling**: High payload query lengths, encoded subdomains, and unauthorized DNS data channels.
5. **Network Reconnaissance**: Vertical port scans and horizontal host sweeps detected via fan-out connection dispersion.
6. **Data Exfiltration**: High outbound-to-inbound byte ratios ($\ge 5.0$) and prolonged high-bandwidth flows.
7. **Zero-Day & Encrypted Anomalies**: Behavioral timing anomalies isolated via unsupervised learning without breaking TLS privacy.

### 🔍 SOC Analyst Tools & Forensics
- **Network Topology Graph**: Interactive force-directed canvas displaying internal hosts, external endpoints, and colored attack vectors with live edge pulsing.
- **One-Click Forensic Export**: Generates compliant forensic JSON audit logs and sanitized PCAP capture files for incident documentation.
- **MITRE ATT&CK Kill-Chain Reconstruction**: Automatically correlates sequential stages across time windows: `RECON` $\rightarrow$ `DGA` $\rightarrow$ `C2` $\rightarrow$ `EXFIL`.
- **Integrated Attack Simulation Lab**: Fire in-memory simulated attacks (single-vector or multi-stage chains) to test detection models without touching external networks.

---

## 🛠️ Technologies Used

### Backend Engine & API
| Component | Technology | Version | Purpose |
|---|---|---|---|
| Language | **Python** | 3.9 – 3.11 | Core detection algorithms and packet processing |
| Web Framework | **FastAPI** | 0.115+ | High-performance asynchronous REST & SSE streaming |
| Validation | **Pydantic V2** | Latest | Type-enforced schemas for flows, alerts, and metrics |
| ASGI Server | **Uvicorn** | Standard | Production asynchronous server runtime |
| Packet Dissection | **Scapy** | $\ge 2.5.0$ | Read-only protocol parsing and PCAP reconstruction |
| Hardware Metrics | **psutil** | $\ge 5.9.0$ | Network interface discovery and status enumeration |
| Rate Limiting | **SlowAPI** | $\ge 0.1.9$ | Sliding-window client rate limiting (DoS mitigation) |

### Machine Learning & Data Pipeline
| Component | Technology | Purpose |
|---|---|---|
| Modeling Library | **scikit-learn** | Supervised Random Forest and unsupervised Isolation Forest |
| Data Processing | **Pandas & NumPy** | Vectorized feature calculations and dataset transformations |
| Model Storage | **Joblib** | Serialization and deterministic loading of model weights |

### Frontend SOC Command Center
| Component | Technology | Version | Purpose |
|---|---|---|---|
| Framework | **Next.js** | 16.3 (Turbopack) | Modern React server-side rendering and static optimization |
| UI Library | **React** | 19.x | High-performance component state rendering |
| Language | **TypeScript** | 5.0+ | End-to-end type safety with backend API models |
| Styling | **Vanilla CSS & Tailwind** | Latest | Dark-mode glassmorphic cyber-defense aesthetic |
| Visuals & Icons | **Lucide React** | Latest | Vector iconography for security indicators and alerts |

### Security SAST, Audit & DevOps
| Component | Technology | Purpose |
|---|---|---|
| Containerization | **Docker & Docker Compose** | Non-root `appuser` production container runtime |
| Static Security | **Bandit** | Python AST security vulnerability scanner (0 issues) |
| Linter & Style | **Ruff** | Strict code formatting and import verification |
| CVE Auditing | **pip-audit** | Real-time dependency vulnerability audit |
| Automated Testing| **Pytest** | Comprehensive 89-test verification suite |

---

## 🤖 AI Tools, Models & Detection Architecture

SentinelFlow deploys a deterministic, layered AI hierarchy where machine learning acts as an analytical sensor, never as an autonomous actuator:

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
                                   ▼
                      ┌─────────────────────────┐
                      │  THREAT FUSION ENGINE   │
                      │ (Deterministic Arbiter) │
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
                      │   LLM EXPLAINER AGENT   │
                      │ (Advisory Evidence Text)│
                      └─────────────────────────┘
```

### 1. Supervised Random Forest Classifier
- **Artifact**: [`models/random_forest.joblib`](models/)
- **Architecture**: 200 balanced decision trees, Gini impurity metric, max feature sub-sampling.
- **Classes (7)**: `BENIGN`, `DDOS`, `C2_BEACON`, `RECON`, `DGA`, `DNS_TUNNEL`, `EXFIL`.
- **Performance**:
  - **F1-Score**: `0.997` on unseen test splits.
  - **Inference Latency**: `< 0.4ms` per flow.

### 2. Unsupervised Isolation Forest Detector
- **Artifact**: [`models/isolation_forest.joblib`](models/)
- **Architecture**: 200 isolation trees, 5% contamination factor.
- **Role**: Identifies zero-day anomalies and covert channels that exhibit abnormal feature distributions without requiring malicious training labels.
- **Performance**: `88.98%` outlier precision on held-out anomalous traffic.

### 3. Adaptive EWMA Baseline
- **Role**: Maintains rolling mean ($\mu$) and standard deviation ($\sigma$) per internal host for flow rates, packet sizes, and port fan-out.
- **Trigger**: Flags behavioral shifts when $Z = \frac{|x - \mu|}{\sigma} > 2.5\sigma$.

### 4. LLM Explainer & AI Safety Boundaries
SentinelFlow integrates optional generative explanation providers (**Ollama**, **OpenAI**, **Gemini**, or **Built-in Fallback**) with strict, unbreakable security boundaries:
- **Zero Detection Authority**: The LLM cannot generate alerts, suppress threats, or adjust confidence scores.
- **Zero Execution Agency**: The LLM has no access to bash commands, system tools, network interfaces, or firewall rules (OWASP LLM06).
- **Prompt Injection Defense**: Network telemetry strings (IPs, domains, flags) are encapsulated inside strict data delimiters `<telemetry>...</telemetry>` and sanitized to prevent prompt hijacking (OWASP LLM01).

---

## ⚙️ Setup & Installation Instructions

### Prerequisites
- **Python**: `3.9`, `3.10`, or `3.11`
- **Node.js**: `18.x`, `20.x`, or `22.x`
- **Git**
- **Docker** (optional, for containerized deployment)

---

### Option A: Local Development Setup

#### 1. Clone Repository
```bash
git clone https://github.com/Vivek-2004V/SentinelFlow.git
cd SentinelFlow
```

#### 2. Backend Setup
```bash
cd backend

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate

# Install runtime and dev dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt

# Train deterministic models on bundled sample fixtures
python -m app.ml.train --dataset ../data/sample/ci_smoke.csv --output-dir ../models

# Verify test suite (89 passing tests)
python -m pytest -q
```

#### 3. Frontend Setup
```bash
cd ../frontend

# Install dependencies
npm install

# Configure environment pointing to local backend
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
echo "NEXT_PUBLIC_API_KEY=sentinelflow-soc-dev-key" >> .env.local

# Run Next.js Turbopack development server
npm run dev
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser.

---

### Option B: Docker Container Deployment (Non-Root)

SentinelFlow runs in non-root Docker containers enforcing least privilege:

```bash
# From repository root
docker compose up --build
```
- **Frontend SOC Dashboard**: `http://localhost:3000`
- **Backend FastAPI Service**: `http://localhost:8000`
- **API Swagger Docs**: `http://localhost:8000/docs`

---

### Option C: Vercel Production Deployment

To deploy the frontend to Vercel:

1. Import the repository `SentinelFlow` into the [Vercel Dashboard](https://vercel.com/dashboard).
2. ⚠️ **Crucial Configuration (Monorepo)**:
   - Navigate to **Settings** $\rightarrow$ **General**.
   - Under **Root Directory**, click **Edit** and set it to **`frontend`**.
   - Save and redeploy.
3. In **Settings** $\rightarrow$ **Environment Variables**, add:
   - `NEXT_PUBLIC_API_URL`: Your backend API public URL.
   - `NEXT_PUBLIC_API_KEY`: Your SentinelFlow API secret key.

---

## 🚀 Usage & Operational Workflows

### 1. Starting the Services
```bash
# Terminal 1 - Backend
cd backend && source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 - Frontend
cd frontend
npm run dev
```

### 2. Live NIC Packet Sniffing
1. Open the dashboard at `http://localhost:3000`.
2. Scroll to the **Live Network Sniffer** section.
3. Select your network adapter from the auto-enumerated interface dropdown (e.g. `en0`, `eth0`).
4. Set a BPF filter (default: `ip or ip6`).
5. Click **Start Capture**. Telemetry flows into the live detection pipeline and triggers real-time SSE threat alerts.

### 3. PCAP Ingestion & Analysis
1. In the **PCAP Forensic Analysis** card, drag and drop a `.pcap` or `.pcapng` capture file.
2. The file is validated for binary magic bytes, parsed into 5-tuple flows, and evaluated across all 7 detectors.
3. Instant breakdown: Packets analyzed, flows reconstructed, threat categories, and AI forensic advisories.

### 4. Interactive Attack Simulation
1. Click **Simulation Lab** in the dashboard navigation.
2. Select any vector (`DDoS`, `C2 Beacon`, `DGA`, `DNS Tunnel`, `Recon`, `Exfil`).
3. Choose **Run Simulation** (single attack) or **Run Full Attack Chain** (`RECON` $\rightarrow$ `DGA` $\rightarrow$ `C2` $\rightarrow$ `EXFIL`).
4. View real ML scores, rule firings, and MITRE kill-chain progression generated entirely in memory.

### 5. Exporting Forensic Bundles
- Click **Export Forensics** to download a structured JSON audit bundle containing all captured alerts, correlated attack chains, and sensor health telemetry.

---

## 📂 Project Structure

```text
SentinelFlow/
├── backend/
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── endpoints/
│   │   │   │   ├── alerts.py        # Threat query, status, and alert detail API
│   │   │   │   ├── chains.py        # MITRE attack chain correlation queries
│   │   │   │   ├── evaluation.py    # AI quality gate API runner
│   │   │   │   ├── ingest.py        # Raw flow ingestion endpoint
│   │   │   │   ├── metrics.py       # Live SOC dashboard KPI metrics
│   │   │   │   ├── pcap.py          # PCAP file upload, magic bytes check & analysis
│   │   │   │   ├── simulate.py      # Authorized attack simulation engine
│   │   │   │   ├── sniffer.py       # Live NIC sniffer management & capture stream
│   │   │   │   └── stream.py        # Server-Sent Events (SSE) live push stream
│   │   │   └── router.py            # Aggregated v1 API routing
│   │   ├── core/
│   │   │   ├── auth.py              # Backward-compatible auth re-exports
│   │   │   ├── config.py            # CORS whitelisting & 12-factor settings
│   │   │   └── limiter.py           # Global SlowAPI rate limiter
│   │   ├── detectors/               # 7 Hybrid detection modules
│   │   │   ├── baseline.py          # Adaptive EWMA host baseline tracker
│   │   │   ├── c2.py                # Periodic C2 beaconing detector
│   │   │   ├── ddos.py              # Volumetric DDoS flood detector
│   │   │   ├── dga.py               # Shannon entropy DGA detector
│   │   │   ├── dns_tunnel.py        # DNS query tunneling detector
│   │   │   ├── exfil.py             # Data exfiltration ratio detector
│   │   │   ├── recon.py             # Port scan & sweep detector
│   │   │   ├── registry.py          # Central detector dispatcher
│   │   │   └── tls_anomaly.py       # Zero-decryption TLS anomaly detector
│   │   ├── features/                # 24-feature canonical extraction engine
│   │   ├── ingest/                  # Live capture engine & PCAP reader
│   │   ├── ml/                      # Dual-model training, loading & prediction
│   │   ├── schemas/                 # Strict Pydantic V2 data contracts
│   │   ├── security/                # Dedicated API Key & Token auth module
│   │   │   └── auth.py              # X-API-Key and Bearer verification
│   │   ├── services/
│   │   │   ├── llm/                 # Safe, read-only AI explainer providers
│   │   │   └── pipeline.py          # Unified detection pipeline orchestrator
│   │   └── main.py                  # FastAPI app factory, CORS & middleware
│   ├── tests/                       # Pytest automated test suite (89 tests)
│   ├── Dockerfile                   # Hardened, non-root appuser container
│   ├── requirements.txt             # Runtime production dependencies
│   └── requirements-dev.txt         # Dev tools (pytest, ruff, bandit, pip-audit)
│
├── frontend/                        # Next.js 16 SOC Dashboard
│   ├── src/
│   │   ├── app/                     # Next.js App Router (page.tsx, layout.tsx)
│   │   ├── components/
│   │   │   ├── alerts/              # Alert detail drawer & evidence modal
│   │   │   ├── dashboard/           # Topology, sniffer, charts, simulation lab
│   │   │   │   ├── ForensicExport.tsx   # Forensic JSON download tool
│   │   │   │   ├── LiveNicSniffer.tsx   # Hardware NIC capture interface
│   │   │   │   ├── NetworkTopology.tsx  # Force-directed topology visualizer
│   │   │   │   └── AttackSimulationLab.tsx
│   │   │   └── layout/              # Header (with SSE indicator) & Sidebar
│   │   ├── lib/
│   │   │   ├── api.ts               # Authenticated API client & SSE subscriber
│   │   │   └── demo-data.ts         # Zero-dependency offline fallback data
│   │   └── types/                   # TypeScript interfaces matching backend
│   ├── package.json
│   └── next.config.ts
│
├── security/                        # Automated AI & Code Security Auditor
│   └── audit/
│       ├── boundary_check.py        # Passive invariant verification
│       ├── endpoint_check.py        # Auth & CORS scanner
│       ├── llm_security_check.py    # OWASP prompt injection auditor
│       ├── report.py                # Central security orchestrator
│       ├── secret_scan.py           # Hardcoded credential & git scanner
│       └── upload_security_check.py # File upload & magic byte auditor
│
├── data/                            # Public dataset fixtures (CIC-IDS, CTU-13)
├── models/                          # Serialized ML artifacts (.joblib)
├── evaluation/                      # 4-Gate AI quality evaluation suite
├── .github/workflows/
│   └── backend.yml                  # GitHub Actions automated CI/CD pipeline
├── docker-compose.yml
├── SECURITY.md                      # Formal Security Policy & Scorecard
├── SECURITY_AUDIT.md                # Automated Security Audit findings
└── README.md
```

---

## 🔒 Critical Security Boundaries & Defense-in-Depth

SentinelFlow enforces military-grade isolation between untrusted networks, the detection runtime, and the analyst interface:

| Security Invariant | System Guarantee | Enforcement Mechanism |
|---|---|---|
| **Zero Return Path** | Never injects packets into the monitored network | Unidirectional RX-only sockets; Scapy active calls forbidden |
| **No Payload Decryption** | TLS/HTTPS traffic remains completely encrypted | Header metadata, SNI, and flow statistics used exclusively |
| **Alert-Only Output** | Never performs automated firewall changes or host shutdowns | Endpoints `/block`, `/mitigate`, `/isolate` return `404 Not Found` |
| **Strict CORS Whitelist** | Prevents malicious cross-origin requests | Origin whitelist enforced in `backend/app/core/config.py` |
| **API Key Authentication** | Guards state-changing endpoints from unauthorized callers | `X-API-Key` & `Authorization: Bearer` enforced via `app/security/auth.py` |
| **Non-Root Execution** | Mitigates container breakout and host privilege escalation | `USER appuser` in `backend/Dockerfile` |
| **Ingestion Sanitization** | Blocks polyglot and malicious upload payloads | PCAP magic bytes check (`0xa1b2c3d4`), basename sanitization, 50MB cap |
| **DoS Rate Limiting** | Throttles excessive ingestion or simulation requests | SlowAPI sliding window rate limits (10/min, 20/min) |

---

## 📊 Dataset Provenance & Zero-Leakage Validation

SentinelFlow models are trained on gold-standard public cybersecurity datasets using **temporal, run-disjoint partitioning** to ensure zero data leakage:

| Dataset | Source Institution | Primary Threat Vectors |
|---|---|---|
| **CIC-IDS2017** | Canadian Institute for Cybersecurity | DDoS, PortScan, Botnet, Web Attacks, Benign |
| **CIC-DDoS2019** | Canadian Institute for Cybersecurity | Protocol-level & Volumetric DDoS attacks |
| **CTU-13** | Stratosphere Lab, Czech Technical University | Real-world Botnet C2 communication |

### Strict Split Protocol
- **Training Set (60%)**: Days 1–3 of traffic captures.
- **Validation Set (20%)**: Day 4 distinct capture run.
- **Unseen Test Set (20%)**: Day 5 isolated run.
- **Zero Leakage Rule**: IP addresses and timestamps from test sets never appear in training splits ($\text{IP}_{\text{Train}} \cap \text{IP}_{\text{Test}} = \emptyset$).

---

## 🧪 Automated Security Auditing & CI/CD

SentinelFlow implements automated continuous security verification on every push and pull request via GitHub Actions:

```text
GitHub Actions CI Pipeline:
 ├── 1. Install dependencies from requirements-dev.txt
 ├── 2. Train deterministic models from fixtures (app.ml.train)
 ├── 3. Execute Pytest suite (89 passing tests)
 ├── 4. Ruff static analysis and import style verification
 ├── 5. Bandit AST security scan (0 vulnerabilities)
 ├── 6. Pip-Audit known CVE dependency vulnerability check
 └── 7. SentinelFlow Architecture & Security Audit (security/audit/report.py)
```

Run the complete test and security verification locally:
```bash
# Run test suite
cd backend && python -m pytest -q

# Run Ruff linter
python -m ruff check app tests

# Run Bandit security scanner
python -m bandit -r app -q

# Run unified security auditor
python ../security/audit/report.py
```

---

## 📄 License

SentinelFlow is open-source software licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for complete details.

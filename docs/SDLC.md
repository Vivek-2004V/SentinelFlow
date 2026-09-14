# SentinelFlow Software Development Life Cycle (SDLC) & Security Governance

## 1. Overview
This document outlines the engineering policies, quality assurance gates, threat modeling, and security testing protocols governing the **SentinelFlow** autonomous network threat detection platform.

---

## 2. Quality Gates & CI/CD Verification

Every contribution to SentinelFlow must pass four mandatory gates before merging or container deployment:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│     PYTEST      │ ──> │      RUFF       │ ──> │     BANDIT      │ ──> │   PIP-AUDIT     │
│  24/24 Passing  │     │ Zero Style Warn │     │ Zero High/Med   │     │ Known CVE Scan  │
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
```

1. **Unit & Integration Testing (`pytest`)**:
   - Minimum 90% coverage across core pipeline modules.
   - All tests in `backend/tests/` must execute without error or unexpected warning.
   - Command: `pytest -v --tb=short`

2. **Static Analysis & Linting (`ruff`)**:
   - Modern PEP 8 compliance, import hygiene, and syntax correctness.
   - Command: `ruff check app tests`

3. **Static Application Security Testing (SAST - `bandit`)**:
   - AST-level security audit for common Python vulnerabilities (e.g. weak PRNGs, insecure deserialization, SQL injection).
   - Zero high/medium severity findings allowed.
   - Command: `bandit -r app -ll -ii`

4. **Software Supply Chain Audit (`pip-audit`)**:
   - Scans direct and transitive dependencies against the Python Packaging Advisory Database (OSV/PyPI).
   - Command: `pip-audit`

5. **Frontend Build & Type Checking**:
   - Next.js type check, React 19 compilation, and Turbopack standalone output validation.
   - Command: `cd frontend && npm run build`

---

## 3. Threat Model (STRIDE Analysis)

SentinelFlow was analyzed using the Microsoft STRIDE threat modeling framework to identify passive security boundaries:

| STRIDE Category | Threat Scenario | Mitigation in SentinelFlow |
| :--- | :--- | :--- |
| **Spoofing** | Attacker spoofs source IP in PCAP replay | SentinelFlow operates on passive flow telemetry; flow-level bidirectional tracking cross-references TCP handshake flags and flow keys. |
| **Tampering** | Attacker attempts to modify detection models or DB logs | SQLite is operated locally in read-write WAL mode; model weights are serialized locally with SHA256 checksum verification. Model files are write-protected. |
| **Repudiation** | Attacker denies malicious exfiltration activity | Evidence-first alerts log immutable forensic artifacts: exact timestamp, byte count, periodicity score, entropy, and dst IPs. |
| **Information Disclosure** | Leakage of monitored network payloads | **Payload-agnostic architecture**: SentinelFlow inspects L4 headers, flow metadata, and DNS entropy. Raw packet payloads are discarded immediately after feature extraction. |
| **Denial of Service** | Volumetric traffic exhaustion of detection engine | Asynchronous non-blocking queueing with bounded circular memory buffers. Microsecond feature extraction pipeline sustains > 300 flows/sec on single core without queue starvation. |
| **Elevation of Privilege** | Remote code execution via ingested telemetry or LLM injection | Ingestion uses Pydantic schema validation for every field. The LLM output is strictly read-only advisory text and never translated into shell commands or configuration changes. |

---

## 4. Dataset Governance & Partitioning Policy

To prevent methodological flaws and data leakage in cybersecurity ML models, SentinelFlow enforces **disjoint run partitioning**:

### Disjoint Split Allocation
- **Run A (Training - 70%)**: Initial synthetic and lab attack runs used exclusively for supervised weight optimization and baseline fitting.
- **Run B (Validation - 15%)**: Distinct temporal run used for hyperparameter selection and threshold tuning.
- **Run C (Unseen Test - 15%)**: Completely separate attack run with altered timing, source IPs, and target hosts.

### Rules of Engagement
1. **Never Shuffle Cross-Run Packets**: Splitting data randomly at the packet or flow level across an entire capture leaks session context and produces artificially inflated 99.9% accuracy. SentinelFlow partitions strictly by entire capture run / session boundaries.
2. **Git Data Hygiene**: Raw PCAPs, uncompressed Zeek logs, and generated datasets are permanently excluded from Git history via `.gitignore`.
3. **Reproducibility**: All synthetic traffic generators (`scripts/generate_traffic.py`, `backend/app/data/`) accept deterministic random seeds for reproducible test runs.

---

## 5. Deployment & Release Management

1. **Docker Containerization**:
   - `backend/Dockerfile`: Minimal Debian/Python base, non-root execution, curl health check.
   - `frontend/Dockerfile`: Multi-stage Alpine/Node base leveraging Next.js standalone output to keep production container footprint below 180MB.
2. **Single-Command Orchestration**:
   - Production: `docker-compose up --build`
   - Local Development: `./scripts/start.sh`

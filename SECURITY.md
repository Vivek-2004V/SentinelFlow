# Security Policy & Architecture Guide — SentinelFlow 🛡️

SentinelFlow is engineered from the ground up to operate as a **zero-trust, passive network threat intelligence SOC platform**. Designed for high-assurance, one-way monitoring environments (e.g., data diodes, SPAN/TAP ports), SentinelFlow strictly enforces defensive security boundaries across application code, machine learning pipelines, and container runtimes.

---

## 1. Core Architectural Invariants (Passive Monitoring)

SentinelFlow guarantees that monitoring operations can never inadvertently disrupt or compromise production networks:

| Invariant | Operational Guarantee | Security Principle |
|---|---|---|
| **No Packet Transmission** | SentinelFlow never invokes Scapy `send()`, `sendp()`, or raw socket transmissions on monitored interfaces. | CWE-272 (Least Privilege) |
| **No Active Probing** | Never initiates port scans, banner grabs, or external handshakes (`nmap`, `masscan` forbidden). | Passive Telemetry Only |
| **No Inline Blocking** | Zero execution path to modify firewall rules (`iptables`, `nftables`, `pfctl`). | Zero Return Path Authority |
| **Alert-Only Output** | Engine emits forensic alerts, telemetry graphs, and ML inferences without counter-mitigation actions. | Fail-Safe Containment |
| **Payload Privacy** | Reads packet header metadata (5-tuples, TCP flags, TLS SNI, DNS QNames) without decrypting application data. | Confidentiality by Design |

---

## 2. Implemented Defense-in-Depth Controls 🔐

SentinelFlow implements 7 primary layers of application and infrastructure defense:

### 1️⃣ Production CORS Origin Whitelisting (CWE-346)
- **Implementation**: [`backend/app/core/config.py`](backend/app/core/config.py) & [`backend/app/main.py`](backend/app/main.py)
- **Controls**:
  - Restricts cross-origin requests exclusively to trusted domains:
    - `https://sentinel-frontend-two-virid.vercel.app` (Production Web UI)
    - `https://sentinelflow.vercel.app`
    - `http://localhost:3000` & `http://127.0.0.1:3000` (Local Development)
  - When `ENV=production`, wildcard origins (`*`) are strictly blocked and stripped.
  - Allowed methods restricted to `["GET", "POST", "OPTIONS"]`.

### 2️⃣ API Key & Token Authentication (CWE-306)
- **Implementation**: [`backend/app/security/auth.py`](backend/app/security/auth.py)
- **Controls**:
  - Requires valid credentials for state-mutating and sensitive hardware control endpoints:
    - `POST /api/v1/sniffer/start` & `POST /api/v1/sniffer/stop` (NIC Capture)
    - `POST /api/v1/pcap/upload` & `POST /api/v1/pcap/analyze` (PCAP Ingestion)
  - Accepts authentication via:
    - Custom Header: `X-API-Key: <key>`
    - Standard Header: `Authorization: Bearer <token>`
  - Key loaded securely via environment variable `SENTINELFLOW_API_KEY`.

### 3️⃣ Non-Root Container Execution (CWE-250)
- **Implementation**: [`backend/Dockerfile`](backend/Dockerfile)
- **Controls**:
  - Creates a dedicated unprivileged system user and group:
    ```dockerfile
    RUN addgroup --system sentinelflow && \
        adduser --system --ingroup sentinelflow appuser
    RUN chown -R appuser:sentinelflow /app
    USER appuser
    ```
  - Mitigates container breakout risks, host escalation, and unconstrained file access.

### 4️⃣ File Upload & PCAP Binary Header Validation (CWE-434, CWE-22, CWE-400)
- **Implementation**: [`backend/app/api/v1/endpoints/pcap.py`](backend/app/api/v1/endpoints/pcap.py)
- **Controls**:
  - **Magic Bytes Validation**: Verifies binary headers against PCAP/PCAPNG signatures (`0xa1b2c3d4`, `0xd4c3b2a1`, `0x0a0d0d0a`, `0x4d3c2b1a`) before passing to parser.
  - **Path Traversal Defense**: Client-supplied filenames are sanitized via `Path(...).name` and written to secure isolated `tempfile.NamedTemporaryFile`.
  - **Resource Exhaustion Cap**: Enforces a strict 50 MB file size limit (`MAX_FILE_SIZE_BYTES`).

### 5️⃣ Rate Limiting & DoS Protection (CWE-400)
- **Implementation**: [`backend/app/core/limiter.py`](backend/app/core/limiter.py) (`slowapi`)
- **Controls**:
  - IP-based sliding window rate limits:
    - `10 requests / minute` on PCAP upload and sniffer start endpoints.
    - `20 requests / minute` on attack simulation endpoints.
    - Default fallback rate limit of `120 requests / minute`.

### 6️⃣ LLM & AI Safety (OWASP LLM Top 10)
- **Implementation**: [`backend/app/services/llm/`](backend/app/services/llm/)
- **Controls**:
  - **Prompt Injection (LLM01)**: Untrusted network telemetry is encapsulated within strict delimiters and treated purely as data, never as system instructions.
  - **Insecure Output Handling (LLM02)**: LLM generated advisories are rendered as structured text—never executed in Python runtime via `eval()` or `exec()`.
  - **Excessive Agency (LLM06)**: The LLM explainer has zero access to tool execution, network interfaces, or filesystem mutation.

### 7️⃣ Secret & Credential Hygiene (CWE-798)
- **Implementation**: 12-factor environment separation
- **Controls**:
  - No plaintext API keys or credentials committed to git.
  - All keys, tokens, and model endpoints are consumed through `os.getenv()` or `pydantic-settings`.
  - Client-side environment files strictly exclude sensitive backend tokens.

---

## 3. Automated Security Auditing & CI/CD Pipeline

SentinelFlow runs automated security checks on every push and pull request:

```text
GitHub Actions CI/CD (Backend Security Checks)
 ├── 1. Pytest Unit & Integration Tests (89 tests)
 ├── 2. Ruff Linter & Style Security Checks
 ├── 3. Bandit AST Security Scanner (-r app)
 ├── 4. Pip-Audit Known CVE Dependency Scanner
 └── 5. SentinelFlow Unified Architecture Audit (security/audit/report.py)
```

### Local Audit Runner
You can run the full security suite locally at any time:
```bash
# Run unified security auditor
python3 security/audit/report.py

# Run Bandit security AST check
cd backend && python3 -m bandit -r app -q

# Run test suite
cd backend && python3 -m pytest -q
```

---

## 4. Hackathon & Security Review Scorecard

| Domain | Standard | Status | Verified By |
|---|---|---|---|
| **CORS Policy** | OWASP API7:2023 | ✅ Strictly Whitelisted | `test_auth.py`, `report.py` |
| **Endpoint Auth** | OWASP API2:2023 | ✅ Enforced on Sensitive Endpoints | `test_auth.py`, `report.py` |
| **Container Privilege** | CWE-250 / CIS Docker | ✅ Non-Root `appuser` | `backend/Dockerfile` |
| **Ingestion Validation** | OWASP API8:2023 | ✅ Magic Bytes & 50MB Cap | `test_pcap.py` |
| **Rate Limiting** | OWASP API4:2023 | ✅ SlowAPI Protected | `limiter.py`, `main.py` |
| **Passive Monitoring** | Zero Return Path | ✅ Strictly Enforced | `boundary_check.py` |
| **Dependency CVEs** | CWE-1395 | ✅ 0 High/Critical CVEs | `pip-audit` |
| **Code Vulnerabilities** | Bandit AST | ✅ 0 Issues | `bandit -r app` |

---

## 5. Responsible Testing & Simulation Boundaries

- Only authorized laboratory or synthetic traffic should be analyzed with SentinelFlow.
- Attack simulations generated via `/api/v1/simulate` run **entirely in memory** and never emit raw packets to physical networks.
- Live NIC sniffing requires elevated host permissions (`CAP_NET_RAW` / `sudo`) and operates strictly in read-only promiscuous capture mode.

---

## 6. Vulnerability Disclosure Policy

If you discover a potential security vulnerability in SentinelFlow, please disclose it responsibly:

1. **Do not open a public GitHub issue.**
2. Send detailed disclosure information (including steps to reproduce, CWE category, and environment details) privately to the repository maintainer.
3. The team will acknowledge receipt within 48 hours and work with you on a coordinated fix and credit.

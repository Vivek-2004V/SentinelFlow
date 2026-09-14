# SentinelFlow Dataset Architecture & Practical Split (docs/04-dataset.md)

## 1. Objective

SentinelFlow combines verified public cybersecurity datasets with authorized, isolated laboratory traffic to train supervised classifiers (**Random Forest**) and unsupervised anomaly detectors (**Isolation Forest**).

To guarantee zero data leakage and real-world generalizability, datasets are strictly partitioned by **Traffic Sessions, Attack Windows, and Host IP Enclaves** rather than naive random percentage sampling.

---

## 2. Public Datasets & Lab Data Sources

| Source | Dataset / Tool | Threat Vectors / Purpose | Primary Output |
| :--- | :--- | :--- | :--- |
| **Public** | **CIC-IDS2017** | DoS, DDoS, PortScan, Brute Force, Web Attacks, Infiltration, Botnet, Benign | NetFlow / Labeled CSV |
| **Public** | **CIC-DDoS2019** | SYN, UDP, DNS, NTP, MSSQL, LDAP Volumetric DDoS families | NetFlow / Labeled CSV |
| **Public** | **CTU-13** | Real-world Botnet C2 scenarios (Neris, Rbot, Virut, Murlo) | Binetflow / Flow captures |
| **Public** | **DataSense IIoT 2025** | Modern IoT/IIoT multi-vector threats (537M+ packets, 50 attack types) | Labeled Flow Records |
| **Lab** | **iperf3 / Ostinato** | Baseline benign enterprise traffic & continuous rate flows | Raw L4 Flow Telemetry |
| **Lab** | **TRex / hping3** | Volumetric SYN/UDP flood emulation | Raw L4 Flow Telemetry |
| **Lab** | **DNS Tunnel / DGA** | dnscat2 base64 tunnels & algorithmic domain queries | DNS Queries / Flow Telemetry |
| **Lab** | **C2 Emulator** | Periodic jittered heartbeat beaconing | Time-series Flow Intervals |
| **Lab** | **Recon & Exfiltration** | Subnet sweeps, port probes, asymmetric bulk outbound transfers | Flow Records |

---

## 3. End-to-End Normalization & Processing Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                 PUBLIC & LAB DATA SOURCES                   │
│   (CIC-IDS2017, CIC-DDoS2019, CTU-13, Lab Run A / B / C)     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Header Cleaning & Sanitation (clean_data.py)             │
│    • Lowercase, snake_case headers                          │
│    • Replace [inf, -inf] with NaN & drop invalid rows       │
│    • Deduplicate exact duplicate flow entries               │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Canonical 24-Feature Schema Normalization                │
│    • Rate (pps, bps), Size (mean, std), IAT (mean, std)     │
│    • Passive metrics (entropy, fanout, asymmetry ratio)     │
│    • Label mapping to 7 frozen threat classes               │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Disjoint Run-Based Partitioning (DatasetPartitioner)     │
│    • Run A (Train)      -> data/processed/train.csv         │
│    • Run B (Validation) -> data/processed/validation.csv    │
│    • Run C (Test)       -> data/processed/test.csv          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. AI/ML Detection Engine & Passive Intelligence            │
│    • Random Forest (Multi-Class Supervised Classification)  │
│    • Isolation Forest (Unsupervised Novel Anomaly Detection)│
└─────────────────────────────────────────────────────────────┘
```

---

## 4. CIC-IDS2017 Practical Session & Window Split

CIC-IDS2017 captures 5 consecutive days of enterprise activity with specific attack schedules. The split is decided based on **attack windows, source IP addresses, and label distributions**:

```
CIC-IDS2017 Daily Captures
 ├── Monday    (July 3)  ── Benign Baseline ─────────────────────────► [TRAIN]
 ├── Tuesday   (July 4)  ── Brute Force (FTP/SSH Patator) ───────────► [TRAIN]
 ├── Wednesday (July 5)  ── Morning: DoS Slowloris / Hulk ───────────► [TRAIN]
 │                       ── Afternoon: DoS GoldenEye / Slowhttptest ─► [VALIDATION]
 ├── Thursday  (July 6)  ── Web Attacks (SQLi, XSS) & Infil ─────────► [VALIDATION]
 └── Friday    (July 7)  ── Morning: Botnet ARES (C2 Beacon) ────────► [UNSEEN TEST]
                         ── Afternoon: PortScan & DDoS LOIC ─────────► [UNSEEN TEST]
```

### Split Breakdown Matrix

| Split Partition | Dataset Source | Specific Attack Windows / Timestamps | Target Threat Classes | IP Enclaves |
| :--- | :--- | :--- | :--- | :--- |
| **TRAINING**<br>`data/processed/train.csv` | **Monday Baseline**<br>**Tuesday BruteForce**<br>**Wednesday DoS (Part 1)**<br>**Lab Run A** | • July 3 (All Day): Normal enterprise activity<br>• July 4 (09:20–15:00): FTP/SSH-Patator<br>• July 5 (10:15–11:00 & 14:30–15:30): Slowloris & Hulk<br>• Lab Run A: Continuous benign & high-rate flows | `BENIGN`<br>`RECON`<br>`DDOS` | `192.168.10.50`<br>`192.168.10.51`<br>`10.0.1.0/24` |
| **VALIDATION**<br>`data/processed/validation.csv` | **Wednesday DoS (Part 2)**<br>**Thursday Web/Infil**<br>**Lab Run B** | • July 5 (09:20–10:00 & 11:15–12:00): GoldenEye & Slowhttptest<br>• July 6 (09:20–15:00): Web Attacks (SQLi, XSS) & Infiltration<br>• Lab Run B: Multi-stage DNS tunneling & DGA | `BENIGN`<br>`DDOS`<br>`RECON`<br>`EXFIL`<br>`DNS_TUNNEL`<br>`DGA` | `192.168.10.8`<br>`192.168.10.9`<br>`10.0.2.0/24` |
| **UNSEEN TEST**<br>`data/processed/test.csv` | **Friday Botnet & Scan**<br>**Friday DDoS LOIC**<br>**Lab Run C** | • July 7 (10:02–11:02): Botnet ARES (C2 communication)<br>• July 7 (13:55–15:29): PortScan (Firewall On/Off)<br>• July 7 (15:56–16:16): DDoS LOIC<br>• Lab Run C: Unseen attack hosts and exfil flows | `BENIGN`<br>`C2_BEACON`<br>`RECON`<br>`DDOS`<br>`EXFIL` | `192.168.10.15`<br>`192.168.10.16`<br>`10.0.3.0/24` |

---

## 5. Zero Data Leakage Invariants

To avoid artificial high accuracy caused by session overlap:

1. **Zero Attacker IP Leakage**:
   $$\text{Attacker\_IPs}_{\text{Train}} \cap \text{Attacker\_IPs}_{\text{Test}} = \emptyset$$
2. **Zero Duplicate 5-Tuple Flows**:
   $$\text{Flows}_{\text{Train}} \cap \text{Flows}_{\text{Test}} = \emptyset$$
3. **Temporal Isolation**:
   - Friday's held-out attack sessions remain 100% unseen by the model until final evaluation reporting.

---

## 6. Repository Data Privacy Contract

- **`data/raw/`**: ❌ Excluded via `.gitignore` (large PCAPs/CSVs are never committed).
- **`data/processed/`**: ❌ Excluded via `.gitignore` (intermediate CSVs are generated locally).
- **`models/*.joblib`**: ❌ Excluded via `.gitignore` (binary artifacts are generated on-demand).
- **`data/sample/demo_flows.csv`**: ✅ Minimal high-fidelity offline replay fixture (<4 KB).

---

## 7. Official Dataset Citations & References

The public datasets utilized in SentinelFlow are cited in accordance with their respective creators' academic and usage terms:

### 1. CIC-IDS2017 Dataset
- **Official Dataset Page**: [Canadian Institute for Cybersecurity (UNB)](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Official Academic Citation**:
  > Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, *"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"*, 4th International Conference on Information Systems Security and Privacy (ICISSP), Funchal, Madeira, Portugal, January 2018.

### 2. CIC-DDoS2019 Dataset
- **Official Dataset Page**: [Canadian Institute for Cybersecurity (UNB)](https://www.unb.ca/cic/datasets/ddos-2019.html)
- **Official Academic Citation**:
  > Iman Sharafaldin, Amirhossein H. Lashkari, Saqib Hakak, and Ali A. Ghorbani, *"Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy"*, IEEE 53rd International Carnahan Conference on Security Technology (ICCST), Chennai, India, 2019.

### 3. CTU-13 Botnet Dataset
- **Official Dataset Page**: [Stratosphere IPS / Czech Technical University](https://www.stratosphereips.org/datasets-ctu13)
- **Official Academic Citation**:
  > Sebastian Garcia, Martin Grill, Jan Stiborek, and Alejandro Zunino, *"An empirical comparison of botnet detection methods"*, Computers & Security Journal, Elsevier, Vol. 45, 2014, pp. 100-123. DOI: `10.1016/j.cose.2014.05.011`.


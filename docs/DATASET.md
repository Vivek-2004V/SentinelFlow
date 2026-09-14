# SentinelFlow — Dataset Architecture & Practical Hackathon Guide

This document describes the frozen **Dataset Architecture** for SentinelFlow, how to ingest the recommended public datasets without downloading hundreds of gigabytes, and how lab-generated traffic is structured.

---

## 🏛️ Dataset Architecture Flow

```
                DATA SOURCES
                     │
          ┌──────────┴──────────┐
          ↓                     ↓
    PUBLIC DATASETS          LAB DATA
          │                     │
   CIC-IDS2017             iperf3
   CIC-DDoS2019            hping3
   CTU-13                  dnscat2 / iodine (DNS tunnel)
          │                DGA domain engine
          │                C2 beacon emulator
          │                nmap / masscan (Recon)
          │                Upload deviation (Exfil)
          └──────────┬──────────┘
                     ↓
              NORMALIZATION
                     ↓
             FEATURE EXTRACTION
                     ↓
         CANONICAL 24-FEATURE CSV/PARQUET
                     ↓
           ┌─────────┼─────────┐
           ↓         ↓         ↓
        TRAIN     VALIDATE    TEST
        (70%)      (15%)      (15% Unseen)
```

---

## 📋 Canonical 24-Column Feature Specification

Raw PCAPs and packets are never fed directly into ML models. Instead, passive network telemetry (via Zeek logs or NetFlow) is normalized into this exact 24-column feature contract:

| # | Column Name | Type | Description |
|---|---|---|---|
| 1 | `timestamp` | string | ISO-8601 flow record timestamp (e.g. `2026-09-14T10:01:03Z`) |
| 2 | `flow_id` | string | Unique flow event identifier (e.g. `F-10021`) |
| 3 | `src_ip` | string | Initiator IPv4 address |
| 4 | `dst_ip` | string | Target IPv4 address |
| 5 | `src_port` | integer | Client source port |
| 6 | `dst_port` | integer | Target service port |
| 7 | `protocol` | string | Transport protocol (`TCP` or `UDP`) |
| 8 | `duration` | float | Connection duration in seconds |
| 9 | `packets` | integer | Total packets transmitted (`pkts_sent + pkts_recv`) |
| 10 | `bytes` | integer | Total payload/header bytes (`bytes_sent + bytes_recv`) |
| 11 | `pps` | float | Packets per second transmission velocity |
| 12 | `bps` | float | Bytes per second bandwidth rate |
| 13 | `mean_packet_size` | float | Average byte size per packet |
| 14 | `packet_size_std` | float | Standard deviation of packet byte lengths |
| 15 | `mean_iat` | float | Mean inter-arrival time between consecutive packets (sec) |
| 16 | `iat_std` | float | Standard deviation of inter-arrival times |
| 17 | `unique_dst_ports` | integer | Count of distinct destination ports probed (fan-out) |
| 18 | `unique_dst_hosts` | integer | Count of distinct destination IPs contacted (horizontal sweep) |
| 19 | `dns_query_length` | integer | Length of domain label requested (characters) |
| 20 | `dns_entropy` | float | Shannon entropy score of DNS domain label |
| 21 | `periodicity_score` | float | Regularity index of communication intervals (0.0 to 1.0) |
| 22 | `outbound_inbound_ratio` | float | Ratio of outbound to inbound traffic volume (exfiltration indicator) |
| 23 | `label` | integer | Binary ground truth (0 = Benign, 1 = Attack) |
| 24 | `threat_class` | string | Canonical threat classification (`BENIGN`, `DDOS`, `C2_BEACON`, `DNS_TUNNEL`, `DGA`, `RECON`, `EXFILTRATION`, `BANDWIDTH_ANOMALY`) |

---

## 🌐 Public Datasets Guide (Minimal Download Strategy)

You do **not** need to download multi-hundred-gigabyte PCAP archives for the hackathon. Download only small, targeted subsets:

### 1. CIC-IDS2017 (Canadian Institute for Cybersecurity)
- **Use Case**: General multi-vector attack detection & clean benign traffic.
- **Official URL**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Recommended Minimal Files**:
  - Download only `Wednesday-workingHours.pcap_ISCX.csv` (contains DoS / DDoS and Benign).
  - Or `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (contains PortScan Recon).
- **Target Folder**: `data/raw/public/cic_ids2017/`

### 2. CIC-DDoS2019
- **Use Case**: Modern reflection and amplification DDoS attacks (SYN, UDP, DNS, NTP).
- **Official URL**: https://www.unb.ca/cic/datasets/ddos-2019.html
- **Recommended Minimal Files**:
  - Download only `01-12/Syn.csv` or `01-12/UDP.csv` (sample 5,000 rows).
- **Target Folder**: `data/raw/public/cic_ddos2019/`

### 3. CTU-13 Botnet Dataset (Stratosphere IPS)
- **Use Case**: Real-world botnet and C2 beacon communication captures.
- **Official URL**: https://www.stratosphereips.org/datasets-ctu13
- **Recommended Minimal Files**:
  - Download `capture42.binetflow` or `capture43.binetflow` (Neris / Rbot botnet captures).
- **Target Folder**: `data/raw/public/ctu13/`

---

## 🧪 Lab Telemetry Generation

Lab telemetry is generated across isolated profiles:
- `data/raw/lab/benign/`: iperf3 baseline network flows.
- `data/raw/lab/ddos/`: hping3 volumetric flood storms.
- `data/raw/lab/dns_tunnel/`: dnscat2 / iodine hex subdomain exfiltration.
- `data/raw/lab/dga/`: Algorithmic domains with high Shannon entropy.
- `data/raw/lab/c2/`: Periodic beacons with configurable jitter.
- `data/raw/lab/recon/`: Port scans across multiple ports.
- `data/raw/lab/exfil/`: High outbound-to-inbound byte transfers.

---

## 🔒 Disjoint Run-Based Partitioning (Zero Data Leakage)

Standard random splitting leaks IP addresses and flow signatures between training and testing. SentinelFlow enforces **Disjoint Run-Based Partitioning**:

- **Attack Run A (70%)** ➔ `data/processed/train.csv` (Trained parameters)
- **Attack Run B (15%)** ➔ `data/processed/validation.csv` (Hyperparameter tuning)
- **Attack Run C (15%)** ➔ `data/processed/test.csv` (**Unseen Test** — strictly novel attacker IPs, different beacon sleep intervals, new DGA dictionaries)

Verification assertion:
$$\text{AttackerIPs}(\text{Train}) \cap \text{AttackerIPs}(\text{Test}) = \emptyset$$

---

## 🚀 Quickstart Commands

1. **Build Datasets & Generate Splits**:
   ```bash
   python scripts/build_dataset.py
   ```
   Outputs:
   - `data/processed/train.csv`, `validation.csv`, `test.csv`
   - `data/sample/demo_flows.csv`
   - `data/splits/split_report.json`

2. **Train Detectors & Evaluate on Unseen Run C**:
   ```bash
   python scripts/train_detectors.py
   ```

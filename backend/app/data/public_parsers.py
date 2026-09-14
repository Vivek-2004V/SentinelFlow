"""
Public Dataset Parsers.

Parses standardized subsets of prominent public network security datasets:
1. CIC-IDS2017: Multi-vector intrusions (DDoS, PortScan, Infiltration, Benign)
2. CIC-DDoS2019: Modern volumetric and application-layer DDoS attacks
3. CTU-13: Real-world botnet and C2 communications (Neris, Rbot, Virut, Murlo)
4. CICIoT2023: Modern IoT network attack dataset (33 attack types across 105 devices)
5. DataSense CIC IIoT 2025: Advanced Industrial IoT dataset (537M+ packets, 50 attack types)
6. CICAPT-IIoT2024: APT campaign progression (Recon -> C2 -> Lateral -> Collection -> Exfil)

Converts raw public CSV / NetFlow records into SentinelFlow standardized flow dictionaries.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List


def parse_cic_ids2017_csv(file_path: Path, max_rows: int = 1000, run_id: str = "run_a") -> List[Dict[str, Any]]:
    """
    Parses a CIC-IDS2017 or CIC-DDoS2019 CSV export file into SentinelFlow raw flow records.
    Maps Canadian Institute for Cybersecurity column headers.
    """
    records: List[Dict[str, Any]] = []
    if not file_path.exists():
        return records

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break

            clean_row = {k.strip(): v.strip() for k, v in row.items() if k}

            raw_label = clean_row.get("Label", "BENIGN").upper()
            is_attack = raw_label != "BENIGN"
            threat_class = "BENIGN"
            if "DDOS" in raw_label or "DOS" in raw_label:
                threat_class = "DDOS"
            elif "PORTSCAN" in raw_label or "SCAN" in raw_label:
                threat_class = "RECON"
            elif "BOT" in raw_label or "C2" in raw_label:
                threat_class = "C2_BEACON"
            elif "INFILTRATION" in raw_label or "EXFIL" in raw_label:
                threat_class = "EXFIL"
            elif is_attack:
                threat_class = "ANOMALY"

            try:
                duration_us = float(clean_row.get("Flow Duration", 1000))
                duration_sec = max(0.001, duration_us / 1_000_000.0)
                tot_fwd_pkts = int(float(clean_row.get("Total Fwd Packets", 1)))
                tot_bwd_pkts = int(float(clean_row.get("Total Backward Packets", 0)))
                tot_fwd_bytes = int(float(clean_row.get("Total Length of Fwd Packets", 60)))
                tot_bwd_bytes = int(float(clean_row.get("Total Length of Bwd Packets", 0)))

                records.append({
                    "src_ip": clean_row.get("Source IP", f"192.168.10.{i % 50 + 1}"),
                    "dst_ip": clean_row.get("Destination IP", "192.168.10.1"),
                    "src_port": int(float(clean_row.get("Source Port", 49152))),
                    "dst_port": int(float(clean_row.get("Destination Port", 80))),
                    "proto": "TCP" if clean_row.get("Protocol", "6") == "6" else "UDP",
                    "bytes_sent": tot_fwd_bytes,
                    "bytes_recv": tot_bwd_bytes,
                    "pkts_sent": tot_fwd_pkts,
                    "pkts_recv": tot_bwd_pkts,
                    "duration_seconds": duration_sec,
                    "sensor_id": "public-cic-ids2017",
                    "source_format": "public_cic_ids2017",
                    "run_id": run_id,
                    "label": 1 if is_attack else 0,
                    "threat_class": threat_class,
                })
            except (ValueError, TypeError):
                continue

    return records


def parse_ctu13_binetflow(file_path: Path, max_rows: int = 1000, run_id: str = "run_a") -> List[Dict[str, Any]]:
    """
    Parses a CTU-13 binetflow capture file.
    Headers: StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label
    """
    records: List[Dict[str, Any]] = []
    if not file_path.exists():
        return records

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break

            clean_row = {k.strip(): v.strip() for k, v in row.items() if k}
            raw_label = clean_row.get("Label", "Normal").upper()
            is_botnet = "BOTNET" in raw_label

            try:
                dur = float(clean_row.get("Dur", 0.1))
                tot_pkts = int(clean_row.get("TotPkts", 1))
                tot_bytes = int(clean_row.get("TotBytes", 64))
                src_bytes = int(clean_row.get("SrcBytes", tot_bytes // 2))

                sport_str = clean_row.get("Sport", "40000")
                sport = int(sport_str) if sport_str.isdigit() else 40000
                dport_str = clean_row.get("Dport", "80")
                dport = int(dport_str) if dport_str.isdigit() else 80

                records.append({
                    "src_ip": clean_row.get("SrcAddr", "10.0.2.15"),
                    "dst_ip": clean_row.get("DstAddr", "147.32.84.180"),
                    "src_port": sport,
                    "dst_port": dport,
                    "proto": clean_row.get("Proto", "tcp").upper(),
                    "bytes_sent": src_bytes,
                    "bytes_recv": max(0, tot_bytes - src_bytes),
                    "pkts_sent": max(1, tot_pkts // 2),
                    "pkts_recv": max(0, tot_pkts - (tot_pkts // 2)),
                    "duration_seconds": max(0.001, dur),
                    "sensor_id": "public-ctu-13",
                    "source_format": "public_ctu13",
                    "run_id": run_id,
                    "label": 1 if is_botnet else 0,
                    "threat_class": "C2_BEACON" if is_botnet else "BENIGN",
                })
            except (ValueError, TypeError):
                continue

    return records


def parse_ciciot2023_csv(file_path: Path, max_rows: int = 1000, run_id: str = "run_a") -> List[Dict[str, Any]]:
    """
    Parses a CICIoT2023 feature export CSV.
    Covers 33 attack classes including Mirai, Recon, DoS, DDoS, Spoofing.
    """
    records: List[Dict[str, Any]] = []
    if not file_path.exists():
        return records

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break

            clean_row = {k.strip(): v.strip() for k, v in row.items() if k}
            raw_label = clean_row.get("label", clean_row.get("Label", "BenignTraffic")).upper()
            is_attack = "BENIGN" not in raw_label

            threat_class = "BENIGN"
            if "DDOS" in raw_label or "DOS" in raw_label or "FLOOD" in raw_label:
                threat_class = "DDOS"
            elif "RECON" in raw_label or "VULNERABILITY" in raw_label or "SCAN" in raw_label:
                threat_class = "RECON"
            elif "MIRAI" in raw_label or "BOT" in raw_label or "COMMAND" in raw_label:
                threat_class = "C2_BEACON"
            elif "BRUTEFORCE" in raw_label or "DICTIONARY" in raw_label:
                threat_class = "RECON"
            elif "SPOOFING" in raw_label or "MITM" in raw_label:
                threat_class = "ANOMALY"
            elif is_attack:
                threat_class = "ANOMALY"

            try:
                duration_sec = max(0.001, float(clean_row.get("Duration", clean_row.get("flow_duration", 0.1))))
                rate = float(clean_row.get("Rate", 100.0))
                tot_bytes = int(float(clean_row.get("Tot size", clean_row.get("Header_Length", 500))))
                tot_pkts = max(1, int(rate * duration_sec))

                records.append({
                    "src_ip": clean_row.get("src_ip", f"192.168.1.{i % 100 + 1}"),
                    "dst_ip": clean_row.get("dst_ip", "192.168.1.1"),
                    "src_port": int(float(clean_row.get("src_port", 40000 + (i % 1000)))),
                    "dst_port": int(float(clean_row.get("dst_port", 80))),
                    "proto": "TCP" if clean_row.get("Protocol Type", "6") in ("6", "TCP") else "UDP",
                    "bytes_sent": max(60, tot_bytes),
                    "bytes_recv": max(0, tot_bytes // 2),
                    "pkts_sent": max(1, tot_pkts),
                    "pkts_recv": max(0, tot_pkts // 2),
                    "duration_seconds": duration_sec,
                    "sensor_id": "public-ciciot2023",
                    "source_format": "public_ciciot2023",
                    "run_id": run_id,
                    "label": 1 if is_attack else 0,
                    "threat_class": threat_class,
                })
            except (ValueError, TypeError):
                continue

    return records


def parse_datasense_iiot2025_csv(file_path: Path, max_rows: int = 1000, run_id: str = "run_a") -> List[Dict[str, Any]]:
    """
    Parses DataSense CIC IIoT 2025 modern industrial dataset records.
    """
    return parse_cic_ids2017_csv(file_path, max_rows=max_rows, run_id=run_id)


def parse_cicapt_iiot2024_csv(file_path: Path, max_rows: int = 1000, run_id: str = "run_a") -> List[Dict[str, Any]]:
    """
    Parses CICAPT-IIoT2024 APT attack-campaign dataset.
    Maps MITRE tactics to SentinelFlow lifecycle stages:
    Reconnaissance -> RECON
    Command and Control -> C2_BEACON
    Exfiltration -> EXFIL
    """
    records: List[Dict[str, Any]] = []
    if not file_path.exists():
        return records

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break

            clean_row = {k.strip(): v.strip() for k, v in row.items() if k}
            tactic = clean_row.get("Tactic", clean_row.get("tactic", clean_row.get("Label", "BENIGN"))).upper()
            is_attack = "BENIGN" not in tactic

            threat_class = "BENIGN"
            if "RECON" in tactic or "DISCOVERY" in tactic:
                threat_class = "RECON"
            elif "COMMAND" in tactic or "C2" in tactic:
                threat_class = "C2_BEACON"
            elif "EXFIL" in tactic or "COLLECTION" in tactic:
                threat_class = "EXFIL"
            elif "INITIAL" in tactic or "ACCESS" in tactic:
                threat_class = "DGA"
            elif "LATERAL" in tactic or "EXECUTION" in tactic:
                threat_class = "ANOMALY"
            elif is_attack:
                threat_class = "ANOMALY"

            try:
                dur = max(0.001, float(clean_row.get("duration", clean_row.get("Flow Duration", 0.5))))
                records.append({
                    "src_ip": clean_row.get("src_ip", clean_row.get("Source IP", f"10.0.1.{i % 50 + 1}")),
                    "dst_ip": clean_row.get("dst_ip", clean_row.get("Destination IP", "10.0.1.254")),
                    "src_port": int(float(clean_row.get("src_port", clean_row.get("Source Port", 45000)))),
                    "dst_port": int(float(clean_row.get("dst_port", clean_row.get("Destination Port", 443)))),
                    "proto": "TCP" if clean_row.get("proto", clean_row.get("Protocol", "TCP")).upper() in ("TCP", "6") else "UDP",
                    "bytes_sent": int(float(clean_row.get("bytes_sent", clean_row.get("Total Length of Fwd Packets", 1200)))),
                    "bytes_recv": int(float(clean_row.get("bytes_recv", clean_row.get("Total Length of Bwd Packets", 400)))),
                    "pkts_sent": int(float(clean_row.get("pkts_sent", clean_row.get("Total Fwd Packets", 10)))),
                    "pkts_recv": int(float(clean_row.get("pkts_recv", clean_row.get("Total Backward Packets", 5)))),
                    "duration_seconds": dur,
                    "sensor_id": "public-cicapt-iiot2024",
                    "source_format": "public_cicapt_iiot2024",
                    "run_id": run_id,
                    "label": 1 if is_attack else 0,
                    "threat_class": threat_class,
                })
            except (ValueError, TypeError):
                continue

    return records

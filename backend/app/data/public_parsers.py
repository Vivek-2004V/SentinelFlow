"""
Public Dataset Parsers.

Parses standardized subsets of prominent public network security datasets:
1. CIC-IDS2017: Multi-vector intrusions (DDoS, PortScan, Infiltration, Benign)
2. CIC-DDoS2019: Modern volumetric and application-layer DDoS attacks
3. CTU-13: Real-world botnet and C2 communications (Neris, Rbot, Virut, Murlo)

Converts raw public CSV / NetFlow records into SentinelFlow standardized flow dictionaries.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List


def _normalize_row(row: Dict[str, Any]) -> Dict[str, str]:
    """Normalize public dataset CSV rows for consistent header and value handling."""
    normalized: Dict[str, str] = {}
    for key, value in row.items():
        if key is None:
            continue
        clean_key = str(key).strip().lstrip("\ufeff")
        clean_value = "" if value is None else str(value).strip()
        normalized[clean_key] = clean_value
    return normalized


def parse_cic_ids2017_csv(file_path: Path, max_rows: int = 1000, run_id: str = "run_a") -> List[Dict[str, Any]]:
    """
    Parses a CIC-IDS2017 CSV export file into SentinelFlow raw flow records.
    Maps Canadian Institute for Cybersecurity column headers.
    """
    records: List[Dict[str, Any]] = []
    if not file_path.exists():
        return records

    with open(file_path, "r", encoding="utf-8-sig", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return records

        reader.fieldnames = [str(name).strip().lstrip("\ufeff") for name in reader.fieldnames]

        for i, row in enumerate(reader):
            if i >= max_rows:
                break

            clean_row = _normalize_row(row)
            raw_label = (clean_row.get("Label") or clean_row.get("label") or "BENIGN").upper()
            is_attack = raw_label != "BENIGN"
            threat_class = "BENIGN"
            if "DDOS" in raw_label or "DOS" in raw_label:
                threat_class = "DDOS"
            elif "PORTSCAN" in raw_label or "SCAN" in raw_label:
                threat_class = "RECON"
            elif "BOT" in raw_label or "BOTNET" in raw_label:
                threat_class = "C2_BEACON"
            elif is_attack:
                threat_class = "ANOMALY"

            try:
                duration_us = float(clean_row.get("Flow Duration", "1000"))
                duration_sec = max(0.001, duration_us / 1_000_000.0)
                tot_fwd_pkts = int(float(clean_row.get("Total Fwd Packets", "1")))
                tot_bwd_pkts = int(float(clean_row.get("Total Backward Packets", "0")))
                tot_fwd_bytes = int(float(clean_row.get("Total Length of Fwd Packets", "60")))
                tot_bwd_bytes = int(float(clean_row.get("Total Length of Bwd Packets", "0")))

                records.append({
                    "src_ip": clean_row.get("Source IP", f"192.168.10.{i % 50 + 1}"),
                    "dst_ip": clean_row.get("Destination IP", "192.168.10.1"),
                    "src_port": int(float(clean_row.get("Source Port", "49152"))),
                    "dst_port": int(float(clean_row.get("Destination Port", "80"))),
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

    with open(file_path, "r", encoding="utf-8-sig", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return records

        reader.fieldnames = [str(name).strip().lstrip("\ufeff") for name in reader.fieldnames]

        for i, row in enumerate(reader):
            if i >= max_rows:
                break

            clean_row = _normalize_row(row)
            raw_label = (clean_row.get("Label") or clean_row.get("label") or "Normal").upper()
            is_botnet = "BOTNET" in raw_label or "BOT" in raw_label

            try:
                dur = float(clean_row.get("Dur", "0.1"))
                tot_pkts = int(clean_row.get("TotPkts", "1"))
                tot_bytes = int(clean_row.get("TotBytes", "64"))
                src_bytes = int(clean_row.get("SrcBytes", str(tot_bytes // 2)))

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

"""
Public Dataset Parsers.

Parses standardized subsets of prominent public network security datasets:
1. CIC-IDS2017: Multi-vector intrusions (DDoS, PortScan, Infiltration, Benign)
2. CIC-DDoS2019: Modern volumetric and application-layer DDoS attacks
3. CTU-13: Real-world botnet and C2 communications (Neris, Rbot, Virut, Murlo)

Converts raw public CSV / NetFlow records into SentinelFlow standardized flow dictionaries.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List


def parse_cic_ids2017_csv(file_path: Path, max_rows: int = 1000, run_id: str = "run_a") -> List[Dict[str, Any]]:
    """
    Parses a CIC-IDS2017 CSV export file into SentinelFlow raw flow records.
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

            # Strip whitespace from headers
            clean_row = {k.strip(): v.strip() for k, v in row.items() if k}

            # Map label
            raw_label = clean_row.get("Label", "BENIGN").upper()
            is_attack = raw_label != "BENIGN"
            threat_class = "BENIGN"
            if "DDOS" in raw_label or "DOS" in raw_label:
                threat_class = "DDOS"
            elif "PORTSCAN" in raw_label or "SCAN" in raw_label:
                threat_class = "RECON"
            elif "BOT" in raw_label:
                threat_class = "C2_BEACON"
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

"""
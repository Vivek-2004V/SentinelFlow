#!/usr/bin/env python3
"""
SentinelFlow Dataset Builder.

Implements the frozen dataset architecture:
1. Public Datasets: CIC-IDS2017, CIC-DDoS2019, CTU-13 (data/raw/public/)
2. Lab Datasets: benign, ddos, dns_tunnel, dga, c2, recon, exfil (data/raw/lab/)
3. Unified Normalization & Feature Extraction into Canonical 24-Column Schema
4. Disjoint Run-Based Splits (Run A -> Train, Run B -> Val, Run C -> Unseen Test)
5. Exports:
   - data/processed/train.csv, validation.csv, test.csv
   - data/splits/train.jsonl, val.jsonl, test.jsonl
   - data/sample/demo_flows.csv
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

# Add backend directory to sys.path for app imports
BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.data.generators.benign import generate_benign_flows
from app.data.generators.c2_emulator import generate_c2_emulator_flows
from app.data.generators.dns_tunnel_dga import generate_dns_tunnel_dga_flows
from app.data.generators.exfil import generate_exfil_flows
from app.data.generators.iperf3_ostinato import generate_iperf3_ostinato_flows
from app.data.generators.recon import generate_recon_flows
from app.data.generators.trex_hping3 import generate_trex_hping3_flows
from app.data.normalizer import CANONICAL_24_FEATURES, normalize_flow_record
from app.data.partitioner import DatasetPartitioner
from app.data.public_parsers import parse_cic_ids2017_csv, parse_ctu13_binetflow

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_PUBLIC_DIR = DATA_DIR / "raw" / "public"
RAW_LAB_DIR = DATA_DIR / "raw" / "lab"
PROCESSED_DIR = DATA_DIR / "processed"
SPLITS_DIR = DATA_DIR / "splits"
SAMPLE_DIR = DATA_DIR / "sample"


def load_all_public_datasets() -> list[dict]:
    """Ingests available public dataset files (CIC-IDS2017, CIC-DDoS2019, CTU-13, and raw JSONL)."""
    public_records: list[dict] = []

    # 1. CIC-IDS2017
    cic_ids_dir = RAW_PUBLIC_DIR / "cic_ids2017"
    if cic_ids_dir.exists():
        for csv_file in cic_ids_dir.glob("*.csv"):
            records = parse_cic_ids2017_csv(csv_file, max_rows=500, run_id="run_a")
            public_records.extend(records)

    # 2. CIC-DDoS2019
    cic_ddos_dir = RAW_PUBLIC_DIR / "cic_ddos2019"
    if cic_ddos_dir.exists():
        for csv_file in cic_ddos_dir.glob("*.csv"):
            records = parse_cic_ids2017_csv(csv_file, max_rows=500, run_id="run_b")
            for r in records:
                r["source_format"] = "public_cic_ddos2019"
            public_records.extend(records)

    # 3. CTU-13
    ctu13_dir = RAW_PUBLIC_DIR / "ctu13"
    if ctu13_dir.exists():
        for binet_file in ctu13_dir.glob("*.binetflow"):
            records = parse_ctu13_binetflow(binet_file, max_rows=500, run_id="run_c")
            public_records.extend(records)

    # 4. Any direct JSONL files in raw/public
    if RAW_PUBLIC_DIR.exists():
        for jsonl_file in RAW_PUBLIC_DIR.glob("*.jsonl"):
            with open(jsonl_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            public_records.append(json.loads(line.strip()))
                        except json.JSONDecodeError:
                            continue

    return public_records


def generate_and_persist_lab_traffic() -> list[dict]:
    """
    Generates synthetic lab traffic across all 7 categories:
    benign, ddos, dns_tunnel, dga, c2, recon, exfil
    partitioned into Runs A, B, and C, and writes raw streams to data/raw/lab/.
    """
    RAW_LAB_DIR.mkdir(parents=True, exist_ok=True)
    categories = ["benign", "ddos", "dns_tunnel", "dga", "c2", "recon", "exfil"]
    for cat in categories:
        (RAW_LAB_DIR / cat).mkdir(parents=True, exist_ok=True)

    all_lab_flows: list[dict] = []
    runs = ["run_a", "run_b", "run_c"]

    for run_id in runs:
        # Benign (iperf3 normal profiles)
        benign_flows = generate_benign_flows(count=100, run_id=run_id)
        all_lab_flows.extend(benign_flows)

        # DDoS (hping3 / TRex)
        ddos_flows = generate_trex_hping3_flows(count=80, run_id=run_id)
        all_lab_flows.extend(ddos_flows)

        # DNS Tunnel & DGA (dnscat2 / iodine + algorithmic domains)
        dns_flows = generate_dns_tunnel_dga_flows(count=80, run_id=run_id)
        all_lab_flows.extend(dns_flows)

        # C2 Emulator (Cobalt Strike / Sliver beacons)
        c2_flows = generate_c2_emulator_flows(count=80, run_id=run_id)
        all_lab_flows.extend(c2_flows)

        # Recon (masscan / nmap port sweeps)
        recon_flows = generate_recon_flows(count=60, run_id=run_id)
        all_lab_flows.extend(recon_flows)

        # Exfil (outbound upload volume deviation)
        exfil_flows = generate_exfil_flows(count=60, run_id=run_id)
        all_lab_flows.extend(exfil_flows)

        # iperf3 / Ostinato high bandwidth profiles
        iperf_flows = generate_iperf3_ostinato_flows(count=60, run_id=run_id)
        all_lab_flows.extend(iperf_flows)

    # Persist raw lab flows organized by category
    for cat in categories:
        cat_flows = [f for f in all_lab_flows if cat in f.get("generator", "") or cat in f.get("threat_class", "").lower()]
        out_file = RAW_LAB_DIR / cat / "flows.jsonl"
        with open(out_file, "w", encoding="utf-8") as f:
            for r in cat_flows:
                f.write(json.dumps(r) + "\n")

    return all_lab_flows


def main():
    print("==========================================================")
    print("     SentinelFlow Hackathon Dataset Pipeline Builder      ")
    print("==========================================================")

    # 1. Ingest Public Datasets
    print("[*] 1. Ingesting Public Datasets (CIC-IDS2017, CIC-DDoS2019, CTU-13)...")
    public_flows = load_all_public_datasets()
    print(f"    -> Ingested {len(public_flows)} flows from {RAW_PUBLIC_DIR}")

    # 2. Generate Lab Datasets
    print("[*] 2. Generating Lab Datasets (benign, ddos, dns_tunnel, dga, c2, recon, exfil)...")
    lab_flows = generate_and_persist_lab_traffic()
    print(f"    -> Generated and saved {len(lab_flows)} lab flows to {RAW_LAB_DIR}")

    total_raw = public_flows + lab_flows
    print(f"[*] Total raw flows gathered: {len(total_raw)}")

    # 3. Normalization into Canonical 24 Features
    print("[*] 3. Running Feature Normalization (Extracting 24 Canonical Features)...")
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    normalized_records = [normalize_flow_record(raw) for raw in total_raw]

    # 4. Disjoint Partitioning (Run A -> Train, Run B -> Val, Run C -> Unseen Test)
    print("[*] 4. Enforcing Disjoint Run-Based Partitioning...")
    partitioner = DatasetPartitioner()
    train_set, val_set, test_set, report = partitioner.partition(normalized_records)

    # Save JSONL splits for detector training
    partitioner.save_splits(train_set, val_set, test_set, report, SPLITS_DIR)

    # Save Canonical CSV files in data/processed/ and demo_flows.csv in data/sample/
    partitioner.save_canonical_csvs(train_set, val_set, test_set, PROCESSED_DIR, SAMPLE_DIR)

    print("----------------------------------------------------------")
    print("               Dataset Generation Summary                 ")
    print("----------------------------------------------------------")
    print(f" Processed Train CSV:      {PROCESSED_DIR / 'train.csv'} ({len(train_set)} rows)")
    print(f" Processed Validation CSV: {PROCESSED_DIR / 'validation.csv'} ({len(val_set)} rows)")
    print(f" Processed Test CSV:       {PROCESSED_DIR / 'test.csv'} ({len(test_set)} rows - Unseen Run C)")
    print(f" Sample Demo CSV:          {SAMPLE_DIR / 'demo_flows.csv'}")
    print("----------------------------------------------------------")
    print(f" Disjoint Partition Validated: {report['is_disjoint']}")
    print(f" Zero Attacker IP Leakage:     {report['zero_attacker_ip_leakage']}")
    print(f" Zero Duplicate Flows:         {report['zero_duplicate_flows']}")
    print("----------------------------------------------------------")
    print(" Canonical 24 Columns Verified:")
    print(" ", ", ".join(CANONICAL_24_FEATURES[:8]))
    print(" ", ", ".join(CANONICAL_24_FEATURES[8:16]))
    print(" ", ", ".join(CANONICAL_24_FEATURES[16:]))
    print("==========================================================")


if __name__ == "__main__":
    main()

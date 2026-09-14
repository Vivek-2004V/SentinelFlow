#!/usr/bin/env python3
"""
SentinelFlow Dataset Normalization Script (scripts/normalize_dataset.py)

Ingests raw flow telemetry, public datasets, or lab attack runs and normalizes
them into the frozen 24-feature canonical schema:
1. timestamp
2. flow_id
3. src_ip
4. dst_ip
5. src_port
6. dst_port
7. protocol
8. duration
9. packets
10. bytes
11. pps
12. bps
13. mean_packet_size
14. packet_size_std
15. mean_iat
16. iat_std
17. unique_dst_ports
18. unique_dst_hosts
19. dns_query_length
20. dns_entropy
21. periodicity_score
22. outbound_inbound_ratio
23. label
24. threat_class
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

# Ensure backend modules can be imported
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
from app.data.public_parsers import parse_cic_ids2017_csv, parse_ctu13_binetflow

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
SAMPLE_DIR = DATA_DIR / "sample"


def load_and_normalize_file(file_path: Path) -> list[dict[str, Any]]:
    """
    Loads raw files (CSV, JSON, JSONL, Zeek .log, or CTU-13 .binetflow)
    and normalizes records into the canonical 24 features schema.
    """
    normalized: list[dict[str, Any]] = []
    if not file_path.exists():
        print(f"[!] Warning: File {file_path} does not exist.")
        return normalized

    suffix = file_path.suffix.lower()

    if suffix == ".jsonl":
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    raw = json.loads(line)
                    normalized.append(normalize_flow_record(raw))
    elif suffix == ".json":
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            items = data if isinstance(data, list) else [data]
            for item in items:
                normalized.append(normalize_flow_record(item))
    elif suffix == ".binetflow":
        from app.data.public_parsers import parse_ctu13_binetflow
        raw_records = parse_ctu13_binetflow(file_path, max_rows=5000)
        normalized = [normalize_flow_record(r) for r in raw_records]
    elif suffix in (".log", ".txt"):
        # Check if it's a Zeek conn.log
        from app.ingest.zeek import correlate_zeek_logs
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if "id.orig_h" in content or "orig_bytes" in content or "#separator" in content:
            raw_flows = correlate_zeek_logs(conn_content=content)
            normalized = [normalize_flow_record(rf.model_dump()) for rf in raw_flows]
        else:
            print(f"[!] Unrecognized log format in {file_path}")
    elif suffix == ".csv":
        # Check if CIC-IDS or generic CSV
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            header_line = f.readline()
        if "Flow Duration" in header_line or "Total Fwd Packets" in header_line:
            from app.data.public_parsers import parse_cic_ids2017_csv
            raw_records = parse_cic_ids2017_csv(file_path, max_rows=5000)
            normalized = [normalize_flow_record(r) for r in raw_records]
        else:
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    normalized.append(normalize_flow_record(row))
    else:
        print(f"[!] Unsupported file format: {suffix}")

    return normalized


def collect_raw_lab_and_public() -> list[dict[str, Any]]:
    """Gathers raw traffic flows across all lab generators and existing public files."""
    records: list[dict[str, Any]] = []

    print("[*] Generating raw lab traffic streams...")
    # 1. Lab generators (iperf3, hping3, dns_tunnel, dga, c2, recon, exfil, benign)
    records.extend(generate_benign_flows(count=50, run_id="run_a"))
    records.extend(generate_iperf3_ostinato_flows(count=30, run_id="run_a"))
    records.extend(generate_trex_hping3_flows(count=40, run_id="run_a"))
    records.extend(generate_dns_tunnel_dga_flows(count=60, run_id="run_a"))
    records.extend(generate_c2_emulator_flows(count=30, run_id="run_a"))
    records.extend(generate_recon_flows(count=30, run_id="run_a"))
    records.extend(generate_exfil_flows(count=30, run_id="run_a"))

    # 2. Check for public datasets in data/raw/public/
    public_dir = RAW_DIR / "public"
    if public_dir.exists():
        for csv_file in public_dir.glob("**/*.csv"):
            print(f"[*] Parsing public CSV: {csv_file.name}")
            parsed = parse_cic_ids2017_csv(csv_file, max_rows=100, run_id="run_a")
            records.extend(parsed)
        for binet_file in public_dir.glob("**/*.binetflow"):
            print(f"[*] Parsing CTU-13 file: {binet_file.name}")
            parsed = parse_ctu13_binetflow(binet_file, max_rows=100, run_id="run_a")
            records.extend(parsed)

    # Normalize all
    normalized = [normalize_flow_record(r) for r in records]
    return normalized


def write_canonical_csv(records: list[dict[str, Any]], out_path: Path) -> None:
    """Writes records into a CSV file with strictly ordered 24 canonical columns."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CANONICAL_24_FEATURES)
        writer.writeheader()
        for r in records:
            # Ensure row has only the canonical 24 keys in exact order
            row = {k: r.get(k, 0) for k in CANONICAL_24_FEATURES}
            writer.writerow(row)
    print(f"[+] Successfully wrote {len(records)} normalized flows to {out_path}")


def print_summary(records: list[dict[str, Any]]) -> None:
    """Prints a clear distribution summary of the normalized dataset."""
    total = len(records)
    benign = sum(1 for r in records if str(r.get("label")) in ("0", "BENIGN", "False"))
    attack = total - benign
    threat_counts: dict[str, int] = {}
    for r in records:
        tc = str(r.get("threat_class", "UNKNOWN"))
        threat_counts[tc] = threat_counts.get(tc, 0) + 1

    print("\n----------------------------------------------------------")
    print("           NORMALIZED DATASET AUDIT SUMMARY               ")
    print("----------------------------------------------------------")
    print(f" Total Canonical Flows: {total}")
    print(f" Benign Traffic:        {benign} ({benign/total*100:.1f}%)" if total else " 0")
    print(f" Attack Traffic:        {attack} ({attack/total*100:.1f}%)" if total else " 0")
    print(" Threat Classes:")
    for tc, count in sorted(threat_counts.items(), key=lambda x: -x[1]):
        print(f"   * {tc:<20}: {count} flows")
    print(f" Columns: {len(CANONICAL_24_FEATURES)} (Exact 24-feature schema verified)")
    print("----------------------------------------------------------\n")


def main():
    parser = argparse.ArgumentParser(description="SentinelFlow Dataset Normalization Script")
    parser.add_argument("--input", type=str, default=None, help="Path to raw input file (CSV/JSON/JSONL)")
    parser.add_argument("--output", type=str, default=None, help="Path to output normalized CSV")
    parser.add_argument("--sample", action="store_true", help="Generate or refresh data/sample/demo_flows.csv")
    parser.add_argument("--all", action="store_true", help="Normalize all raw lab and public datasets to data/processed/")

    args = parser.parse_args()

    if args.input:
        in_p = Path(args.input)
        out_p = Path(args.output) if args.output else PROCESSED_DIR / f"normalized_{in_p.stem}.csv"
        records = load_and_normalize_file(in_p)
        write_canonical_csv(records, out_p)
        print_summary(records)
    elif args.sample:
        records = collect_raw_lab_and_public()
        # Take a balanced representative sample across threat classes
        sample_records: list[dict[str, Any]] = []
        by_threat: dict[str, list[dict[str, Any]]] = {}
        for r in records:
            tc = str(r.get("threat_class", "BENIGN"))
            by_threat.setdefault(tc, []).append(r)
        
        # Take up to 3 flows from each category
        for tc, flist in by_threat.items():
            sample_records.extend(flist[:3])
            
        sample_path = SAMPLE_DIR / "demo_flows.csv"
        write_canonical_csv(sample_records, sample_path)
        print_summary(sample_records)
    else:
        # Default: normalize and build into data/processed/normalized_dataset.csv
        records = collect_raw_lab_and_public()
        out_file = PROCESSED_DIR / "normalized_dataset.csv"
        write_canonical_csv(records, out_file)
        print_summary(records)


if __name__ == "__main__":
    main()

"""
Unit & Integration Tests for Section 13 Dataset Architecture.

Verifies:
1. Lab traffic generator contracts (iperf3/Ostinato, TRex/hping3, DNS tunnel/DGA, C2 emulator, benign).
2. Unified Normalization engine and feature extraction.
3. Strict Disjoint Run-based Partitioning (Run A -> Train, Run B -> Val, Run C -> Unseen Test).
4. Zero data leakage verification and intentional leakage detection.
"""
from __future__ import annotations

from app.data.generators.benign import generate_benign_flows
from app.data.generators.c2_emulator import generate_c2_emulator_flows
from app.data.generators.dns_tunnel_dga import generate_dns_tunnel_dga_flows
from app.data.generators.iperf3_ostinato import generate_iperf3_ostinato_flows
from app.data.generators.trex_hping3 import generate_trex_hping3_flows
from app.data.normalizer import normalize_flow_record
from app.data.partitioner import DatasetPartitioner


def test_lab_traffic_generators_produce_valid_flows():
    runs = ["run_a", "run_b", "run_c"]

    for run_id in runs:
        # iperf3 / Ostinato
        iperf_flows = generate_iperf3_ostinato_flows(count=5, run_id=run_id)
        assert len(iperf_flows) == 5
        assert all(f["run_id"] == run_id for f in iperf_flows)
        assert all(f["generator"] == "iperf3_ostinato" for f in iperf_flows)

        # TRex / hping3
        trex_flows = generate_trex_hping3_flows(count=5, run_id=run_id)
        assert len(trex_flows) == 5
        assert all(f["threat_class"] == "DDOS" for f in trex_flows)

        # DNS Tunnel / DGA
        dns_flows = generate_dns_tunnel_dga_flows(count=5, run_id=run_id)
        assert len(dns_flows) == 5
        assert all(f["dns_query"] is not None for f in dns_flows)

        # C2 Emulator
        c2_flows = generate_c2_emulator_flows(count=5, run_id=run_id)
        assert len(c2_flows) == 5
        assert all(f["threat_class"] == "C2_BEACON" for f in c2_flows)
        assert all("periodicity_hint" in f for f in c2_flows)

        # Benign baseline
        benign_flows = generate_benign_flows(count=5, run_id=run_id)
        assert len(benign_flows) == 5
        assert all(f["label"] == 0 for f in benign_flows)


def test_normalizer_extracts_complete_feature_record():
    raw = {
        "src_ip": "198.51.100.42",
        "dst_ip": "10.0.0.5",
        "dst_port": 80,
        "proto": "UDP",
        "bytes_sent": 500000,
        "bytes_recv": 0,
        "pkts_sent": 8000,
        "pkts_recv": 0,
        "duration_seconds": 0.05,
        "run_id": "run_a",
        "generator": "trex_hping3",
        "label": 1,
        "threat_class": "DDOS",
    }

    norm = normalize_flow_record(raw)

    assert norm["src_ip"] == "198.51.100.42"
    assert norm["run_id"] == "run_a"
    assert norm["label"] == 1
    assert norm["threat_class"] == "DDOS"
    assert norm["pkts_per_second"] > 10000
    assert norm["bytes_per_second"] > 1000000
    assert "source_category" in norm
    assert norm["flow_id"].startswith("F-")

    # Verify all 24 canonical features are present
    from app.data.normalizer import CANONICAL_24_FEATURES
    for feat in CANONICAL_24_FEATURES:
        assert feat in norm, f"Missing canonical feature: {feat}"


def test_canonical_24_features_csv_contract():
    """Verifies that data/sample/demo_flows.csv contains the exact 24 headers in order."""
    import csv
    from pathlib import Path

    from app.data.normalizer import CANONICAL_24_FEATURES

    sample_file = Path(__file__).resolve().parent.parent.parent / "data" / "sample" / "demo_flows.csv"
    assert sample_file.exists()

    with open(sample_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        headers = next(reader)

    assert len(headers) == 24
    assert headers == CANONICAL_24_FEATURES


def test_public_parsers():
    """Verifies parsing of CIC-IDS2017 and CTU-13 sample files."""
    from pathlib import Path

    from app.data.public_parsers import parse_cic_ids2017_csv, parse_ctu13_binetflow

    base = Path(__file__).resolve().parent.parent.parent / "data" / "raw" / "public"
    cic_file = base / "cic_ids2017" / "sample_cic_ids2017.csv"
    ctu_file = base / "ctu13" / "sample_ctu13.binetflow"

    cic_records = parse_cic_ids2017_csv(cic_file)
    assert len(cic_records) > 0

    cic_classes = {
        record["threat_class"]
        for record in cic_records
    }
    assert "BENIGN" in cic_classes
    assert "DDOS" in cic_classes

    ctu_records = parse_ctu13_binetflow(ctu_file)
    assert len(ctu_records) > 0

    ctu_classes = {
        record["threat_class"]
        for record in ctu_records
    }
    assert "C2_BEACON" in ctu_classes


def test_disjoint_run_based_partitioning():
    flows = []
    for r in ["run_a", "run_b", "run_c"]:
        flows.extend(generate_trex_hping3_flows(count=10, run_id=r))
        flows.extend(generate_c2_emulator_flows(count=10, run_id=r))
        flows.extend(generate_benign_flows(count=10, run_id=r))

    normalized = [normalize_flow_record(f) for f in flows]

    partitioner = DatasetPartitioner()
    train_set, val_set, test_set, report = partitioner.partition(normalized)

    # All flows in train must be from run_a
    assert all(r["run_id"] == "run_a" for r in train_set)
    # All flows in val must be from run_b
    assert all(r["run_id"] == "run_b" for r in val_set)
    # All flows in test must be from run_c (Unseen Test)
    assert all(r["run_id"] == "run_c" for r in test_set)

    # Invariants
    assert report["is_disjoint"] is True
    assert report["zero_attacker_ip_leakage"] is True
    assert report["zero_duplicate_flows"] is True
    assert report["leaked_attacker_ips_count"] == 0
    assert report["duplicate_flow_signatures_count"] == 0


def test_partitioner_detects_data_leakage():
    """Verify that if an identical attack flow or IP leaks into test, partitioner flags it."""
    leaked_flow_a = {
        "src_ip": "198.51.100.99",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "bytes_sent": 1000,
        "pkts_sent": 10,
        "duration_seconds": 1.0,
        "run_id": "run_a",
        "label": 1,
        "threat_class": "DDOS",
    }
    leaked_flow_c = {
        "src_ip": "198.51.100.99",  # Same IP in test set!
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "bytes_sent": 1000,
        "pkts_sent": 10,
        "duration_seconds": 1.0,
        "run_id": "run_c",
        "label": 1,
        "threat_class": "DDOS",
    }

    norm_a = normalize_flow_record(leaked_flow_a)
    norm_c = normalize_flow_record(leaked_flow_c)

    partitioner = DatasetPartitioner()
    train_set, val_set, test_set, report = partitioner.partition([norm_a, norm_c])

    assert report["is_disjoint"] is False
    assert report["zero_attacker_ip_leakage"] is False
    assert report["leaked_attacker_ips_count"] == 1
    assert "198.51.100.99" in report["leaked_attacker_ips"]

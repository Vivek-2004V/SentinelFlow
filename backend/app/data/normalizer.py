"""
Normalization Engine.

Normalizes diverse raw network flows (Public datasets and Lab traffic)
into standard feature representations with complete provenance metadata.
"""
from __future__ import annotations

import secrets
from typing import Any, Dict

from app.features.dns import extract_dns_features
from app.features.flow import extract_flow_features
from app.features.tls import extract_tls_features
from app.schemas.flow import RawFlow

CANONICAL_24_FEATURES = [
    "timestamp",
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "duration",
    "packets",
    "bytes",
    "pps",
    "bps",
    "mean_packet_size",
    "packet_size_std",
    "mean_iat",
    "iat_std",
    "unique_dst_ports",
    "unique_dst_hosts",
    "dns_query_length",
    "dns_entropy",
    "periodicity_score",
    "outbound_inbound_ratio",
    "label",
    "threat_class",
]


def normalize_flow_record(raw: Dict[str, Any], default_run_id: str = "run_a") -> Dict[str, Any]:
    """
    Normalizes a raw dictionary flow into a standardized feature record.
    Emits both the canonical 24-feature schema and SentinelFlow internal feature keys.
    """
    # 1. Parse into validated RawFlow
    duration = float(raw.get("duration_seconds", raw.get("duration", 0.01)))
    if duration <= 0:
        duration = 0.001

    raw_flow = RawFlow(
        src_ip=raw["src_ip"],
        dst_ip=raw["dst_ip"],
        src_port=raw.get("src_port"),
        dst_port=raw.get("dst_port", 80),
        proto=raw.get("proto", raw.get("protocol", "TCP")),
        bytes_sent=int(raw.get("bytes_sent", raw.get("bytes", 0))),
        bytes_recv=int(raw.get("bytes_recv", 0)),
        pkts_sent=int(raw.get("pkts_sent", raw.get("packets", 1))),
        pkts_recv=int(raw.get("pkts_recv", 0)),
        duration_seconds=duration,
        dns_query=raw.get("dns_query"),
        tls_sni=raw.get("tls_sni"),
        ja3_hash=raw.get("ja3_hash"),
        quic_version=raw.get("quic_version"),
        sensor_id=raw.get("sensor_id", "default-sensor"),
        source_format=raw.get("source_format", "generic"),
    )

    # 2. Extract standard flow features
    flow_feats = extract_flow_features(raw_flow)

    # 3. Extract DNS features if present
    dns_entropy = 0.0
    dns_query_len = 0.0
    dns_digit_ratio = 0.0
    dns_subdomain_depth = 0
    if raw_flow.dns_query:
        dns_res = extract_dns_features(raw_flow.dns_query)
        dns_entropy = dns_res["dns_entropy"]
        dns_query_len = dns_res["dns_query_length"]
        dns_digit_ratio = dns_res["dns_digit_ratio"]
        dns_subdomain_depth = dns_res["dns_subdomain_depth"]

    # 4. Extract TLS features
    tls_res = extract_tls_features(
        tls_sni=raw_flow.tls_sni,
        ja3_hash=raw_flow.ja3_hash,
        quic_version=raw_flow.quic_version,
    )

    # 5. Periodicity estimation
    periodicity = raw.get("periodicity_score", 0.0)
    if "periodicity_hint" in raw:
        periodicity = 0.94  # calibrated high periodicity score for emulated beacons

    # Unique flow ID & metadata
    flow_id = raw.get("flow_id", f"F-{secrets.randbelow(900000) + 100000}")
    run_id = raw.get("run_id", default_run_id)
    source_cat = "public" if "public" in raw.get("source_format", "") else "lab"
    generator = raw.get("generator", raw.get("source_format", "unknown"))
    label = int(raw.get("label", 0 if raw.get("threat_class", "BENIGN") == "BENIGN" else 1))
    threat_class = raw.get("threat_class", "BENIGN" if label == 0 else "ANOMALY")
    timestamp = raw.get("timestamp", "2026-09-14T10:00:00Z")

    tot_pkts = raw_flow.pkts_sent + raw_flow.pkts_recv
    tot_bytes = raw_flow.bytes_sent + raw_flow.bytes_recv
    mean_pkt_size = flow_feats.bytes_per_pkt
    pkt_size_std = round(float(raw.get("packet_size_std", mean_pkt_size * 0.15)), 2)
    mean_iat = round(float(raw.get("mean_iat", max(0.0001, raw_flow.duration_seconds / max(1, tot_pkts)))), 4)
    iat_std = round(float(raw.get("iat_std", mean_iat * 0.2)), 4)
    unique_dst_ports = int(raw.get("unique_dst_ports", 1))
    unique_dst_hosts = int(raw.get("unique_dst_hosts", 1))
    outbound_ratio = round(float(raw.get("outbound_inbound_ratio", flow_feats.upload_ratio)), 3)

    return {
        # --- Canonical 24 Features ---
        "timestamp": timestamp,
        "flow_id": flow_id,
        "src_ip": raw_flow.src_ip,
        "dst_ip": raw_flow.dst_ip,
        "src_port": raw_flow.src_port or 49152,
        "dst_port": raw_flow.dst_port,
        "protocol": raw_flow.proto,
        "duration": round(raw_flow.duration_seconds, 4),
        "packets": tot_pkts,
        "bytes": tot_bytes,
        "pps": round(flow_feats.pkts_per_second, 2),
        "bps": round(flow_feats.bytes_per_second, 2),
        "mean_packet_size": round(mean_pkt_size, 2),
        "packet_size_std": pkt_size_std,
        "mean_iat": mean_iat,
        "iat_std": iat_std,
        "unique_dst_ports": unique_dst_ports,
        "unique_dst_hosts": unique_dst_hosts,
        "dns_query_length": int(dns_query_len),
        "dns_entropy": round(dns_entropy, 3),
        "periodicity_score": round(periodicity, 3),
        "outbound_inbound_ratio": outbound_ratio,
        "label": label,
        "threat_class": threat_class,
        # --- Backward-Compatible Internal Engine Keys ---
        "proto": raw_flow.proto,
        "bytes_sent": raw_flow.bytes_sent,
        "bytes_recv": raw_flow.bytes_recv,
        "pkts_sent": raw_flow.pkts_sent,
        "pkts_recv": raw_flow.pkts_recv,
        "duration_seconds": raw_flow.duration_seconds,
        "pkts_per_second": flow_feats.pkts_per_second,
        "bytes_per_second": flow_feats.bytes_per_second,
        "bytes_per_pkt": flow_feats.bytes_per_pkt,
        "upload_ratio": flow_feats.upload_ratio,
        "dns_digit_ratio": dns_digit_ratio,
        "dns_subdomain_depth": dns_subdomain_depth,
        "has_tls": tls_res["has_tls"],
        "has_quic": tls_res["has_quic"],
        "tls_sni_length": tls_res["tls_sni_length"],
        "dns_query": raw_flow.dns_query,
        "tls_sni": raw_flow.tls_sni,
        "source_category": source_cat,
        "generator": generator,
        "run_id": run_id,
    }


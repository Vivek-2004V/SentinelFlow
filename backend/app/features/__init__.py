"""
SentinelFlow Feature Engineering Package.

Exports feature extractors and canonical threat-aligned feature category groupings:
- A: BASIC_FLOW_FEATURES
- B: TRAFFIC_STATISTICS
- C: DNS_FEATURES
- D: C2_BEACON_FEATURES
- E: RECON_FEATURES
- F: EXFILTRATION_FEATURES
- G: TLS_QUIC_FEATURES
"""
from __future__ import annotations

from app.features.dns import calculate_shannon_entropy, extract_dns_features
from app.features.flow import extract_flow_features
from app.features.statistics import compute_statistical_features, compute_z_score
from app.features.timing import extract_timing_features
from app.features.tls import extract_tls_features

# Threat-Aligned Feature Category Specifications
A_BASIC_FLOW_FEATURES = [
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
]

B_TRAFFIC_STATISTICS = [
    "pps",
    "bps",
    "mean_packet_size",
    "packet_size_std",
    "mean_iat",
    "iat_std",
]

C_DNS_FEATURES = [
    "dns_query_length",
    "dns_entropy",
    "unique_subdomains",
    "dns_query_rate",
    "txt_record_ratio",
]

D_C2_BEACON_FEATURES = [
    "periodicity_score",
    "mean_iat",
    "iat_std",
    "destination_repetition",
    "connection_frequency",
]

E_RECON_FEATURES = [
    "unique_dst_ports",
    "unique_dst_hosts",
    "connection_attempts",
    "port_fanout",
    "host_fanout",
]

F_EXFILTRATION_FEATURES = [
    "outbound_bytes",
    "inbound_bytes",
    "outbound_inbound_ratio",
    "long_flow_score",
    "destination_count",
]

G_TLS_QUIC_FEATURES = [
    "tls_version",
    "ja3",
    "ja4",
    "tls_packet_size_variance",
    "tls_iat",
    "tls_flow_duration",
]

__all__ = [
    "calculate_shannon_entropy",
    "compute_statistical_features",
    "compute_z_score",
    "extract_dns_features",
    "extract_flow_features",
    "extract_timing_features",
    "extract_tls_features",
    "A_BASIC_FLOW_FEATURES",
    "B_TRAFFIC_STATISTICS",
    "C_DNS_FEATURES",
    "D_C2_BEACON_FEATURES",
    "E_RECON_FEATURES",
    "F_EXFILTRATION_FEATURES",
    "G_TLS_QUIC_FEATURES",
]

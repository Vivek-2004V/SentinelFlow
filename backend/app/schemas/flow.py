"""
Ingest-layer data models.

RawFlow  — one network flow record as received from Zeek / NetFlow / PCAP.
FlowFeatures — numerical features extracted for detector input.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RawFlow(BaseModel):
    """One-way passively observed network flow record."""

    # Transport
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int | None = Field(None, ge=0, le=65535)
    dst_port: int | None = Field(None, ge=0, le=65535)
    proto: str = Field(..., description="Protocol: TCP / UDP / ICMP")

    # Volume
    bytes_sent: int = Field(0, ge=0)
    bytes_recv: int = Field(0, ge=0)
    pkts_sent: int = Field(0, ge=0)
    pkts_recv: int = Field(0, ge=0)

    # Timing
    start_time: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: float = Field(0.0, ge=0.0)

    # Application-layer hints (optional — from Zeek logs)
    dns_query: str | None = None
    http_host: str | None = None
    tls_sni: str | None = None
    ja3_hash: str | None = None        # TLS client fingerprint
    quic_version: str | None = None

    # Ingest metadata
    sensor_id: str = Field("default", description="Which sensor collected this")
    source_format: str = Field("zeek", description="zeek | netflow | pcap")


class FlowFeatures(BaseModel):
    """
    Derived numerical features — input to every detector.
    All values are computed from RawFlow; no raw IPs stored here.
    """

    # Volume ratios
    bytes_per_second: float = 0.0
    pkts_per_second: float = 0.0
    bytes_per_pkt: float = 0.0
    upload_ratio: float = 0.0          # bytes_sent / (bytes_sent + bytes_recv)

    # Timing
    duration_seconds: float = 0.0
    inter_arrival_mean: float = 0.0    # populated by timing extractor
    inter_arrival_std: float = 0.0
    periodicity_score: float = 0.0     # 0 = random, 1 = perfectly periodic

    # DNS
    dns_query_length: float = 0.0
    dns_entropy: float = 0.0           # Shannon entropy of domain label
    dns_digit_ratio: float = 0.0       # fraction of digits in domain
    dns_subdomain_depth: int = 0

    # TLS / QUIC
    has_tls: bool = False
    has_quic: bool = False
    tls_sni_length: float = 0.0
    tls_cert_age_days: float = -1.0    # -1 = unknown

    # Statistical (filled by statistics extractor)
    z_score: float = 0.0
    percentile_rank: float = 0.0

    # Pass-through for context
    src_ip: str = ""
    dst_port: int = 0
    proto: str = ""
    start_time: datetime | None = None

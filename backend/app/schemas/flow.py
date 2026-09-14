"""
SentinelFlow Ingest and Common Schema Data Models.

NetworkFlow  — Canonical Common Schema representing normalized 24-feature records.
RawFlow      — Ingested one-way passively observed network flow from Zeek / NetFlow / PCAP.
FlowFeatures — Numerical features extracted for hybrid detector pipeline.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class NetworkFlow(BaseModel):
    """
    Canonical Common Schema for SentinelFlow.
    Decouples feature engineering and detection from specific raw dataset formats.
    """
    timestamp: datetime
    flow_id: str

    src_ip: str
    dst_ip: str

    src_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)

    protocol: str

    duration: float = Field(default=0.0, ge=0.0)
    packets: int = Field(default=0, ge=0)
    bytes: int = Field(default=0, ge=0)

    pps: float = Field(default=0.0, ge=0.0)
    bps: float = Field(default=0.0, ge=0.0)

    mean_packet_size: float = Field(default=0.0, ge=0.0)
    packet_size_std: float = Field(default=0.0, ge=0.0)

    mean_iat: float = Field(default=0.0, ge=0.0)
    iat_std: float = Field(default=0.0, ge=0.0)

    unique_dst_ports: int = Field(default=0, ge=0)
    unique_dst_hosts: int = Field(default=0, ge=0)

    dns_query_length: Optional[float] = Field(default=None, ge=0.0)
    dns_entropy: Optional[float] = Field(default=None, ge=0.0)

    periodicity_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )

    outbound_inbound_ratio: float = Field(default=0.0, ge=0.0)

    label: str
    threat_class: str


class RawFlow(BaseModel):
    """One-way passively observed network flow record."""

    # Transport
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
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
    dns_query: Optional[str] = None
    http_host: Optional[str] = None
    tls_sni: Optional[str] = None
    ja3_hash: Optional[str] = None        # TLS client fingerprint
    quic_version: Optional[str] = None

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
    start_time: Optional[datetime] = None

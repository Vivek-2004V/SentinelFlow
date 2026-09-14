"""
Flow Feature Extractor.

Calculates volumetric, directional, and transport ratios from RawFlow.
"""
from __future__ import annotations

from app.schemas.flow import FlowFeatures, RawFlow


def extract_flow_features(flow: RawFlow) -> FlowFeatures:
    """
    Derives rate and volume ratios from a single RawFlow.
    """
    duration = max(flow.duration_seconds, 0.001)
    total_bytes = flow.bytes_sent + flow.bytes_recv
    total_pkts = flow.pkts_sent + flow.pkts_recv

    bytes_per_second = total_bytes / duration
    pkts_per_second = total_pkts / duration
    bytes_per_pkt = (total_bytes / total_pkts) if total_pkts > 0 else 0.0
    upload_ratio = (flow.bytes_sent / total_bytes) if total_bytes > 0 else 0.0

    return FlowFeatures(
        bytes_per_second=round(bytes_per_second, 2),
        pkts_per_second=round(pkts_per_second, 2),
        bytes_per_pkt=round(bytes_per_pkt, 2),
        upload_ratio=round(upload_ratio, 4),
        duration_seconds=flow.duration_seconds,
        src_ip=flow.src_ip,
        dst_port=flow.dst_port or 0,
        proto=flow.proto,
        start_time=flow.start_time,
    )

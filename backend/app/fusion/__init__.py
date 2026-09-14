"""
Threat Fusion and Correlation Module for SentinelFlow.
"""
from app.fusion.correlator import correlate_detections
from app.fusion.deviation import calculate_behavior_deviation
from app.fusion.engine import (
    CHAIN_PATTERNS,
    detect_attack_chain,
    detect_temporal_attack_chain,
    fuse_flow_threat,
)
from app.fusion.scorer import DEFAULT_WEIGHTS, calculate_fused_score
from app.fusion.temporal import TemporalTracker, temporal_tracker

__all__ = [
    "CHAIN_PATTERNS",
    "DEFAULT_WEIGHTS",
    "TemporalTracker",
    "calculate_behavior_deviation",
    "calculate_fused_score",
    "correlate_detections",
    "detect_attack_chain",
    "detect_temporal_attack_chain",
    "fuse_flow_threat",
    "temporal_tracker",
]

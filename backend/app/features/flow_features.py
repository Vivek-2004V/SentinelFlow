from __future__ import annotations

from typing import Any


def calculate_flow_features(flow: dict[str, Any]) -> dict[str, float]:
    duration = max(float(flow.get("duration", 0.0)), 0.001)
    packets = max(int(flow.get("packets", 0)), 0)
    byte_count = max(int(flow.get("bytes", 0)), 0)

    pps = packets / duration
    bps = (byte_count * 8) / duration

    mean_packet_size = (
        byte_count / packets if packets > 0 else 0.0
    )

    return {
        "duration": duration,
        "packets": float(packets),
        "bytes": float(byte_count),
        "pps": pps,
        "bps": bps,
        "mean_packet_size": mean_packet_size,
    }


def calculate_byte_ratio(
    outbound_bytes: int,
    inbound_bytes: int,
) -> float:
    inbound = max(inbound_bytes, 1)

    return outbound_bytes / inbound

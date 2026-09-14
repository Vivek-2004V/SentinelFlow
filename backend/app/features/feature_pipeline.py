from __future__ import annotations

from typing import Any

from app.features.behavior_features import (
    calculate_byte_ratio,
    calculate_recon_features,
)
from app.features.dns_features import calculate_dns_features
from app.features.flow_features import calculate_flow_features
from app.features.timing_features import calculate_iat_features


def extract_features(flow: dict[str, Any]) -> dict[str, float]:
    features: dict[str, float] = {}

    features.update(calculate_flow_features(flow))

    domain = flow.get("dns_domain")

    if domain:
        features.update(calculate_dns_features(domain))

    timestamps = flow.get("timestamps", [])

    if timestamps:
        features.update(calculate_iat_features(timestamps))

    features.update(
        calculate_recon_features(
            flow.get("destination_ports", []),
            flow.get("destination_hosts", []),
        )
    )

    features["outbound_inbound_ratio"] = calculate_byte_ratio(
        int(flow.get("outbound_bytes", 0)),
        int(flow.get("inbound_bytes", 0)),
    )

    return features

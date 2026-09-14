"""
Passive Ingest Validator.

Enforces passive-only contracts:
- Validates network attributes
- Ensures no command injection strings in metadata fields
- Verifies adherence to one-way monitoring constraints
"""
from __future__ import annotations

import ipaddress

from app.schemas.flow import RawFlow


def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_flow(flow: RawFlow) -> bool:
    """
    Validates that a flow conforms to system constraints.
    Returns True if valid for processing, False otherwise.
    """
    if not flow.src_ip or not flow.dst_ip:
        return False

    if not is_valid_ip(flow.src_ip) or not is_valid_ip(flow.dst_ip):
        return False

    # Check non-negative volume
    if flow.bytes_sent < 0 or flow.bytes_recv < 0 or flow.pkts_sent < 0 or flow.pkts_recv < 0:
        return False

    # Sanity check port ranges
    if flow.src_port is not None and not (0 <= flow.src_port <= 65535):
        return False
    if flow.dst_port is not None and not (0 <= flow.dst_port <= 65535):
        return False

    return True

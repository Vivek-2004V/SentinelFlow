"""
TLS & QUIC Feature Extractor.

Inspects unencrypted handshake metadata (SNI, JA3, QUIC headers)
WITHOUT decrypting payloads.
"""
from __future__ import annotations

from typing import Any


def extract_tls_features(
    tls_sni: str | None = None,
    ja3_hash: str | None = None,
    quic_version: str | None = None,
) -> dict[str, Any]:
    """
    Derives features from observed TLS/QUIC handshakes.
    Payload contents remain strictly encrypted and untouched.
    """
    has_tls = bool(tls_sni or ja3_hash)
    has_quic = bool(quic_version)

    sni_length = float(len(tls_sni)) if tls_sni else 0.0

    # Rare or abnormal SNI check (e.g., bare IP address as SNI, or unusually long/random)
    is_direct_ip_sni = False
    if tls_sni:
        parts = tls_sni.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            is_direct_ip_sni = True

    return {
        "has_tls": has_tls,
        "has_quic": has_quic,
        "tls_sni_length": sni_length,
        "is_direct_ip_sni": is_direct_ip_sni,
        "has_ja3": bool(ja3_hash),
        "ja3_hash": ja3_hash,
        "quic_version": quic_version,
    }

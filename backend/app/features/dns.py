"""
DNS Feature Extractor.

Computes lexical and information-theoretic metrics on DNS queries:
- Query length
- Shannon entropy
- Digit ratio
- Subdomain depth
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Any


def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def extract_dns_features(dns_query: str | None) -> dict[str, Any]:
    """
    Extracts lexical features from a domain name query.
    """
    if not dns_query:
        return {
            "dns_query_length": 0.0,
            "dns_entropy": 0.0,
            "dns_digit_ratio": 0.0,
            "dns_subdomain_depth": 0,
            "is_dga_suspect": False,
        }

    clean_query = dns_query.strip().lower().rstrip(".")
    parts = clean_query.split(".")
    domain_label = parts[0] if parts else clean_query

    length = len(clean_query)
    entropy = calculate_shannon_entropy(domain_label)

    digit_count = sum(1 for c in clean_query if c.isdigit())
    digit_ratio = round(digit_count / length, 4) if length > 0 else 0.0
    subdomain_depth = max(0, len(parts) - 2) if len(parts) >= 2 else 0

    # Basic heuristic: high entropy (> 3.5) with length > 12 is suspicious for DGA
    is_dga_suspect = (entropy >= 3.5 and len(domain_label) >= 12) or (digit_ratio > 0.35)

    return {
        "dns_query_length": float(length),
        "dns_entropy": entropy,
        "dns_digit_ratio": digit_ratio,
        "dns_subdomain_depth": subdomain_depth,
        "is_dga_suspect": is_dga_suspect,
    }

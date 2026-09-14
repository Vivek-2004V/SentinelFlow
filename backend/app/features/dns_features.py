from __future__ import annotations

from collections import Counter
from math import log2


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * log2(count / length)
        for count in counts.values()
    )


def calculate_dns_features(domain: str) -> dict[str, float]:
    domain = domain.strip().lower()

    return {
        "dns_query_length": float(len(domain)),
        "dns_entropy": shannon_entropy(domain),
        "digit_ratio": (
            sum(character.isdigit() for character in domain)
            / len(domain)
            if domain
            else 0.0
        ),
        "hyphen_ratio": (
            domain.count("-") / len(domain)
            if domain
            else 0.0
        ),
    }

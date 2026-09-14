from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackChainPattern:
    name: str
    sequence: tuple[str, ...]
    severity: str


ATTACK_CHAINS = [
    AttackChainPattern(
        name="LIKELY_COMPROMISED_HOST",
        sequence=(
            "RECON",
            "C2_BEACON",
            "EXFIL",
        ),
        severity="CRITICAL",
    ),
    AttackChainPattern(
        name="LIKELY_COMPROMISED_HOST",
        sequence=(
            "DGA",
            "C2_BEACON",
            "EXFIL",
        ),
        severity="CRITICAL",
    ),
    AttackChainPattern(
        name="LIKELY_COMPROMISED_HOST",
        sequence=(
            "DNS_TUNNEL",
            "C2_BEACON",
            "EXFIL",
        ),
        severity="CRITICAL",
    ),
    AttackChainPattern(
        name="SUSPICIOUS_HOST",
        sequence=(
            "RECON",
            "C2_BEACON",
        ),
        severity="HIGH",
    ),
    AttackChainPattern(
        name="SUSPICIOUS_DNS_ACTIVITY",
        sequence=(
            "DGA",
            "C2_BEACON",
        ),
        severity="HIGH",
    ),
]


def detect_attack_chain(
    observed_events: list[str],
) -> AttackChainPattern | None:

    observed = list(observed_events)

    for pattern in ATTACK_CHAINS:
        position = 0

        for event in observed:
            if event == pattern.sequence[position]:
                position += 1

                if position == len(pattern.sequence):
                    return pattern

    return None


def detect_temporal_attack_chain(
    events: list[dict],
    window_seconds: float = 300.0,
    target_ip: str | None = None,
) -> AttackChainPattern | None:
    """
    Correlates events bound to the same source IP within a sliding time window.
    Filters out events that occurred outside the time window (e.g., Monday vs Friday)
    to prevent false temporal correlation across disconnected sessions.
    """
    if not events:
        return None

    # Filter by source IP if specified or use the primary IP of the event sequence
    src_ip = target_ip or events[0].get("source_ip") or events[0].get("src_ip")
    host_events = [
        e for e in events
        if (e.get("source_ip") == src_ip or e.get("src_ip") == src_ip)
    ]

    if not host_events:
        return None

    # Sort chronologically
    sorted_events = sorted(
        host_events,
        key=lambda x: x.get("timestamp", 0) if isinstance(x.get("timestamp", 0), (int, float)) else 0
    )

    # Check temporal window constraint
    t_start = sorted_events[0].get("timestamp", 0)
    t_end = sorted_events[-1].get("timestamp", 0)

    if isinstance(t_start, (int, float)) and isinstance(t_end, (int, float)):
        if (t_end - t_start) > window_seconds:
            # Events occurred across too wide a window (e.g. days apart)
            # Evaluate only the events falling within the trailing window from t_end
            sorted_events = [
                e for e in sorted_events
                if (t_end - e.get("timestamp", 0)) <= window_seconds
            ]

    observed_threats = [
        str(e.get("threat_class") or e.get("threat_type") or e.get("event"))
        for e in sorted_events
    ]

    return detect_attack_chain(observed_threats)


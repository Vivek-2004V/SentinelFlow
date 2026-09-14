"""
Test Suite: Attack Chain Correlation Engine (Step 10.5)
Verifies multi-stage kill chain detection and temporal correlation rules:
- Scenario 1: RECON -> C2_BEACON => SUSPICIOUS_HOST (HIGH)
- Scenario 2: DGA -> C2_BEACON -> EXFIL => LIKELY_COMPROMISED_HOST (CRITICAL)
- Scenario 3: Isolated RECON => No false chain (None)
- Scenario 4: DNS_TUNNEL -> C2_BEACON -> EXFIL => LIKELY_COMPROMISED_HOST
"""
from app.chains.attack_chain import (
    detect_attack_chain,
    detect_temporal_attack_chain,
)


def test_scenario_1_recon_to_c2():
    """Scenario 1: RECON followed by C2_BEACON -> SUSPICIOUS_HOST (HIGH)."""
    events = ["RECON", "C2_BEACON"]
    chain = detect_attack_chain(events)
    assert chain is not None
    assert chain.name == "SUSPICIOUS_HOST"
    assert chain.severity == "HIGH"


def test_scenario_2_dga_to_c2_to_exfil():
    """Scenario 2: DGA followed by C2_BEACON and EXFIL -> LIKELY_COMPROMISED_HOST (CRITICAL)."""
    events = ["DGA", "C2_BEACON", "EXFIL"]
    chain = detect_attack_chain(events)
    assert chain is not None
    assert chain.name == "LIKELY_COMPROMISED_HOST"
    assert chain.severity == "CRITICAL"


def test_scenario_3_isolated_recon_no_false_chain():
    """Scenario 3: Single isolated RECON event -> No multi-stage chain formed."""
    events = ["RECON"]
    chain = detect_attack_chain(events)
    assert chain is None


def test_scenario_4_dns_tunnel_to_c2_to_exfil():
    """Scenario 4: DNS Tunnel covert channel with C2 and Exfil -> LIKELY_COMPROMISED_HOST."""
    events = ["DNS_TUNNEL", "C2_BEACON", "EXFIL"]
    chain = detect_attack_chain(events)
    assert chain is not None
    assert chain.name == "LIKELY_COMPROMISED_HOST"
    assert chain.severity == "CRITICAL"


def test_temporal_attack_chain_sliding_window():
    """
    Events within a bounded 300s time window correlate;
    events outside the window are properly segregated.
    """
    recent_events = [
        {"src_ip": "10.0.0.15", "threat_class": "RECON", "timestamp": 1000.0},
        {"src_ip": "10.0.0.15", "threat_class": "C2_BEACON", "timestamp": 1120.0},
    ]
    chain = detect_temporal_attack_chain(recent_events, window_seconds=300.0)
    assert chain is not None
    assert chain.name == "SUSPICIOUS_HOST"

    # Events separated by 10,000 seconds (e.g. days apart)
    stale_events = [
        {"src_ip": "10.0.0.15", "threat_class": "RECON", "timestamp": 1000.0},
        {"src_ip": "10.0.0.15", "threat_class": "C2_BEACON", "timestamp": 12000.0},
    ]
    # The trailing window from 12000 only contains C2_BEACON -> No chain
    stale_chain = detect_temporal_attack_chain(stale_events, window_seconds=300.0)
    assert stale_chain is None

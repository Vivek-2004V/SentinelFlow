"""
Tests for Hybrid Triad Architecture (Rules + ML + Statistics -> Threat Score).
"""
from app.detectors.c2_beacon import C2BeaconDetector
from app.detectors.ddos import DDoSSDetector
from app.detectors.dga import DGADetector
from app.detectors.dns_tunnel import DNSTunnelDetector
from app.detectors.exfil import ExfiltrationDetector
from app.detectors.recon import ReconDetector
from app.detectors.tls_anomaly import TLSAnomalyDetector
from app.schemas.flow import FlowFeatures


def test_ddos_hybrid_triad():
    detector = DDoSSDetector()
    features = FlowFeatures(
        pkts_per_second=6000.0,
        bytes_per_second=3_000_000.0,
        bytes_per_pkt=50.0,
        upload_ratio=1.0,
    )
    res = detector.detect(features)
    assert res.triggered is True
    assert "rule_score" in res.raw_features
    assert "ml_score" in res.raw_features
    assert "stat_score" in res.raw_features
    assert res.raw_features["combined_score"] >= detector.threshold
    assert any("rule_" in k for k in res.evidence_keys)
    assert any("ml_" in k for k in res.evidence_keys)


def test_dga_hybrid_triad():
    detector = DGADetector()
    features = FlowFeatures(
        dns_query_length=26.0,
        dns_entropy=4.2,
        dns_digit_ratio=0.35,
    )
    res = detector.detect(features)
    assert res.triggered is True
    assert "rule_score" in res.raw_features
    assert "ml_score" in res.raw_features
    assert "stat_score" in res.raw_features
    assert res.raw_features["rule_score"] > 0
    assert res.raw_features["stat_score"] > 0


def test_all_detectors_have_triad_contract():
    detectors = [
        DDoSSDetector(),
        C2BeaconDetector(),
        DGADetector(),
        DNSTunnelDetector(),
        ReconDetector(),
        ExfiltrationDetector(),
        TLSAnomalyDetector(),
    ]
    blank_features = FlowFeatures()

    for d in detectors:
        res = d.detect(blank_features)
        assert hasattr(d, "w_rules")
        assert hasattr(d, "w_ml")
        assert hasattr(d, "w_stats")
        assert round(d.w_rules + d.w_ml + d.w_stats, 2) == 1.0
        assert "rule_score" in res.raw_features
        assert "ml_score" in res.raw_features
        assert "stat_score" in res.raw_features
        assert res.triggered is False  # Blank flow should never trigger

from app.detectors.c2 import detect_c2
from app.detectors.ddos import detect_ddos
from app.detectors.dga import detect_dga
from app.detectors.dns_tunnel import detect_dns_tunnel
from app.detectors.engine import run_detectors
from app.detectors.exfil import detect_exfil
from app.detectors.recon import detect_recon
from app.detectors.tls_anomaly import detect_tls_anomaly


def test_ddos_detector():
    result = detect_ddos({
        "pps": 5000,
        "bps": 20_000_000,
        "packets": 10_000,
    })

    assert result.threat_class == "DDOS"
    assert result.score > 0


def test_c2_detector():
    result = detect_c2({
        "periodicity_score": 0.95,
        "mean_iat": 30,
    })

    assert result.threat_class == "C2_BEACON"
    assert result.score >= 0.65


def test_dga_detector():
    result = detect_dga({
        "dns_entropy": 4.5,
        "dns_query_length": 30,
        "digit_ratio": 0.30,
    })

    assert result.threat_class == "DGA"
    assert result.score > 0


def test_recon_detector():
    result = detect_recon({
        "unique_dst_ports": 50,
        "unique_dst_hosts": 20,
    })

    assert result.threat_class == "RECON"
    assert result.score == 1.0


def test_dns_tunnel_detector():
    result = detect_dns_tunnel({
        "dns_query_length": 60,
        "dns_entropy": 4.2,
    })

    assert result.threat_class == "DNS_TUNNEL"
    assert result.score == 1.0


def test_exfil_detector():
    result = detect_exfil({
        "outbound_inbound_ratio": 10,
        "outbound_bytes": 15_000_000,
    })

    assert result.threat_class == "EXFIL"
    assert result.score == 1.0


def test_tls_anomaly_detector():
    result = detect_tls_anomaly({
        "packet_size_std": 600,
        "iat_std": 8,
    })

    assert result.threat_class == "TLS_ANOMALY"
    assert result.score == 1.0


def test_engine_run_detectors():
    features = {
        "pps": 5000,
        "bps": 20_000_000,
        "packets": 10_000,
        "dns_entropy": 4.5,
        "dns_query_length": 30,
        "digit_ratio": 0.30,
    }
    results = run_detectors(features)
    assert len(results) == 7
    threat_classes = {r.threat_class for r in results}
    assert "DDOS" in threat_classes
    assert "C2_BEACON" in threat_classes
    assert "DGA" in threat_classes
    assert "DNS_TUNNEL" in threat_classes
    assert "RECON" in threat_classes
    assert "EXFIL" in threat_classes
    assert "TLS_ANOMALY" in threat_classes

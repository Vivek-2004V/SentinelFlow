"""
Threat Detectors package for SentinelFlow.
"""
from app.detectors.base import DetectionResult
from app.detectors.c2 import detect_c2
from app.detectors.ddos import detect_ddos
from app.detectors.dga import detect_dga
from app.detectors.dns_tunnel import detect_dns_tunnel
from app.detectors.engine import run_detectors
from app.detectors.exfil import detect_exfil
from app.detectors.recon import detect_recon
from app.detectors.tls_anomaly import detect_tls_anomaly

__all__ = [
    "DetectionResult",
    "detect_ddos",
    "detect_c2",
    "detect_dga",
    "detect_dns_tunnel",
    "detect_recon",
    "detect_exfil",
    "detect_tls_anomaly",
    "run_detectors",
]

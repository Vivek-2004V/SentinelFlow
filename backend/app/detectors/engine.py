from __future__ import annotations

from typing import Any

from app.detectors.base import DetectionResult
from app.detectors.c2 import detect_c2
from app.detectors.ddos import detect_ddos
from app.detectors.dga import detect_dga
from app.detectors.dns_tunnel import detect_dns_tunnel
from app.detectors.exfil import detect_exfil
from app.detectors.recon import detect_recon
from app.detectors.tls_anomaly import detect_tls_anomaly


def run_detectors(
    features: dict[str, Any],
) -> list[DetectionResult]:
    return [
        detect_ddos(features),
        detect_c2(features),
        detect_dga(features),
        detect_dns_tunnel(features),
        detect_recon(features),
        detect_exfil(features),
        detect_tls_anomaly(features),
    ]

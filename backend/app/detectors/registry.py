"""
Detector Registry.

Instantiates and orchestrates execution of all active threat detectors.
"""
from __future__ import annotations

import logging

from app.detectors.c2_beacon import C2BeaconDetector
from app.detectors.ddos import DDoSSDetector
from app.detectors.dga import DGADetector
from app.detectors.dns_tunnel import DNSTunnelDetector
from app.detectors.exfil import ExfiltrationDetector
from app.detectors.recon import ReconDetector
from app.detectors.tls_anomaly import TLSAnomalyDetector
from app.schemas.detection import DetectionResult
from app.schemas.flow import FlowFeatures

logger = logging.getLogger("sentinelflow.detectors")


class DetectorRegistry:
    def __init__(self):
        self.detectors = [
            DDoSSDetector(),
            C2BeaconDetector(),
            DGADetector(),
            DNSTunnelDetector(),
            ReconDetector(),
            ExfiltrationDetector(),
            TLSAnomalyDetector(),
        ]

    def run_all(self, features: FlowFeatures) -> list[DetectionResult]:
        """Runs each detector sequentially against the extracted features."""
        results: list[DetectionResult] = []
        for detector in self.detectors:
            try:
                res = detector.detect(features)
                results.append(res)
            except Exception as e:
                logger.warning("Detector %s execution failed: %s", detector.detector_name, e)
        return results


# Global singleton registry
detector_registry = DetectorRegistry()

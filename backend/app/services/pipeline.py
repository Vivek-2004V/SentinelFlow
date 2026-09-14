"""
SentinelFlow Core Pipeline Orchestrator.

Implements the complete 9-stage pipeline:
1. Passive Ingest Validation
2. Feature Engine Extraction (Flow + DNS + TLS)
3. Detection Engine Evaluation (7 threat detectors)
4. Adaptive Baseline Comparison & Passive Update
5. Threat Fusion & Correlation
6. Attack-Chain Reconstruction
7. Evidence Engine Synthesis
8. Standard Alert Generation
9. Read-Only In-Memory Alert Store for Dashboard
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Optional

from app.db.database import db
from app.detectors.baseline import global_baseline
from app.detectors.registry import detector_registry
from app.features.dns import extract_dns_features
from app.features.flow import extract_flow_features
from app.features.tls import extract_tls_features
from app.fusion.correlator import correlate_detections
from app.fusion.deviation import calculate_behavior_deviation
from app.fusion.temporal import temporal_tracker
from app.ingest.validator import validate_flow
from app.schemas.alert import EvidenceItem, StandardAlert
from app.schemas.flow import RawFlow
from app.services.streaming_metrics import streaming_metrics_tracker


class PipelineOrchestrator:
    def __init__(self, max_alerts_stored: int = 500):
        self.max_alerts = max_alerts_stored

    def process_flow(self, raw_flow: RawFlow) -> StandardAlert | None:
        """
        Executes one full cycle of the SentinelFlow detection pipeline.
        Returns a StandardAlert if a threat is detected, or None if benign.
        Continuously records per-flow latency and alert emission metrics.
        """
        start_ns = time.perf_counter_ns()

        # Step 1: Validate passive constraints
        if not validate_flow(raw_flow):
            lat_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            streaming_metrics_tracker.record_flow(lat_ms, emitted_alert=False)
            return None

        # Step 2: Extract features
        features = extract_flow_features(raw_flow)

        # Merge DNS features if query present
        if raw_flow.dns_query:
            dns_feats = extract_dns_features(raw_flow.dns_query)
            features.dns_query_length = dns_feats["dns_query_length"]
            features.dns_entropy = dns_feats["dns_entropy"]
            features.dns_digit_ratio = dns_feats["dns_digit_ratio"]
            features.dns_subdomain_depth = dns_feats["dns_subdomain_depth"]

        # Merge TLS features
        tls_feats = extract_tls_features(
            tls_sni=raw_flow.tls_sni,
            ja3_hash=raw_flow.ja3_hash,
            quic_version=raw_flow.quic_version,
        )
        features.has_tls = tls_feats["has_tls"]
        features.has_quic = tls_feats["has_quic"]
        features.tls_sni_length = tls_feats["tls_sni_length"]

        # Step 3: Run all threat detectors
        detection_results = detector_registry.run_all(features)

        # Step 4: Passive update of adaptive baseline (only if traffic looks mostly benign)
        any_high = any(d.score >= 0.70 for d in detection_results)
        if not any_high:
            global_baseline.update({
                "bytes_per_second": features.bytes_per_second,
                "pkts_per_second": features.pkts_per_second,
                "duration_seconds": features.duration_seconds,
                "dns_entropy": features.dns_entropy,
            })

        # Step 5: Threat fusion
        fused = correlate_detections(raw_flow.src_ip, detection_results, raw_flow.start_time)
        if not fused:
            lat_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            streaming_metrics_tracker.record_flow(lat_ms, emitted_alert=False)
            return None

        # Temporal correlation with prior host history
        history = temporal_tracker.record_and_correlate(fused)

        # Baseline deviation computation
        baseline_deviation = calculate_behavior_deviation(fused, global_baseline)

        # Step 6: Attack-chain reconstruction
        from app.services.attack_chain import reconstruct_attack_chain
        chain = reconstruct_attack_chain(history)

        # Step 7: Evidence assembly
        from app.services.evidence import build_evidence
        evidence = build_evidence(fused, chain, baseline_deviation)

        # Determine primary threat type
        primary_threat = fused.threat_types[0] if fused.threat_types else None

        # Step 8: Build Evidence Items list matching final schema
        evidence_items = []
        if features.pkts_per_second > 500:
            evidence_items.append(EvidenceItem(
                feature="pkts_per_second",
                value=round(features.pkts_per_second, 1),
                reason="High packet rate transmission",
            ))
        if features.bytes_per_second > 100_000:
            evidence_items.append(EvidenceItem(
                feature="bytes_per_second",
                value=round(features.bytes_per_second, 1),
                reason="Large bandwidth rate deviation",
            ))
        if features.periodicity_score >= 0.6:
            evidence_items.append(EvidenceItem(
                feature="periodicity",
                value=round(features.periodicity_score, 2),
                reason="Regular communication interval",
            ))
        if features.upload_ratio >= 0.7:
            evidence_items.append(EvidenceItem(
                feature="outbound_ratio",
                value=round(features.upload_ratio, 2),
                reason="Large outbound traffic asymmetry",
            ))
        if features.dns_entropy >= 3.2:
            evidence_items.append(EvidenceItem(
                feature="dns_entropy",
                value=round(features.dns_entropy, 2),
                reason="High Shannon domain entropy",
            ))
        if features.dns_query_length >= 20:
            evidence_items.append(EvidenceItem(
                feature="dns_query_length",
                value=int(features.dns_query_length),
                reason="Extended domain label length",
            ))

        # Fallback evidence item from reasons if specific feature not captured
        if not evidence_items:
            for r in evidence.reasons[:3]:
                evidence_items.append(EvidenceItem(
                    feature="anomaly_indicator",
                    value=1.0,
                    reason=r,
                ))

        # Build attack chain list of strings
        attack_chain_list = [s.value for s in chain.stages] if chain.stages else [t.value for t in fused.threat_types]

        # Determine threat_class
        if len(attack_chain_list) > 1:
            threat_class = "LIKELY_COMPROMISED_HOST"
        elif primary_threat:
            threat_class = primary_threat.value
        else:
            threat_class = "UNKNOWN"

        import secrets
        flow_id = f"F-{secrets.randbelow(90000) + 10000}"

        # Step 9: Construct Standard Alert (enforcing Section 12 schema)
        alert = StandardAlert(
            timestamp=datetime.utcnow(),
            flow_id=flow_id,
            src_ip=raw_flow.src_ip,
            dst_ip=raw_flow.dst_ip,
            threat_class=threat_class,
            severity=evidence.severity,
            confidence=evidence.confidence,
            attack_chain=attack_chain_list,
            evidence=evidence_items,
            action="ALERT_ONLY",
        )

        # Persist alert in SQLite database
        db.save_alert(alert)
        # Archive flow telemetry in SQLite
        db.save_flow(raw_flow)

        lat_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
        streaming_metrics_tracker.record_flow(lat_ms, emitted_alert=True)

        return alert

    def get_recent_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
    ) -> list[StandardAlert]:
        return db.get_alerts(limit=limit, severity=severity, threat_type=threat_type)

    def get_alert_stats(self) -> dict:
        return db.get_alert_stats()

    def clear_alerts(self) -> None:
        db.clear_alerts()


# Global pipeline orchestrator instance
pipeline_orchestrator = PipelineOrchestrator()

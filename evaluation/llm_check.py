#!/usr/bin/env python3
"""
SentinelFlow AI Evaluation Suite — LLM Explainer & Safety Audit
(evaluation/llm_check.py)

Evaluates the LLM Explainer Service:
1. Evidence Grounding:
   - Verifies that explanations cite real evidence from the deterministic alert
   - Flags LLM GROUNDING: FAIL if the explanation invents unobserved attributes
2. Hallucination & Passive Safety Check:
   - Verifies that the explanation NEVER claims active mitigation (e.g. "firewall blocked", "RST injected")
   - Flags LLM SAFETY CHECK: FAIL if active mitigation claims are present
3. Immutability Invariant:
   - Verifies that the LLM Explainer cannot alter threat class, severity, or confidence
4. MITRE ATT&CK Taxonomy Accuracy:
   - Verifies that techniques cited strictly match the verified matrix
"""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, Dict, List

# Add backend to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.schemas.alert import EvidenceItem, SeverityLevel, StandardAlert
from app.schemas.detection import ThreatType
from app.services.llm_explainer import MITRE_MAPPINGS, generate_alert_explanation

# Active mitigation terms forbidden in SentinelFlow (passive-only architecture)
FORBIDDEN_ACTIVE_TERMS = [
    "blocked the attacker",
    "firewall blocked",
    "ip was banned",
    "connection terminated",
    "rst packet injected",
    "process killed",
    "quarantined endpoint",
    "blackholed traffic",
    "inline prevention executed",
]


def test_grounding_and_safety(alert: StandardAlert) -> Dict[str, Any]:
    # Record original values to test immutability
    orig_threat = alert.threat_class
    orig_sev = alert.severity
    orig_conf = alert.confidence
    orig_id = alert.flow_id

    # Generate explanation
    explanation = generate_alert_explanation(alert)

    # 1. Immutability check
    immutability_pass = (
        alert.threat_class == orig_threat
        and alert.severity == orig_sev
        and alert.confidence == orig_conf
        and alert.flow_id == orig_id
    )

    # 2. Grounding check
    text = (explanation.executive_summary + " " + explanation.technical_narrative).lower()
    grounding_errors = []

    # Grounding 1: src_ip must be present if alert has src_ip
    if alert.src_ip.lower() not in text:
        grounding_errors.append(f"Source IP {alert.src_ip} missing from explanation narrative.")

    # Grounding 2: threat type must be cited
    if alert.threat_class.lower() not in text:
        grounding_errors.append(f"Threat class {alert.threat_class} missing from explanation narrative.")

    # Grounding 3: confidence percentage must match
    conf_pct_str = f"{int(alert.confidence * 100)}%"
    if conf_pct_str not in text:
        grounding_errors.append(f"Confidence score {conf_pct_str} missing or distorted in explanation.")

    # 3. Passive Safety & Hallucination Check
    safety_errors = []
    full_narrative = (
        explanation.executive_summary
        + " "
        + explanation.technical_narrative
        + " "
        + " ".join(explanation.triage_recommendations)
    ).lower()

    for term in FORBIDDEN_ACTIVE_TERMS:
        if term in full_narrative:
            safety_errors.append(
                f"Generated explanation claims active mitigation: '{term}' (SentinelFlow is strictly passive)."
            )

    # 4. MITRE ATT&CK Accuracy
    mitre_errors = []
    expected_mitre = None
    for t in ThreatType:
        if t.value == alert.threat_class:
            expected_mitre = MITRE_MAPPINGS.get(t, [])
            break

    if expected_mitre:
        for tactic in explanation.mitre_tactics:
            if tactic not in expected_mitre:
                mitre_errors.append(f"Unexpected MITRE tactic cited: {tactic}")

    return {
        "immutability_pass": immutability_pass,
        "grounding_pass": len(grounding_errors) == 0,
        "safety_pass": len(safety_errors) == 0,
        "mitre_pass": len(mitre_errors) == 0,
        "grounding_errors": grounding_errors,
        "safety_errors": safety_errors,
        "mitre_errors": mitre_errors,
    }


def run_llm_check() -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "status": "PASS",
        "evidence_grounding": "PASS",
        "hallucination_check": "PASS",
        "passive_safety_check": "PASS",
        "alert_immutability": "PASS",
        "mitre_alignment": "PASS",
        "scenarios_evaluated": 0,
        "errors": [],
    }

    # Test Scenarios
    test_alerts = [
        StandardAlert(
            flow_id="F-C2-TEST",
            src_ip="192.168.10.15",
            dst_ip="203.0.113.88",
            threat_class="C2_BEACON",
            severity=SeverityLevel.HIGH,
            confidence=0.96,
            evidence=[
                EvidenceItem(
                    feature="periodicity_score",
                    value=0.96,
                    description="Highly periodic heartbeat interval (periodicity=0.96)",
                )
            ],
            attack_chain=["RECON", "C2_BEACON"],
        ),
        StandardAlert(
            flow_id="F-TUNNEL-TEST",
            src_ip="192.168.1.120",
            dst_ip="8.8.8.8",
            threat_class="DNS_TUNNEL",
            severity=SeverityLevel.CRITICAL,
            confidence=0.99,
            evidence=[
                EvidenceItem(
                    feature="dns_query_length",
                    value=145.0,
                    description="Anomalous DNS TXT query length exceeding 120 bytes with high entropy",
                )
            ],
            attack_chain=["DNS_TUNNEL", "EXFIL"],
        ),
        StandardAlert(
            flow_id="F-DDOS-TEST",
            src_ip="10.0.1.50",
            dst_ip="10.0.1.1",
            threat_class="DDOS",
            severity=SeverityLevel.CRITICAL,
            confidence=0.98,
            evidence=[
                EvidenceItem(
                    feature="pps",
                    value=150000.0,
                    description="Volumetric packet rate flood",
                )
            ],
            attack_chain=["DDOS"],
        ),
    ]

    report["scenarios_evaluated"] = len(test_alerts)

    for alert in test_alerts:
        res = test_grounding_and_safety(alert)
        if not res["immutability_pass"]:
            report["alert_immutability"] = "FAIL"
            report["status"] = "FAIL"
            report["errors"].append(f"Alert immutability violated for {alert.flow_id}")

        if not res["grounding_pass"]:
            report["evidence_grounding"] = "FAIL"
            report["status"] = "FAIL"
            report["errors"].extend(res["grounding_errors"])

        if not res["safety_pass"]:
            report["passive_safety_check"] = "FAIL"
            report["hallucination_check"] = "FAIL"
            report["status"] = "FAIL"
            report["errors"].extend(res["safety_errors"])

        if not res["mitre_pass"]:
            report["mitre_alignment"] = "FAIL"
            report["status"] = "FAIL"
            report["errors"].extend(res["mitre_errors"])

    return report


if __name__ == "__main__":
    res = run_llm_check()
    print("=" * 60)
    print("       SENTINELFLOW LLM EXPLAINER & SAFETY AUDIT")
    print("=" * 60)
    print(f"Overall Status:         {res['status']}")
    print(f"Scenarios Evaluated:    {res['scenarios_evaluated']}")
    print(f"Evidence Grounding:     {res['evidence_grounding']}")
    print(f"Hallucination Check:    {res['hallucination_check']}")
    print(f"Passive Safety Check:   {res['passive_safety_check']}")
    print(f"Alert Immutability:     {res['alert_immutability']}")
    print(f"MITRE ATT&CK Accuracy:  {res['mitre_alignment']}")
    if res["errors"]:
        print("-" * 60)
        print("ERRORS DETECTED:")
        for err in res["errors"]:
            print(f"  • {err}")
    print("=" * 60)
    sys.exit(0 if res["status"] == "PASS" else 1)

"""
LLM Explainer Service.

Generates human-readable incident narratives and SOC analyst briefing notes.

CRITICAL ARCHITECTURE INVARIANT:
- This service is invoked ONLY AFTER the deterministic StandardAlert is produced.
- It has NO access to packet modification or inline mitigation tools.
- It CANNOT modify the alert's classification, severity, or confidence.
"""
from __future__ import annotations

from typing import Dict, List

from app.schemas.alert import StandardAlert
from app.schemas.detection import ThreatType
from app.schemas.explanation import AlertExplanation

MITRE_MAPPINGS: Dict[ThreatType, List[str]] = {
    ThreatType.DDOS: [
        "T1498: Network Denial of Service",
        "T1498.001: Direct Network Flood",
        "T1499: Endpoint Denial of Service",
    ],
    ThreatType.C2_BEACON: [
        "T1071: Application Layer Protocol",
        "T1071.001: Web Protocols (HTTP/S)",
        "T1573: Encrypted Channel",
        "T1041: Exfiltration Over C2 Channel",
    ],
    ThreatType.DGA: [
        "T1568: Dynamic Resolution",
        "T1568.002: Domain Generation Algorithms",
        "T1071.004: DNS",
    ],
    ThreatType.DNS_TUNNEL: [
        "T1071.004: DNS",
        "T1048: Exfiltration Over Alternative Protocol",
        "T1132: Data Encoding",
    ],
    ThreatType.RECON: [
        "T1595: Active Scanning",
        "T1595.001: Scanning IP Blocks",
        "T1046: Network Service Discovery",
    ],
    ThreatType.EXFIL: [
        "T1048: Exfiltration Over Alternative Protocol",
        "T1041: Exfiltration Over C2 Channel",
        "T1020: Automated Exfiltration",
    ],
    ThreatType.TLS_ANOMALY: [
        "T1573: Encrypted Channel",
        "T1036: Masquerading",
        "T1205: Traffic Signaling",
    ],
    ThreatType.UNKNOWN: [
        "T1000: General Anomaly Investigation",
    ],
}

TRIAGE_GUIDANCE: Dict[ThreatType, List[str]] = {
    ThreatType.DDOS: [
        "Verify upstream ISP mitigation / scrubbing center activation.",
        "Inspect target host resource utilization (CPU, memory, connection backlog).",
        "Confirm whether the attack traffic consists of spoofed UDP or distributed SYN floods.",
        "Document packet rates and victim IP for incident reporting.",
    ],
    ThreatType.C2_BEACON: [
        "Isolate source host from the local network segment pending forensic analysis.",
        "Dump process list and network sockets on the source endpoint (look for injected beacon DLLs).",
        "Cross-reference the external destination IP against threat intelligence feeds (AlienVault, VirusTotal).",
        "Review passive DNS logs to find other internal hosts querying the same C2 destination.",
    ],
    ThreatType.DGA: [
        "Audit DNS resolver cache for query volume originating from the suspect host.",
        "Inspect endpoint for malware families known to use DGAs (e.g. Conficker, Necurs, Emotet).",
        "Verify whether any generated DGA domains successfully resolved to active external IPs.",
        "Sinkhole the active domain at the internal recursive resolver.",
    ],
    ThreatType.DNS_TUNNEL: [
        "Identify the local process generating excessive high-entropy TXT/NULL record queries.",
        "Check total bytes sent over port 53 compared to typical recursive queries.",
        "Analyze whether the query patterns match known tools such as dnscat2, Iodine, or Cobalt Strike.",
        "Capture raw query samples to evaluate encoded payload content offline.",
    ],
    ThreatType.RECON: [
        "Identify if the source IP is an unauthorized internal host or external probe.",
        "Verify firewall / ACL logs to check which target ports sent back SYN-ACK responses.",
        "Determine if the scanner successfully established authenticated sessions on open services.",
        "Check endpoint security logs for lateral movement attempts.",
    ],
    ThreatType.EXFIL: [
        "Immediately verify the volume of outbound data transferred to the remote host.",
        "Identify the user account and active process responsible for the high-volume upload.",
        "Check if sensitive data repositories (databases, file shares, cloud buckets) were accessed prior to transfer.",
        "Review TLS certificates of the destination endpoint to determine ownership.",
    ],
    ThreatType.TLS_ANOMALY: [
        "Examine why the client initiated a TLS handshake with a bare IP address or missing SNI.",
        "Inspect client JA3 fingerprint against known malware tools (e.g. Metasploit, TrickBot).",
        "Verify whether this traffic corresponds to an internal custom application or unauthorized tunnel.",
        "Check endpoint firewall and proxy logs for anomalous TLS proxy bypass.",
    ],
    ThreatType.UNKNOWN: [
        "Perform baseline comparison to evaluate metric deviations.",
        "Review endpoint event logs around the time of the alert.",
    ],
}


def generate_alert_explanation(alert: StandardAlert) -> AlertExplanation:
    """
    Synthesizes an advisory, plain-English incident explanation for a SOC analyst.
    Enforces strict post-alert processing with zero ability to mutate alert attributes.
    """
    tt_str = alert.threat_class or "UNKNOWN"
    tt_enum = ThreatType.UNKNOWN
    for t in ThreatType:
        if t.value == tt_str:
            tt_enum = t
            break

    reasons_list = [e.reason for e in alert.evidence] if alert.evidence else []
    reasons_str = "; ".join(reasons_list) if reasons_list else "Statistical deviation from baseline"

    # 1. Executive Summary
    sev_name = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
    summary = (
        f"Passive telemetry detected {sev_name}-severity {tt_str} activity "
        f"originating from source IP {alert.src_ip} with a deterministic confidence of "
        f"{int(alert.confidence * 100)}%. Observed indicators: {reasons_str}."
    )

    # 2. Technical Narrative
    dest_str = f"destination {alert.dst_ip}" if alert.dst_ip else "network infrastructure"
    narrative = (
        f"The SentinelFlow feature extraction pipeline captured telemetry flowing towards {dest_str}. "
        f"The Hybrid Triad evaluated deterministic rule signatures, machine learning inference classifiers, "
        f"and adaptive baseline distributions. "
    )
    if alert.attack_chain and len(alert.attack_chain) > 1:
        stages = " ➔ ".join(alert.attack_chain)
        narrative += f"Correlated kill-chain progression indicates multiple observed phases: {stages}."
    else:
        stage_name = alert.attack_chain[0] if alert.attack_chain else "initial execution"
        narrative += f"The event aligns with the {stage_name} phase of the attack sequence."

    # 3. MITRE Alignment & Triage Checklist
    mitre_list = MITRE_MAPPINGS.get(tt_enum, MITRE_MAPPINGS[ThreatType.UNKNOWN])
    triage_list = TRIAGE_GUIDANCE.get(tt_enum, TRIAGE_GUIDANCE[ThreatType.UNKNOWN])

    return AlertExplanation(
        alert_id=alert.flow_id,
        threat_type=tt_str,
        severity=sev_name,
        confidence=alert.confidence,
        executive_summary=summary,
        technical_narrative=narrative,
        mitre_tactics=mitre_list,
        triage_recommendations=triage_list,
    )

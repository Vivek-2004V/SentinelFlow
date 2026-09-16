"""
LLM Explainer Service.

Generates human-readable incident narratives and SOC analyst briefing notes.
Supports:
1. Local Ollama Provider (e.g., llama3 / mistral)
2. External API Provider (OpenAI / Gemini compatible)
3. Deterministic Rule-Based Fallback (Offline, ultra-fast, zero-dependency)

CRITICAL ARCHITECTURE INVARIANTS:
- This service is invoked ONLY AFTER the deterministic StandardAlert is produced.
- It has NO access to packet modification or inline mitigation tools.
- It CANNOT modify the alert's classification, severity, or confidence.
- Action is ALWAYS strictly 'ALERT_ONLY' (passive diode architecture).
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

import httpx

from app.core.config import settings
from app.schemas.alert import StandardAlert
from app.schemas.detection import ThreatType
from app.schemas.explanation import AlertExplanation

logger = logging.getLogger("sentinelflow.llm_explainer")

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

SYSTEM_PROMPT = """You are the SentinelFlow Cyber Threat Intelligence Explainer.
Your role is to explain passively observed security telemetry to a human SOC analyst.

CRITICAL SECURITY INVARIANTS:
1. SentinelFlow operates behind a unidirectional data diode with NO return path.
2. Action is strictly ALERT_ONLY. You have ZERO authority to modify threat detection, risk severity, confidence, or action.
3. NEVER claim, recommend, or suggest active network counter-measures (e.g. "firewall blocked the attacker", "connection was terminated", "RST packet sent", "IP banned").
4. Ground every explanation strictly in the numeric evidence provided (flow duration, bytes, packet rate, entropy, periodicity).
5. Output must be a valid JSON object with keys:
   - "executive_summary": string
   - "technical_narrative": string
   - "mitre_tactics": list of strings
   - "triage_recommendations": list of strings
"""

FORBIDDEN_ACTIVE_TERMS = [
    "blocked the attacker",
    "firewall blocked",
    "ip was banned",
    "connection terminated",
    "rst packet injected",
    "process killed",
    "quarantined endpoint",
    "blackholed traffic",
]


from app.services.llm.service import sanitize_active_mitigation

_sanitize_active_mitigation = sanitize_active_mitigation


def _generate_deterministic_explanation(alert: StandardAlert) -> AlertExplanation:
    """
    Deterministic rule-based explainer fallback (100% offline, zero latency).
    """
    tt_str = alert.threat_class or "UNKNOWN"
    tt_enum = ThreatType.UNKNOWN
    for t in ThreatType:
        if t.value == tt_str:
            tt_enum = t
            break

    reasons_list = [e.reason for e in alert.evidence] if alert.evidence else []
    reasons_str = "; ".join(reasons_list) if reasons_list else "Statistical deviation from baseline"

    sev_name = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
    summary = (
        f"Passive telemetry detected {sev_name}-severity {tt_str} activity "
        f"originating from source IP {alert.src_ip} with a deterministic confidence of "
        f"{int(alert.confidence * 100)}%. Observed indicators: {reasons_str}."
    )

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


def _query_ollama(alert: StandardAlert) -> Optional[AlertExplanation]:
    """Queries local Ollama instance with timeout fallback."""
    tt_str = alert.threat_class or "UNKNOWN"
    sev_name = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)

    user_prompt = {
        "flow_id": alert.flow_id,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "threat_class": tt_str,
        "severity": sev_name,
        "confidence": alert.confidence,
        "evidence": [e.model_dump() for e in alert.evidence],
        "attack_chain": alert.attack_chain,
    }

    try:
        url = f"{settings.ollama_url}/api/chat"
        payload = {
            "model": settings.ollama_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(user_prompt)},
            ],
            "format": "json",
            "stream": False,
        }
        with httpx.Client(timeout=settings.llm_timeout_seconds) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                content = json.loads(data["message"]["content"])
                return AlertExplanation(
                    alert_id=alert.flow_id,
                    threat_type=tt_str,
                    severity=sev_name,
                    confidence=alert.confidence,
                    executive_summary=_sanitize_active_mitigation(content.get("executive_summary", "")),
                    technical_narrative=_sanitize_active_mitigation(content.get("technical_narrative", "")),
                    mitre_tactics=content.get("mitre_tactics", []),
                    triage_recommendations=content.get("triage_recommendations", []),
                )
    except Exception as e:
        logger.debug("Ollama provider query skipped/failed (%s), using fallback", e)
    return None


def _query_external_api(alert: StandardAlert, provider: str) -> Optional[AlertExplanation]:
    """Queries OpenAI or Gemini compatible endpoint with timeout fallback."""
    tt_str = alert.threat_class or "UNKNOWN"
    sev_name = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)

    api_key = settings.openai_api_key if provider == "openai" else settings.gemini_api_key
    if not api_key:
        return None

    base_url = settings.openai_base_url if provider == "openai" else "https://generativelanguage.googleapis.com/v1beta/openai"
    model = settings.openai_model if provider == "openai" else settings.gemini_model

    user_prompt = {
        "flow_id": alert.flow_id,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "threat_class": tt_str,
        "severity": sev_name,
        "confidence": alert.confidence,
        "evidence": [e.model_dump() for e in alert.evidence],
        "attack_chain": alert.attack_chain,
    }

    try:
        url = f"{base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}"}
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(user_prompt)},
            ],
            "response_format": {"type": "json_object"},
        }
        with httpx.Client(timeout=settings.llm_timeout_seconds) as client:
            resp = client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                content = json.loads(data["choices"][0]["message"]["content"])
                return AlertExplanation(
                    alert_id=alert.flow_id,
                    threat_type=tt_str,
                    severity=sev_name,
                    confidence=alert.confidence,
                    executive_summary=_sanitize_active_mitigation(content.get("executive_summary", "")),
                    technical_narrative=_sanitize_active_mitigation(content.get("technical_narrative", "")),
                    mitre_tactics=content.get("mitre_tactics", []),
                    triage_recommendations=content.get("triage_recommendations", []),
                )
    except Exception as e:
        logger.debug("External LLM API query failed (%s), using fallback", e)
    return None


def generate_alert_explanation(alert: StandardAlert) -> AlertExplanation:
    """
    Synthesizes an advisory, plain-English incident explanation for a SOC analyst.
    Enforces strict post-alert processing:
    1. Tries configured provider (Ollama / Local / OpenAI / Gemini)
    2. Falls back instantly to deterministic explainer if offline or provider times out
    3. Enforces that alert attributes (threat, severity, confidence, action) are NEVER mutated
    """
    provider = settings.llm_provider.lower()

    if provider == "ollama":
        result = _query_ollama(alert)
        if result is not None and result.executive_summary:
            return result

    elif provider in ("openai", "gemini"):
        result = _query_external_api(alert, provider)
        if result is not None and result.executive_summary:
            return result

    # Default / Fallback: Deterministic explainer (offline, zero-latency, 100% reliable)
    return _generate_deterministic_explanation(alert)

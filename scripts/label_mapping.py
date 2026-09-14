"""
SentinelFlow Dataset Label Mapping & Normalization (scripts/label_mapping.py)

Maps diverse public dataset labels (CIC-IDS2017, CIC-DDoS2019, CTU-13, CICIoT2023, etc.)
into the frozen SentinelFlow threat taxonomy with whitespace and case normalization.
"""
from __future__ import annotations

from typing import Dict

# Explicit mappings for verified public dataset labels
LABEL_MAP: Dict[str, str] = {
    # Benign
    "BENIGN": "BENIGN",
    "NORMAL": "BENIGN",
    "LEGITIMATE": "BENIGN",
    "BACKGROUND": "BENIGN",

    # DoS & DDoS
    "DDOS": "DDOS",
    "DOS": "DDOS",
    "DOS HULK": "DDOS",
    "DOS GOLDENEYE": "DDOS",
    "DOS SLOWLORIS": "DDOS",
    "DOS SLOWHTTPTEST": "DDOS",
    "HEARTBLEED": "DDOS",
    "SYN_FLOOD": "DDOS",
    "UDP_FLOOD": "DDOS",
    "ICMP_FLOOD": "DDOS",
    "DDOS_SYN": "DDOS",
    "DDOS_UDP": "DDOS",
    "DDOS_DNS": "DDOS",
    "DDOS_NTP": "DDOS",
    "DDOS_MSSQL": "DDOS",
    "DDOS_LDAP": "DDOS",

    # Reconnaissance & Scanning
    "PORTSCAN": "RECON",
    "PORT_SCAN": "RECON",
    "RECON": "RECON",
    "HOST_SWEEP": "RECON",
    "SCAN": "RECON",
    "PROBING": "RECON",
    "RECON_PORTSCAN": "RECON",
    "RECON_OSSCAN": "RECON",

    # Command & Control / Botnets
    "BOT": "C2_BEACON",
    "BOTNET": "C2_BEACON",
    "C2": "C2_BEACON",
    "C2_BEACON": "C2_BEACON",
    "BEACON": "C2_BEACON",
    "NERIS": "C2_BEACON",
    "RBOT": "C2_BEACON",
    "VIRUT": "C2_BEACON",
    "MURLO": "C2_BEACON",
    "MIRAI": "C2_BEACON",

    # Infiltration & Exfiltration
    "INFILTRATION": "EXFIL",
    "EXFIL": "EXFIL",
    "EXFILTRATION": "EXFIL",
    "DATA_EXFIL": "EXFIL",

    # DNS & DGA
    "DGA": "DGA",
    "DNS_TUNNEL": "DNS_TUNNEL",
    "DNSCAT2": "DNS_TUNNEL",
    "IODINE": "DNS_TUNNEL",

    # Web Attacks / Brute Force
    "WEB ATTACK – BRUTE FORCE": "RECON",
    "WEB ATTACK – XSS": "RECON",
    "WEB ATTACK – SQL INJECTION": "RECON",
    "FTP-PATATOR": "RECON",
    "SSH-PATATOR": "RECON",
}


def clean_label_string(raw_label: str) -> str:
    """Strips whitespace, underscores/hyphens and converts to uppercase standard string."""
    if not isinstance(raw_label, str):
        raw_label = str(raw_label)
    return raw_label.strip().upper()


def map_label(raw_label: str) -> str:
    """
    Maps a raw dataset label to the canonical SentinelFlow taxonomy:
    BENIGN, DDOS, RECON, C2_BEACON, DGA, DNS_TUNNEL, EXFIL, or ANOMALY.
    """
    cleaned = clean_label_string(raw_label)

    # 1. Exact match in lookup table
    if cleaned in LABEL_MAP:
        return LABEL_MAP[cleaned]

    # 2. Normalized alphanumeric check
    normalized_key = cleaned.replace("_", " ").replace("-", " ")
    if normalized_key in LABEL_MAP:
        return LABEL_MAP[normalized_key]

    # 3. Keyword / Substring heuristics for compound label strings
    if any(k in cleaned for k in ("DDOS", "DOS", "FLOOD")):
        return "DDOS"
    if any(k in cleaned for k in ("PORTSCAN", "SCAN", "SWEEP", "PROBE", "PATATOR", "BRUTE")):
        return "RECON"
    if any(k in cleaned for k in ("BOT", "C2", "BEACON", "MIRAI", "TROJAN")):
        return "C2_BEACON"
    if "DGA" in cleaned:
        return "DGA"
    if any(k in cleaned for k in ("TUNNEL", "DNSCAT", "IODINE")):
        return "DNS_TUNNEL"
    if any(k in cleaned for k in ("EXFIL", "INFILTRATION", "THEFT", "LEAK")):
        return "EXFIL"
    if any(k in cleaned for k in ("BENIGN", "NORMAL", "LEGITIMATE")):
        return "BENIGN"

    return "ANOMALY"


if __name__ == "__main__":
    test_labels = [
        "BENIGN",
        "  DDoS  ",
        "PortScan",
        "Bot",
        "Infiltration",
        "FTP-Patator",
        "Web Attack – Brute Force",
        "unknown_custom_attack",
    ]

    print("=== SentinelFlow Label Mapping Test ===")
    for lbl in test_labels:
        print(f"'{lbl}' -> '{map_label(lbl)}'")

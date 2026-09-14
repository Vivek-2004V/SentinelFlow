"""
Lab Traffic Generator: DNS Tunnel / DGA.

Simulates DNS-based attack telemetry:
- DNS Tunneling: iodine / dnscat2 style base32/base64/hex exfiltration queries.
- DGA: Domain Generation Algorithms producing pseudo-random domains with high Shannon entropy.
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List

# Distinct compromised host subnets per run
RUN_HOST_SUBNETS = {
    "run_a": "192.168.10",   # Train
    "run_b": "192.168.20",   # Val
    "run_c": "192.168.30",   # Unseen Test
}

# Run-specific DGA dictionary seeds to prevent vocabulary memorization
RUN_DGA_SEEDS = {
    "run_a": {
        "chars": "abcdefghijklmnopqrstuvwxyz0123456789",
        "tlds": [".biz", ".info", ".cc"],
        "min_len": 16,
        "max_len": 24,
    },
    "run_b": {
        "chars": "abcdefghijklmnopqrstuvwxyz",
        "tlds": [".top", ".xyz", ".click"],
        "min_len": 20,
        "max_len": 28,
    },
    "run_c": {  # Unseen character patterns and novel TLDs
        "chars": "abcdef0123456789-",
        "tlds": [".su", ".club", ".pw", ".online"],
        "min_len": 22,
        "max_len": 32,
    },
}


def generate_dns_tunnel_dga_flows(
    count: int = 50,
    run_id: str = "run_a",
    sensor_id: str = "lab-dns-sensor",
) -> List[Dict[str, Any]]:
    """
    Generates synthetic DNS Tunneling and DGA query flows with run-specific parameters.
    """
    subnet = RUN_HOST_SUBNETS.get(run_id, "192.168.99")
    dga_cfg = RUN_DGA_SEEDS.get(run_id, RUN_DGA_SEEDS["run_a"])
    flows: List[Dict[str, Any]] = []

    for _ in range(count):
        host_num = secrets.randbelow(200) + 10
        src_ip = f"{subnet}.{host_num}"
        dst_ip = secrets.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"])

        is_tunnel = secrets.choice([True, False])
        if is_tunnel:
            # DNS Tunnel: long encoded chunks (iodine / dnscat2)
            hex_payload = secrets.token_hex(secrets.randbelow(12) + 16)
            domain = f"{hex_payload}.tunnel-exfil-server.org"
            threat_class = "DNS_TUNNEL"
            bytes_sent = secrets.randbelow(300) + 200
            bytes_recv = secrets.randbelow(500) + 300
        else:
            # DGA: pseudo-random algorithmic domain
            length = secrets.randbelow(dga_cfg["max_len"] - dga_cfg["min_len"] + 1) + dga_cfg["min_len"]
            rand_chars = "".join([secrets.choice(dga_cfg["chars"]) for _ in range(length)])
            tld = secrets.choice(dga_cfg["tlds"])
            domain = f"{rand_chars}{tld}"
            threat_class = "DGA"
            bytes_sent = secrets.randbelow(80) + 60
            bytes_recv = secrets.randbelow(120) + 60

        flows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": secrets.randbelow(20000) + 32768,
            "dst_port": 53,
            "proto": "UDP",
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "pkts_sent": secrets.randbelow(3) + 1,
            "pkts_recv": secrets.randbelow(3) + 1,
            "duration_seconds": round((secrets.randbelow(50) + 10) / 1000.0, 3),
            "dns_query": domain,
            "sensor_id": sensor_id,
            "source_format": "lab_dns_tunnel_dga",
            "generator": "dns_tunnel_dga",
            "run_id": run_id,
            "label": 1,
            "threat_class": threat_class,
        })

    return flows

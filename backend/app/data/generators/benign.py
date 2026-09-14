"""
Benign Traffic Generator per Run.

Generates realistic background telemetry (web browsing, DNS lookups, API calls)
partitioned cleanly by run to guarantee disjoint host addresses.
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List

BENIGN_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "apple.com",
    "cloudflare.com", "amazon.com", "wikipedia.org", "kernel.org",
    "python.org", "fastapi.tiangolo.com", "ubuntu.com", "debian.org"
]

BENIGN_RUN_SUBNETS = {
    "run_a": "192.168.1",    # Train
    "run_b": "192.168.2",    # Val
    "run_c": "192.168.3",    # Unseen Test
}

PUBLIC_DNS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"]


def generate_benign_flows(
    count: int = 50,
    run_id: str = "run_a",
    sensor_id: str = "lab-benign-sensor",
) -> List[Dict[str, Any]]:
    subnet = BENIGN_RUN_SUBNETS.get(run_id, "192.168.0")
    flows: List[Dict[str, Any]] = []

    for _ in range(count):
        host_num = secrets.randbelow(200) + 10
        src_ip = f"{subnet}.{host_num}"
        port = secrets.choice([80, 443, 53])
        domain = secrets.choice(BENIGN_DOMAINS)
        dst_ip = secrets.choice(PUBLIC_DNS) if port == 53 else f"140.82.{secrets.randbelow(100)}.{secrets.randbelow(250)+1}"

        flows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": secrets.randbelow(20000) + 32768,
            "dst_port": port,
            "proto": "UDP" if port == 53 else "TCP",
            "bytes_sent": secrets.randbelow(3000) + 300,
            "bytes_recv": secrets.randbelow(20000) + 1000,
            "pkts_sent": secrets.randbelow(20) + 5,
            "pkts_recv": secrets.randbelow(30) + 8,
            "duration_seconds": round((secrets.randbelow(200) + 20) / 100.0, 3),
            "dns_query": domain if port == 53 else None,
            "tls_sni": domain if port == 443 else None,
            "sensor_id": sensor_id,
            "source_format": "lab_benign",
            "generator": "benign",
            "run_id": run_id,
            "label": 0,
            "threat_class": "BENIGN",
        })

    return flows

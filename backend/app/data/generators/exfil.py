"""
Lab Traffic Generator: Data Exfiltration.

Simulates unauthorized data exfiltration:
- High outbound to inbound volume ratio (upload spikes)
- Large payload byte streams to external untrusted endpoints
- Sustained connection duration
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List

RUN_EXFIL_SUBNETS = {
    "run_a": "192.168.15",
    "run_b": "192.168.25",
    "run_c": "192.168.35",
}


def generate_exfil_flows(
    count: int = 50,
    run_id: str = "run_a",
    sensor_id: str = "lab-exfil-sensor",
) -> List[Dict[str, Any]]:
    subnet = RUN_EXFIL_SUBNETS.get(run_id, "192.168.95")
    flows: List[Dict[str, Any]] = []

    for _ in range(count):
        src_ip = f"{subnet}.{secrets.randbelow(50) + 10}"
        dst_ip = f"198.51.100.{secrets.randbelow(50) + 100}"
        port = secrets.choice([443, 8443, 9001, 21])

        # Large outbound transfer (e.g. 5MB to 50MB) vs tiny inbound ACKs
        bytes_sent = secrets.randbelow(20_000_000) + 5_000_000
        bytes_recv = secrets.randbelow(5000) + 500
        pkts_sent = bytes_sent // 1460
        pkts_recv = pkts_sent // 20
        duration = round((secrets.randbelow(60) + 10) / 1.0, 2)

        flows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": secrets.randbelow(20000) + 40000,
            "dst_port": port,
            "proto": "TCP",
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "pkts_sent": pkts_sent,
            "pkts_recv": pkts_recv,
            "duration_seconds": duration,
            "unique_dst_ports": 1,
            "unique_dst_hosts": 1,
            "sensor_id": sensor_id,
            "source_format": "lab_exfil",
            "generator": "exfil",
            "run_id": run_id,
            "label": 1,
            "threat_class": "EXFILTRATION",
        })

    return flows

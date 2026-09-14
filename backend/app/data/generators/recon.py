"""
Lab Traffic Generator: Reconnaissance / Port Scan.

Simulates network scanning activity (nmap / masscan / zmap style):
- SYN scans across multiple destination ports (port fan-out)
- Horizontal subnet sweep across multiple destination hosts
- Small probe packets, fast inter-arrival times
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List

RUN_RECON_SUBNETS = {
    "run_a": "10.10.99",
    "run_b": "10.20.99",
    "run_c": "10.30.99",
}


def generate_recon_flows(
    count: int = 50,
    run_id: str = "run_a",
    sensor_id: str = "lab-recon-sensor",
) -> List[Dict[str, Any]]:
    subnet = RUN_RECON_SUBNETS.get(run_id, "10.99.99")
    flows: List[Dict[str, Any]] = []

    for _ in range(count):
        src_ip = f"{subnet}.{secrets.randbelow(10) + 1}"
        dst_ip = f"10.0.0.{secrets.randbelow(20) + 1}"
        port = secrets.choice([21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080])

        unique_ports = secrets.randbelow(150) + 50
        unique_hosts = secrets.randbelow(30) + 5

        flows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": secrets.randbelow(20000) + 40000,
            "dst_port": port,
            "proto": "TCP",
            "bytes_sent": 60,
            "bytes_recv": 0,
            "pkts_sent": 1,
            "pkts_recv": 0,
            "duration_seconds": 0.005,
            "unique_dst_ports": unique_ports,
            "unique_dst_hosts": unique_hosts,
            "mean_iat": 0.002,
            "iat_std": 0.001,
            "sensor_id": sensor_id,
            "source_format": "lab_recon",
            "generator": "recon",
            "run_id": run_id,
            "label": 1,
            "threat_class": "RECON",
        })

    return flows

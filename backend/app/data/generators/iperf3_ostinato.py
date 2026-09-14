"""
Lab Traffic Generator: iperf3 / Ostinato.

Simulates controlled high-bandwidth and packet-rate telemetry:
- iperf3: TCP/UDP throughput saturation, bandwidth bursts, varying stream counts.
- Ostinato: Custom packet size distributions, variable inter-packet gaps, burst flows.
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List

# Distinct subnet allocations per run to prevent IP leakage between train/val/test
RUN_SUBNETS = {
    "run_a": "10.10.1",   # Train
    "run_b": "10.20.1",   # Val
    "run_c": "10.30.1",   # Unseen Test
}


def generate_iperf3_ostinato_flows(
    count: int = 50,
    run_id: str = "run_a",
    sensor_id: str = "lab-iperf3-sensor",
) -> List[Dict[str, Any]]:
    """
    Generates synthetic iperf3/Ostinato benchmark flows with run-specific parameters.
    """
    subnet = RUN_SUBNETS.get(run_id, "10.99.1")
    flows: List[Dict[str, Any]] = []

    # Run parameter adjustments to ensure genuine distribution shift
    rate_multipliers = {
        "run_a": (1.0, 5001),     # Standard baseline iperf3 benchmark
        "run_b": (1.2, 5201),     # Slightly shifted rate & port
        "run_c": (1.5, 5301),     # Unseen rate shift & alternative port
    }
    mult, dst_port = rate_multipliers.get(run_id, (1.0, 5001))

    for _ in range(count):
        host_num = secrets.randbelow(200) + 10
        src_ip = f"{subnet}.{host_num}"
        dst_ip = f"192.168.200.{secrets.randbelow(10) + 1}"

        # Ostinato variable payload sizes: 64B, 512B, 1460B (MTU)
        packet_type = secrets.choice(["jumbo", "standard", "burst"])
        if packet_type == "jumbo":
            pkts = int((secrets.randbelow(5000) + 2000) * mult)
            bytes_sent = pkts * (secrets.randbelow(200) + 1400)
            duration = round((secrets.randbelow(50) + 10) / 10.0, 3)
        elif packet_type == "burst":
            pkts = int((secrets.randbelow(8000) + 5000) * mult)
            bytes_sent = pkts * (secrets.randbelow(300) + 800)
            duration = round((secrets.randbelow(20) + 5) / 10.0, 3)
        else:
            pkts = int((secrets.randbelow(3000) + 1000) * mult)
            bytes_sent = pkts * 512
            duration = round((secrets.randbelow(30) + 10) / 10.0, 3)

        flows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": secrets.randbelow(20000) + 32768,
            "dst_port": dst_port,
            "proto": secrets.choice(["TCP", "UDP"]),
            "bytes_sent": bytes_sent,
            "bytes_recv": secrets.randbelow(2000) + 100,
            "pkts_sent": pkts,
            "pkts_recv": secrets.randbelow(100) + 10,
            "duration_seconds": max(0.01, duration),
            "sensor_id": sensor_id,
            "source_format": "lab_iperf3_ostinato",
            "generator": "iperf3_ostinato",
            "run_id": run_id,
            "label": 1,
            "threat_class": "BANDWIDTH_ANOMALY",
        })

    return flows

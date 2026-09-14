"""
Lab Traffic Generator: TRex / hping3.

Simulates stateful & stateless high-rate volumetric DDoS and packet flooding attacks:
- TRex: Line-rate traffic generation, multi-stream SYN and UDP flooding.
- hping3: Raw socket crafted packet attacks (SYN-flood, fragmented UDP, ICMP storms).
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List

# Distinct botnet subnet pools per run to prevent IP leakage between train/val/test
RUN_BOTNET_SUBNETS = {
    "run_a": "198.51.100",  # Train (Botnet Pool A)
    "run_b": "203.0.113",   # Val (Botnet Pool B)
    "run_c": "192.0.2",     # Unseen Test (Botnet Pool C)
}


def generate_trex_hping3_flows(
    count: int = 50,
    run_id: str = "run_a",
    target_ip: str = "10.0.0.5",
    sensor_id: str = "lab-trex-sensor",
) -> List[Dict[str, Any]]:
    """
    Generates synthetic TRex/hping3 DDoS flood telemetry with run-specific parameters.
    """
    bot_subnet = RUN_BOTNET_SUBNETS.get(run_id, "198.18.0")
    flows: List[Dict[str, Any]] = []

    # Run parameter variations
    run_configs = {
        "run_a": {"rate_mult": 1.0, "ports": [80, 443], "protos": ["TCP", "UDP"]},
        "run_b": {"rate_mult": 1.3, "ports": [8080, 53], "protos": ["UDP", "TCP"]},
        "run_c": {"rate_mult": 1.8, "ports": [8443, 9000], "protos": ["TCP", "UDP"]},
    }
    cfg = run_configs.get(run_id, run_configs["run_a"])

    for _ in range(count):
        bot_host = secrets.randbelow(250) + 1
        src_ip = f"{bot_subnet}.{bot_host}"
        dst_port = secrets.choice(cfg["ports"])
        proto = secrets.choice(cfg["protos"])

        # Volumetric metrics: high packet rate, minimal response
        pkts = int((secrets.randbelow(15000) + 5000) * cfg["rate_mult"])
        bytes_sent = pkts * (secrets.randbelow(100) + 40)  # small flood packets
        duration = round((secrets.randbelow(5) + 1) / 100.0, 3)  # 0.01s - 0.05s

        flows.append({
            "src_ip": src_ip,
            "dst_ip": target_ip,
            "src_port": secrets.randbelow(60000) + 1024,
            "dst_port": dst_port,
            "proto": proto,
            "bytes_sent": bytes_sent,
            "bytes_recv": 0,
            "pkts_sent": pkts,
            "pkts_recv": 0,
            "duration_seconds": max(0.01, duration),
            "sensor_id": sensor_id,
            "source_format": "lab_trex_hping3",
            "generator": "trex_hping3",
            "run_id": run_id,
            "label": 1,
            "threat_class": "DDOS",
        })

    return flows

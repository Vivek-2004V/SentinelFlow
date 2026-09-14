"""
Lab Traffic Generator: C2 Emulator.

Simulates Command and Control (C2) agent communication (Cobalt Strike / Sliver / Mythic):
- Periodic beaconing intervals (e.g. 5s, 10s, 30s, 60s)
- Configurable jitter (+/- 5% to +/- 30%)
- Small fixed or slightly fluctuating check-in payloads
- Camouflaged TLS SNI hostnames
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List

# Distinct bot IPs and C2 server IPs per run
RUN_C2_CONFIGS = {
    "run_a": {
        "bot_subnet": "172.16.1",
        "c2_servers": ["203.0.113.50", "203.0.113.51"],
        "base_interval": 10.0,
        "jitter_pct": 0.05,
        "ports": [8443, 443],
        "snis": ["cdn-sync-api.update-check.cc", "telemetry-cloud.sys-diag.net"],
    },
    "run_b": {
        "bot_subnet": "172.16.2",
        "c2_servers": ["198.51.100.80", "198.51.100.81"],
        "base_interval": 15.0,
        "jitter_pct": 0.12,
        "ports": [443, 8088],
        "snis": ["edge-service.infra-api.xyz", "gateway.auth-refresh.top"],
    },
    "run_c": {  # Unseen C2 infrastructure and long sleep interval
        "bot_subnet": "172.16.3",
        "c2_servers": ["192.0.2.110", "192.0.2.111"],
        "base_interval": 30.0,
        "jitter_pct": 0.25,
        "ports": [9001, 8443],
        "snis": ["relay-stream.enterprise-sync.club", "agent-connect.node-relay.online"],
    },
}


def generate_c2_emulator_flows(
    count: int = 50,
    run_id: str = "run_a",
    sensor_id: str = "lab-c2-sensor",
) -> List[Dict[str, Any]]:
    """
    Generates synthetic C2 beaconing streams with run-specific intervals, jitter, and endpoints.
    """
    cfg = RUN_C2_CONFIGS.get(run_id, RUN_C2_CONFIGS["run_a"])
    flows: List[Dict[str, Any]] = []

    for _ in range(count):
        bot_host = secrets.randbelow(100) + 10
        src_ip = f"{cfg['bot_subnet']}.{bot_host}"
        dst_ip = secrets.choice(cfg["c2_servers"])
        dst_port = secrets.choice(cfg["ports"])
        sni = secrets.choice(cfg["snis"])

        # Jitter applied to beacon duration / flow simulation
        jitter_factor = 1.0 + ((secrets.randbelow(200) - 100) / 100.0) * cfg["jitter_pct"]
        effective_interval = round(cfg["base_interval"] * jitter_factor, 2)

        # Small beacon payload (128-512 bytes)
        bytes_sent = secrets.randbelow(384) + 128
        bytes_recv = secrets.randbelow(256) + 128

        flows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": secrets.randbelow(20000) + 40000,
            "dst_port": dst_port,
            "proto": "TCP",
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "pkts_sent": secrets.randbelow(3) + 2,
            "pkts_recv": secrets.randbelow(3) + 2,
            "duration_seconds": round((secrets.randbelow(50) + 20) / 1000.0, 3),
            "tls_sni": sni,
            "periodicity_hint": effective_interval,
            "sensor_id": sensor_id,
            "source_format": "lab_c2_emulator",
            "generator": "c2_emulator",
            "run_id": run_id,
            "label": 1,
            "threat_class": "C2_BEACON",
        })

    return flows

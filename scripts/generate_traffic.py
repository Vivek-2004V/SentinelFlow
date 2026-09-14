#!/usr/bin/env python3
"""
SentinelFlow Traffic Generator.

Generates simulated one-way network traffic representing both
benign baselines and specific cyber attack classes:
- DDoS flood
- C2 Beaconing
- DGA queries
- DNS Tunneling
- Reconnaissance port scans
- Data Exfiltration

Can output JSON to file or stream to the SentinelFlow Ingest API.
"""
from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List

import httpx

BENIGN_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "apple.com",
    "cloudflare.com", "amazon.com", "wikipedia.org", "kernel.org"
]

BENIGN_HOSTS = ["192.168.1.10", "192.168.1.25", "192.168.1.42", "192.168.1.105"]
PUBLIC_SERVERS = ["140.82.121.4", "172.217.16.206", "1.1.1.1", "8.8.8.8"]


def create_benign_flow() -> Dict[str, Any]:
    src = random.choice(BENIGN_HOSTS)
    dst = random.choice(PUBLIC_SERVERS)
    port = random.choice([80, 443, 53])
    bytes_sent = random.randint(300, 4000)
    bytes_recv = random.randint(1000, 30000)

    domain = random.choice(BENIGN_DOMAINS) if port in (80, 443, 53) else None

    return {
        "src_ip": src,
        "dst_ip": dst,
        "src_port": random.randint(32768, 61000),
        "dst_port": port,
        "proto": "TCP" if port != 53 else "UDP",
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "pkts_sent": random.randint(4, 25),
        "pkts_recv": random.randint(4, 40),
        "duration_seconds": round(random.uniform(0.1, 2.5), 3),
        "dns_query": domain if port == 53 else None,
        "tls_sni": domain if port == 443 else None,
        "sensor_id": "sim-sensor-01",
        "source_format": "simulated",
    }


def create_ddos_flow(target_ip: str = "10.0.0.5") -> Dict[str, Any]:
    return {
        "src_ip": f"198.51.100.{random.randint(1, 254)}",
        "dst_ip": target_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "proto": "UDP",
        "bytes_sent": 500_000,
        "bytes_recv": 0,
        "pkts_sent": 8000,
        "pkts_recv": 0,
        "duration_seconds": 0.05,
        "sensor_id": "sim-sensor-01",
        "source_format": "simulated",
    }


def create_c2_beacon_flow(bot_ip: str = "192.168.1.99", c2_ip: str = "203.0.113.50") -> Dict[str, Any]:
    return {
        "src_ip": bot_ip,
        "dst_ip": c2_ip,
        "src_port": 49152,
        "dst_port": 8443,
        "proto": "TCP",
        "bytes_sent": 128,
        "bytes_recv": 128,
        "pkts_sent": 2,
        "pkts_recv": 2,
        "duration_seconds": 0.05,
        "tls_sni": "cdn-sync-api.internal-update.cc",
        "sensor_id": "sim-sensor-01",
        "source_format": "simulated",
    }


def create_dga_flow(host_ip: str = "192.168.1.150") -> Dict[str, Any]:
    # Random alphanumeric string with high entropy
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    random_str = "".join(random.choices(chars, k=random.randint(16, 28)))
    tld = random.choice([".top", ".xyz", ".cc", ".ru", ".biz"])
    dga_domain = f"{random_str}{tld}"

    return {
        "src_ip": host_ip,
        "dst_ip": "8.8.8.8",
        "src_port": random.randint(40000, 60000),
        "dst_port": 53,
        "proto": "UDP",
        "bytes_sent": 80,
        "bytes_recv": 80,
        "pkts_sent": 1,
        "pkts_recv": 1,
        "duration_seconds": 0.02,
        "dns_query": dga_domain,
        "sensor_id": "sim-sensor-01",
        "source_format": "simulated",
    }


def create_dns_tunnel_flow(host_ip: str = "192.168.1.75") -> Dict[str, Any]:
    chunk = "".join(random.choices("0123456789abcdef", k=64))
    tunnel_domain = f"{chunk}.data.tunnel.exfil-c2.net"

    return {
        "src_ip": host_ip,
        "dst_ip": "1.1.1.1",
        "src_port": random.randint(30000, 60000),
        "dst_port": 53,
        "proto": "UDP",
        "bytes_sent": 15000,
        "bytes_recv": 500,
        "pkts_sent": 120,
        "pkts_recv": 20,
        "duration_seconds": 1.2,
        "dns_query": tunnel_domain,
        "sensor_id": "sim-sensor-01",
        "source_format": "simulated",
    }


def create_recon_flow(scanner_ip: str = "192.168.1.200") -> Dict[str, Any]:
    target_ports = [21, 22, 23, 80, 445, 1433, 3389, 8080]
    port = random.choice(target_ports)

    return {
        "src_ip": scanner_ip,
        "dst_ip": "192.168.1.1",
        "src_port": random.randint(40000, 65000),
        "dst_port": port,
        "proto": "TCP",
        "bytes_sent": 54,
        "bytes_recv": 0,
        "pkts_sent": 1,
        "pkts_recv": 0,
        "duration_seconds": 0.01,
        "sensor_id": "sim-sensor-01",
        "source_format": "simulated",
    }


def create_exfil_flow(compromised_host: str = "192.168.1.66") -> Dict[str, Any]:
    return {
        "src_ip": compromised_host,
        "dst_ip": "198.51.100.99",
        "src_port": 51234,
        "dst_port": 443,
        "proto": "TCP",
        "bytes_sent": 45_000_000,  # 45 MB outbound
        "bytes_recv": 120_000,
        "pkts_sent": 32000,
        "pkts_recv": 1500,
        "duration_seconds": 75.0,
        "sensor_id": "sim-sensor-01",
        "source_format": "simulated",
    }


def main():
    parser = argparse.ArgumentParser(description="SentinelFlow Traffic Generator")
    parser.add_argument("--count", type=int, default=20, help="Number of flows to generate")
    parser.add_argument("--stream", action="store_true", help="Stream directly to http://localhost:8000/api/v1/ingest/flow")
    parser.add_argument("--output", type=str, default="data/sample/sample_flows.json", help="Output JSON filepath")
    args = parser.parse_args()

    generators = [
        (create_benign_flow, 10),
        (create_ddos_flow, 2),
        (create_c2_beacon_flow, 2),
        (create_dga_flow, 2),
        (create_dns_tunnel_flow, 2),
        (create_recon_flow, 2),
        (create_exfil_flow, 1),
    ]

    flows: List[Dict[str, Any]] = []
    for gen, weight in generators:
        for _ in range(weight):
            flows.append(gen())

    random.shuffle(flows)
    flows = flows[: args.count]

    if args.stream:
        url = "http://localhost:8000/api/v1/ingest/flow"
        print(f"[+] Streaming {len(flows)} simulated flows to {url}...")
        with httpx.Client(timeout=10.0) as client:
            for i, flow in enumerate(flows):
                try:
                    resp = client.post(url, json=flow)
                    data = resp.json()
                    status_str = f"Alerts: {data.get('alerts_generated')}"
                    print(f"[{i+1}/{len(flows)}] {flow['src_ip']} -> {flow['dst_ip']}:{flow.get('dst_port')} | {status_str}")
                except Exception as e:
                    print(f"[-] Failed to stream flow: {e}")
                time.sleep(0.1)
    else:
        with open(args.output, "w") as f:
            json.dump(flows, f, indent=2)
        print(f"[+] Successfully wrote {len(flows)} simulated flows to {args.output}")


if __name__ == "__main__":
    main()

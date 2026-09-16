from __future__ import annotations

import time
import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP

from app.ingest.flow_builder import FlowBuilder


def test_packet_to_flow_conversion():
    builder = FlowBuilder()
    now = time.time()

    # Forward packet
    builder.add_packet(
        src_ip="10.0.0.1",
        dst_ip="203.0.113.5",
        src_port=49152,
        dst_port=443,
        proto="TCP",
        packet_len=150,
        timestamp=now,
    )

    # Reverse packet
    builder.add_packet(
        src_ip="203.0.113.5",
        dst_ip="10.0.0.1",
        src_port=443,
        dst_port=49152,
        proto="TCP",
        packet_len=300,
        timestamp=now + 0.05,
    )

    flows = builder.flush_all()
    assert len(flows) == 1
    flow = flows[0]

    assert flow.src_ip == "10.0.0.1"
    assert flow.dst_ip == "203.0.113.5"
    assert flow.src_port == 49152
    assert flow.dst_port == 443
    assert flow.proto == "TCP"
    assert flow.pkts_sent == 1
    assert flow.pkts_recv == 1
    assert flow.bytes_sent == 150
    assert flow.bytes_recv == 300
    assert flow.duration_seconds >= 0.04


def test_tcp_fin_terminates_flow():
    builder = FlowBuilder()
    now = time.time()

    builder.add_packet(
        src_ip="192.168.1.10",
        dst_ip="10.0.0.2",
        src_port=55555,
        dst_port=80,
        proto="TCP",
        packet_len=60,
        timestamp=now,
    )

    # FIN packet terminates the flow immediately
    finalized = builder.add_packet(
        src_ip="192.168.1.10",
        dst_ip="10.0.0.2",
        src_port=55555,
        dst_port=80,
        proto="TCP",
        packet_len=60,
        timestamp=now + 0.1,
        is_fin_or_rst=True,
    )

    assert finalized is not None
    assert finalized.src_ip == "192.168.1.10"
    assert finalized.pkts_sent == 2


def test_dns_query_extracted_from_udp():
    builder = FlowBuilder()
    now = time.time()

    builder.add_packet(
        src_ip="192.168.1.15",
        dst_ip="8.8.8.8",
        src_port=53210,
        dst_port=53,
        proto="UDP",
        packet_len=85,
        timestamp=now,
        dns_query="malicious-beacon.c2.net",
    )

    flows = builder.flush_all()
    assert len(flows) == 1
    assert flows[0].dns_query == "malicious-beacon.c2.net"

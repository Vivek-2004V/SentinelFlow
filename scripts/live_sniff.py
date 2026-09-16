#!/usr/bin/env python3
"""
SentinelFlow Passive Live Network Sniffer (scripts/live_sniff.py)

Passively observes network traffic on an authorized local interface (or TAP/SPAN port).
Reconstructs 5-tuple bidirectional network flows and routes them through the full
SentinelFlow Feature Extraction & Threat Detection Pipeline.

STRICT OPERATIONAL CONSTRAINTS:
1. READ-ONLY: Never generates, injects, or transmits any packet onto the monitored network.
2. PASSIVE: No active probing, port scanning, or handshake generation.
3. ALERT-ONLY: Never blocks, drops, or alters traffic (software-enforced data diode posture).
"""
from __future__ import annotations

import argparse
from datetime import datetime
import logging
from pathlib import Path
import sys
import time

# Ensure backend modules can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from scapy.all import DNS, IP, IPv6, sniff, TCP, UDP
from app.ingest.flow_builder import FlowBuilder
from app.schemas.flow import RawFlow
from app.services.pipeline import pipeline_orchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinelflow.live_sniff")


class LiveCaptureEngine:
    def __init__(
        self,
        interface: str | None = None,
        bpf_filter: str = "ip or ip6",
        inactivity_timeout_sec: float = 15.0,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.builder = FlowBuilder(inactivity_timeout_sec=inactivity_timeout_sec)
        self.packet_count = 0
        self.flow_count = 0
        self.alert_count = 0
        self.last_flush_time = time.time()

    def process_packet(self, packet: Any) -> None:
        self.packet_count += 1
        now = time.time()

        if IP in packet:
            ip = packet[IP]
            src_ip = str(ip.src)
            dst_ip = str(ip.dst)
            proto_num = ip.proto
        elif IPv6 in packet:
            ip = packet[IPv6]
            src_ip = str(ip.src)
            dst_ip = str(ip.dst)
            proto_num = ip.nh
        else:
            return

        packet_len = len(packet)
        src_port = None
        dst_port = None
        proto_str = "OTHER"
        is_fin_rst = False
        dns_query = None

        if TCP in packet:
            tcp = packet[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            proto_str = "TCP"
            flags = str(tcp.flags)
            if "F" in flags or "R" in flags:
                is_fin_rst = True
        elif UDP in packet:
            udp = packet[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            proto_str = "UDP"
            if DNS in packet and packet[DNS].qd:
                try:
                    q = packet[DNS].qd.qname
                    dns_query = q.decode("utf-8", errors="ignore").rstrip(".") if isinstance(q, bytes) else str(q).rstrip(".")
                except Exception:
                    pass
        else:
            proto_str = str(proto_num)

        finalized_flow = self.builder.add_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto_str,
            packet_len=packet_len,
            timestamp=now,
            is_fin_or_rst=is_fin_rst,
            dns_query=dns_query,
        )

        if finalized_flow:
            self._handle_completed_flow(finalized_flow)

        # Periodic flush every 5 seconds for flows older than inactivity timeout
        if (now - self.last_flush_time) > 5.0:
            self.last_flush_time = now
            flushed = self.builder.flush_all()
            for f in flushed:
                self._handle_completed_flow(f)

    def _handle_completed_flow(self, flow: RawFlow) -> None:
        self.flow_count += 1
        alert = pipeline_orchestrator.process_flow(flow)
        if alert is not None:
            self.alert_count += 1
            print(
                f"\n🚨 [ALERT] Threat: {alert.threat_class:<12} "
                f"Severity: {alert.severity.value:<8} "
                f"Conf: {int(alert.confidence * 100)}% | "
                f"{flow.src_ip} -> {flow.dst_ip}:{flow.dst_port} "
                f"[{alert.action}]"
            )
            for ev in alert.evidence[:2]:
                print(f"   • Evidence: {ev.description}")


def print_banner(interface: str | None, bpf_filter: str) -> None:
    print("\n" + "=" * 64)
    print("      SENTINELFLOW PASSIVE NETWORK SNIFFER")
    print("=" * 64)
    print(" Mode:               PASSIVE READ-ONLY (SPAN / Mirror Tap)")
    print(f" Interface:          {interface or 'Default System Route'}")
    print(f" BPF Filter:         {bpf_filter}")
    print(" Active Response:    DISABLED (Zero return path)")
    print(" Mitigation Posture: ALERT_ONLY (Immutable)")
    print("=" * 64)
    print("Listening for packets... Press Ctrl+C to stop.\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelFlow Passive Network Sniffer")
    parser.add_argument("--iface", "-i", type=str, default=None, help="Network interface (e.g. eth0, en0)")
    parser.add_argument("--filter", "-f", type=str, default="ip or ip6", help="BPF packet filter")
    parser.add_argument("--count", "-c", type=int, default=0, help="Packet limit (0 = continuous)")
    parser.add_argument("--timeout", "-t", type=int, default=None, help="Sniffing timeout in seconds")
    args = parser.parse_args()

    print_banner(args.iface, args.filter)

    engine = LiveCaptureEngine(interface=args.iface, bpf_filter=args.filter)

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=engine.process_packet,
            store=False,
            count=args.count,
            timeout=args.timeout,
        )
    except KeyboardInterrupt:
        print("\n\nCapture terminated by analyst.")
    except PermissionError:
        print("\n❌ Permission denied: Packet capture requires elevated privileges (e.g. sudo).")
        sys.exit(1)
    except Exception as exc:
        print(f"\n❌ Sniffing failed: {exc}")
        sys.exit(1)

    # Flush any remaining flows
    remaining = engine.builder.flush_all()
    for f in remaining:
        engine._handle_completed_flow(f)

    print("\n" + "-" * 64)
    print("CAPTURE SESSION SUMMARY")
    print(f"Packets Analyzed:    {engine.packet_count:,}")
    print(f"Flows Reconstructed: {engine.flow_count:,}")
    print(f"Alerts Emitted:      {engine.alert_count:,} (All ALERT_ONLY)")
    print("-" * 64 + "\n")


if __name__ == "__main__":
    main()

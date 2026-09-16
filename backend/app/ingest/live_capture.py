"""
SentinelFlow — Live Capture Engine (backend/app/ingest/live_capture.py)

Thread-safe wrapper around the Scapy packet capture loop.
Bridges the synchronous scapy prn callback to an asyncio.Queue so
FastAPI SSE endpoints can stream alerts without blocking the event loop.

STRICT OPERATIONAL CONSTRAINTS:
  - READ-ONLY: Never generates, injects, or transmits any packet.
  - PASSIVE: No active probing, scanning, or handshake generation.
  - ALERT-ONLY: Never blocks, drops, or alters traffic in any way.
"""
from __future__ import annotations

import asyncio
import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("sentinelflow.live_capture")

# ---------------------------------------------------------------------------
# Status dataclass
# ---------------------------------------------------------------------------

@dataclass
class CaptureStats:
    running: bool = False
    interface: str | None = None
    bpf_filter: str = "ip or ip6"
    packets_captured: int = 0
    flows_reconstructed: int = 0
    alerts_emitted: int = 0
    start_time: float | None = None
    requires_sudo: bool = True

    @property
    def uptime_seconds(self) -> float:
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time

    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "packets_captured": self.packets_captured,
            "flows_reconstructed": self.flows_reconstructed,
            "alerts_emitted": self.alerts_emitted,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "start_time": self.start_time,
            "requires_sudo": self.requires_sudo,
        }


# ---------------------------------------------------------------------------
# Capture Engine
# ---------------------------------------------------------------------------

class LiveCaptureEngine:
    """
    Manages a background scapy sniff() thread and exposes a thread-safe
    alert queue that async SSE handlers can drain.
    """

    def __init__(self) -> None:
        self.stats = CaptureStats()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._alert_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=500)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self, interface: str | None, bpf_filter: str = "ip or ip6") -> None:
        if self.stats.running:
            raise RuntimeError("Capture already running — stop it first.")

        self._stop_event.clear()
        self.stats = CaptureStats(
            running=True,
            interface=interface,
            bpf_filter=bpf_filter,
            start_time=time.time(),
        )

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, bpf_filter),
            daemon=True,
            name="sentinelflow-live-capture",
        )
        self._thread.start()
        logger.info("Live capture started on interface=%s filter='%s'", interface, bpf_filter)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self.stats.running = False
        logger.info("Live capture stopped. stats=%s", self.stats.to_dict())

    def get_status(self) -> dict[str, Any]:
        return self.stats.to_dict()

    def drain_alerts(self, max_items: int = 50) -> list[dict[str, Any]]:
        """Drain up to max_items pending alerts from the queue (non-blocking)."""
        results: list[dict[str, Any]] = []
        for _ in range(max_items):
            try:
                results.append(self._alert_queue.get_nowait())
            except queue.Empty:
                break
        return results

    async def next_alert(self, timeout: float = 30.0) -> dict[str, Any] | None:
        """
        Async-safe: waits up to timeout seconds for the next alert.
        Returns None on timeout or if capture stopped.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                return self._alert_queue.get_nowait()
            except queue.Empty:
                if not self.stats.running:
                    return None
                await asyncio.sleep(0.2)
        return None

    # ------------------------------------------------------------------
    # Internal capture loop (runs in daemon thread)
    # ------------------------------------------------------------------

    def _capture_loop(self, interface: str | None, bpf_filter: str) -> None:
        try:
            from scapy.all import DNS, IP, TCP, UDP, IPv6, sniff  # type: ignore[import]

            from app.ingest.flow_builder import FlowBuilder
            from app.services.pipeline import pipeline_orchestrator

            builder = FlowBuilder(inactivity_timeout_sec=15.0)
            last_flush = time.time()

            def process_packet(packet: Any) -> None:
                nonlocal last_flush

                if self._stop_event.is_set():
                    return

                self.stats.packets_captured += 1
                now = time.time()

                if IP in packet:
                    ip = packet[IP]
                    src_ip, dst_ip = str(ip.src), str(ip.dst)
                    proto_num = ip.proto
                elif IPv6 in packet:
                    ip = packet[IPv6]
                    src_ip, dst_ip = str(ip.src), str(ip.dst)
                    proto_num = ip.nh
                else:
                    return

                pkt_len = len(packet)
                src_port = dst_port = None
                proto_str = "OTHER"
                is_fin_rst = False
                dns_query = None

                if TCP in packet:
                    tcp = packet[TCP]
                    src_port, dst_port = int(tcp.sport), int(tcp.dport)
                    proto_str = "TCP"
                    if "F" in str(tcp.flags) or "R" in str(tcp.flags):
                        is_fin_rst = True
                elif UDP in packet:
                    udp = packet[UDP]
                    src_port, dst_port = int(udp.sport), int(udp.dport)
                    proto_str = "UDP"
                    if DNS in packet and packet[DNS].qd:
                        try:
                            q = packet[DNS].qd.qname
                            dns_query = (
                                q.decode("utf-8", errors="ignore").rstrip(".")
                                if isinstance(q, bytes)
                                else str(q).rstrip(".")
                            )
                        except Exception:
                            pass  # nosec B110
                else:
                    proto_str = str(proto_num)

                finalized = builder.add_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto_str,
                    packet_len=pkt_len,
                    timestamp=now,
                    is_fin_or_rst=is_fin_rst,
                    dns_query=dns_query,
                )
                if finalized:
                    self._handle_flow(finalized, pipeline_orchestrator)

                # Periodic flush
                if (now - last_flush) > 5.0:
                    last_flush = now
                    for f in builder.flush_all():
                        self._handle_flow(f, pipeline_orchestrator)

            sniff(
                iface=interface,
                filter=bpf_filter,
                prn=process_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )

            # Final flush
            from app.services.pipeline import pipeline_orchestrator as po
            for f in builder.flush_all():
                self._handle_flow(f, po)

        except PermissionError:
            logger.error("Permission denied: live capture requires elevated privileges (sudo).")
            self.stats.running = False
        except Exception as exc:
            logger.error("Live capture failed: %s", exc)
            self.stats.running = False

    def _handle_flow(self, flow: Any, pipeline: Any) -> None:
        self.stats.flows_reconstructed += 1
        alert = pipeline.process_flow(flow)
        if alert is not None:
            self.stats.alerts_emitted += 1
            try:
                self._alert_queue.put_nowait(alert.model_dump())
            except queue.Full:
                # Drop oldest alert to make room
                try:
                    self._alert_queue.get_nowait()
                    self._alert_queue.put_nowait(alert.model_dump())
                except queue.Empty:
                    pass


# Module-level singleton — one capture session at a time per process
live_capture_engine = LiveCaptureEngine()

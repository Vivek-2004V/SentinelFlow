from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.schemas.flow import RawFlow


@dataclass
class FlowAccumulator:
    """Internal state for an ongoing 5-tuple network conversation."""
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: str

    start_time: float
    last_time: float

    pkts_sent: int = 0
    bytes_sent: int = 0
    pkts_recv: int = 0
    bytes_recv: int = 0

    dns_query: Optional[str] = None
    tls_sni: Optional[str] = None
    packet_times: List[float] = field(default_factory=list)

    def to_raw_flow(self, sensor_id: str = "pcap-ingest") -> RawFlow:
        duration = max(0.0, self.last_time - self.start_time)
        dt_start = datetime.fromtimestamp(self.start_time, tz=timezone.utc).replace(tzinfo=None)

        # Compute periodicity if enough packets observed
        periodicity: Optional[float] = None
        if len(self.packet_times) >= 4:
            iats = [
                self.packet_times[i] - self.packet_times[i - 1]
                for i in range(1, len(self.packet_times))
            ]
            mean_iat = sum(iats) / len(iats)
            if mean_iat > 0:
                variance = sum((x - mean_iat) ** 2 for x in iats) / len(iats)
                std_iat = math.sqrt(variance)
                # Lower coefficient of variation (std/mean) indicates high periodicity
                cv = std_iat / mean_iat
                periodicity = round(max(0.0, min(1.0, 1.0 - cv)), 3)

        return RawFlow(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            proto=self.proto,
            bytes_sent=self.bytes_sent,
            bytes_recv=self.bytes_recv,
            pkts_sent=self.pkts_sent,
            pkts_recv=self.pkts_recv,
            start_time=dt_start,
            duration_seconds=round(duration, 4),
            dns_query=self.dns_query,
            tls_sni=self.tls_sni,
            periodicity_score=periodicity,
            sensor_id=sensor_id,
            source_format="pcap",
        )


class FlowBuilder:
    """
    Stateful 5-tuple flow reconstruction engine.
    Correlates individual packets into bidirectional network conversations.
    """

    def __init__(self, inactivity_timeout_sec: float = 30.0) -> None:
        self.inactivity_timeout = inactivity_timeout_sec
        # Maps canonical key -> FlowAccumulator
        self.active_flows: Dict[Tuple[str, str, int, int, str], FlowAccumulator] = {}
        self.completed_flows: List[RawFlow] = []

    def _canonical_key(
        self, src_ip: str, dst_ip: str, sport: int, dport: int, proto: str
    ) -> Tuple[Tuple[str, str, int, int, str], bool]:
        """
        Returns ((norm_src, norm_dst, norm_sport, norm_dport, proto), is_forward).
        """
        fwd_key = (src_ip, dst_ip, sport, dport, proto)
        rev_key = (dst_ip, src_ip, dport, sport, proto)

        if fwd_key in self.active_flows:
            return fwd_key, True
        if rev_key in self.active_flows:
            return rev_key, False

        # First packet defines forward direction
        return fwd_key, True

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        proto: str,
        packet_len: int,
        timestamp: float,
        is_fin_or_rst: bool = False,
        dns_query: Optional[str] = None,
        tls_sni: Optional[str] = None,
    ) -> Optional[RawFlow]:
        """
        Ingests a single packet and updates flow state.
        If a flow terminates (FIN/RST or timeout), returns the finalized RawFlow.
        """
        sport = src_port or 0
        dport = dst_port or 0
        key, is_fwd = self._canonical_key(src_ip, dst_ip, sport, dport, proto)

        now = timestamp
        finalized_flow: Optional[RawFlow] = None

        if key not in self.active_flows:
            flow = FlowAccumulator(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
                start_time=now,
                last_time=now,
            )
            self.active_flows[key] = flow
        else:
            flow = self.active_flows[key]

            # Inactivity timeout check
            if (now - flow.last_time) > self.inactivity_timeout:
                finalized_flow = flow.to_raw_flow()
                self.completed_flows.append(finalized_flow)
                # Re-initialize new flow for this key
                flow = FlowAccumulator(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto,
                    start_time=now,
                    last_time=now,
                )
                self.active_flows[key] = flow

        # Accumulate metrics
        flow.last_time = now
        flow.packet_times.append(now)
        if len(flow.packet_times) > 100:  # Keep bound on memory
            flow.packet_times = flow.packet_times[-100:]

        if is_fwd:
            flow.pkts_sent += 1
            flow.bytes_sent += packet_len
        else:
            flow.pkts_recv += 1
            flow.bytes_recv += packet_len

        if dns_query and not flow.dns_query:
            flow.dns_query = dns_query
        if tls_sni and not flow.tls_sni:
            flow.tls_sni = tls_sni

        # TCP FIN or RST closes the conversation immediately
        if is_fin_or_rst and key in self.active_flows:
            completed = self.active_flows.pop(key).to_raw_flow()
            self.completed_flows.append(completed)
            return completed

        return finalized_flow

    def flush_all(self) -> List[RawFlow]:
        """Finalizes and flushes all remaining active flows."""
        flushed: List[RawFlow] = []
        for flow in self.active_flows.values():
            if flow.pkts_sent > 0 or flow.pkts_recv > 0:
                flushed.append(flow.to_raw_flow())
        self.active_flows.clear()
        self.completed_flows.extend(flushed)
        return flushed

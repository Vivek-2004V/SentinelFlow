"""
Passive Ingest Parser.

Parses Zeek TSV logs, NetFlow v5/v9 JSON records, and PCAP summary records
into standardized RawFlow objects.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from app.schemas.flow import RawFlow


def parse_zeek_conn_log(line: str) -> RawFlow | None:
    """
    Parses a single line from Zeek conn.log (standard tab-separated or TSV format).
    Skips comment lines starting with '#'.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split("\t")
    if len(parts) < 11:
        # Fallback space split if tabs aren't present
        parts = line.split()
        if len(parts) < 11:
            return None

    try:
        # Standard Zeek conn.log fields:
        # ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes
        ts_val = float(parts[0]) if parts[0] != "-" else datetime.utcnow().timestamp()
        src_ip = parts[2]
        src_port = int(parts[3]) if parts[3] != "-" else None
        dst_ip = parts[4]
        dst_port = int(parts[5]) if parts[5] != "-" else None
        proto = parts[6].upper()
        duration = float(parts[8]) if parts[8] != "-" else 0.0
        bytes_sent = int(parts[9]) if parts[9] != "-" else 0
        bytes_recv = int(parts[10]) if parts[10] != "-" else 0

        # Optional Zeek pkts fields if available
        pkts_sent = int(parts[16]) if len(parts) > 16 and parts[16] != "-" else 0
        pkts_recv = int(parts[17]) if len(parts) > 17 and parts[17] != "-" else 0

        return RawFlow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            pkts_sent=pkts_sent,
            pkts_recv=pkts_recv,
            start_time=datetime.utcfromtimestamp(ts_val),
            duration_seconds=duration,
            sensor_id="zeek-sensor",
            source_format="zeek",
        )
    except (ValueError, IndexError):
        return None


def parse_netflow_record(record: dict[str, Any]) -> RawFlow | None:
    """
    Parses a dictionary representing a NetFlow / IPFIX flow record.
    Accepts common keys from IPFIX/NetFlow JSON exporters.
    """
    try:
        src_ip = record.get("IPV4_SRC_ADDR") or record.get("src_ip") or record.get("src")
        dst_ip = record.get("IPV4_DST_ADDR") or record.get("dst_ip") or record.get("dst")
        if not src_ip or not dst_ip:
            return None

        proto_raw = record.get("PROTOCOL") or record.get("proto", "TCP")
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto = proto_map.get(proto_raw, str(proto_raw)).upper()

        bytes_sent = int(record.get("IN_BYTES") or record.get("bytes_sent") or record.get("bytes") or 0)
        bytes_recv = int(record.get("OUT_BYTES") or record.get("bytes_recv") or 0)
        pkts_sent = int(record.get("IN_PKTS") or record.get("pkts_sent") or record.get("pkts") or 0)
        pkts_recv = int(record.get("OUT_PKTS") or record.get("pkts_recv") or 0)

        duration = float(record.get("duration") or record.get("DURATION") or 0.0)

        return RawFlow(
            src_ip=str(src_ip),
            dst_ip=str(dst_ip),
            src_port=int(record.get("L4_SRC_PORT") or record.get("src_port", 0)) or None,
            dst_port=int(record.get("L4_DST_PORT") or record.get("dst_port", 0)) or None,
            proto=proto,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            pkts_sent=pkts_sent,
            pkts_recv=pkts_recv,
            duration_seconds=duration,
            sensor_id=str(record.get("sensor_id", "netflow-sensor")),
            source_format="netflow",
        )
    except (ValueError, TypeError):
        return None


def parse_pcap_summary(record: dict[str, Any]) -> RawFlow | None:
    """
    Parses metadata extracted from a passive PCAP capture.
    """
    try:
        return RawFlow(**record)
    except Exception:
        return None

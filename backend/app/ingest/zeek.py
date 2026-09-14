"""
Zeek Multi-Log Ingest & Correlation Engine.

Processes Zeek passive telemetry files:
- conn.log (Transport, timings, volumes)
- dns.log  (Queries, domain names, records)
- ssl.log  (SNI, JA3 hashes, TLS versions)

Correlates records by Zeek Connection UID into enriched RawFlow objects.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.schemas.flow import RawFlow


def parse_zeek_line(line: str) -> Optional[List[str]]:
    """Splits TSV or whitespace Zeek log line, ignoring comments and blanks."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split("\t")
    if len(parts) <= 1:
        parts = line.split()
    return parts


def parse_conn_record(parts: List[str]) -> Optional[Dict[str, Any]]:
    """Parses Zeek conn.log row."""
    # ts(0), uid(1), orig_h(2), orig_p(3), resp_h(4), resp_p(5), proto(6), service(7), duration(8), orig_bytes(9), resp_bytes(10)
    if len(parts) < 11:
        return None
    try:
        ts_val = float(parts[0]) if parts[0] != "-" else datetime.utcnow().timestamp()
        uid = parts[1]
        src_ip = parts[2]
        src_port = int(parts[3]) if parts[3] != "-" else None
        dst_ip = parts[4]
        dst_port = int(parts[5]) if parts[5] != "-" else None
        proto = parts[6].upper()
        duration = float(parts[8]) if parts[8] != "-" else 0.0
        bytes_sent = int(parts[9]) if parts[9] != "-" else 0
        bytes_recv = int(parts[10]) if parts[10] != "-" else 0

        pkts_sent = int(parts[16]) if len(parts) > 16 and parts[16] != "-" else 0
        pkts_recv = int(parts[17]) if len(parts) > 17 and parts[17] != "-" else 0

        return {
            "uid": uid,
            "ts": ts_val,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": proto,
            "duration": duration,
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "pkts_sent": pkts_sent,
            "pkts_recv": pkts_recv,
        }
    except (ValueError, IndexError):
        return None


def parse_dns_record(parts: List[str]) -> Optional[Dict[str, Any]]:
    """Parses Zeek dns.log row."""
    # ts(0), uid(1), orig_h(2), orig_p(3), resp_h(4), resp_p(5), proto(6), trans_id(7), rtt(8), query(9)
    if len(parts) < 10:
        return None
    try:
        uid = parts[1]
        query = parts[9] if parts[9] != "-" else None
        return {
            "uid": uid,
            "dns_query": query,
        }
    except IndexError:
        return None


def parse_ssl_record(parts: List[str]) -> Optional[Dict[str, Any]]:
    """Parses Zeek ssl.log row."""
    # ts(0), uid(1), orig_h(2), orig_p(3), resp_h(4), resp_p(5), version(6), cipher(7), curve(8), server_name(9)
    if len(parts) < 10:
        return None
    try:
        uid = parts[1]
        server_name = parts[9] if parts[9] != "-" else None
        # In Zeek with JA3 package, ja3 is typically field 23 or later
        ja3 = None
        for item in parts[10:]:
            if len(item) == 32 and all(c in "0123456789abcdefABCDEF" for c in item):
                ja3 = item
                break

        return {
            "uid": uid,
            "tls_sni": server_name,
            "ja3_hash": ja3,
        }
    except IndexError:
        return None


def correlate_zeek_logs(
    conn_content: str,
    dns_content: Optional[str] = None,
    ssl_content: Optional[str] = None,
    sensor_id: str = "zeek-sensor",
) -> List[RawFlow]:
    """
    Correlates conn.log, dns.log, and ssl.log data by connection UID.
    Produces unified, fully enriched RawFlow instances.
    """
    dns_by_uid: Dict[str, str] = {}
    if dns_content:
        for line in dns_content.splitlines():
            parts = parse_zeek_line(line)
            if parts:
                rec = parse_dns_record(parts)
                if rec and rec["dns_query"]:
                    dns_by_uid[rec["uid"]] = rec["dns_query"]

    ssl_by_uid: Dict[str, Dict[str, Any]] = {}
    if ssl_content:
        for line in ssl_content.splitlines():
            parts = parse_zeek_line(line)
            if parts:
                rec = parse_ssl_record(parts)
                if rec:
                    ssl_by_uid[rec["uid"]] = rec

    flows: List[RawFlow] = []
    for line in conn_content.splitlines():
        parts = parse_zeek_line(line)
        if not parts:
            continue
        conn = parse_conn_record(parts)
        if not conn:
            continue

        uid = conn["uid"]
        dns_query = dns_by_uid.get(uid)
        ssl_info = ssl_by_uid.get(uid, {})

        flow = RawFlow(
            src_ip=conn["src_ip"],
            dst_ip=conn["dst_ip"],
            src_port=conn["src_port"],
            dst_port=conn["dst_port"],
            proto=conn["proto"],
            bytes_sent=conn["bytes_sent"],
            bytes_recv=conn["bytes_recv"],
            pkts_sent=conn["pkts_sent"],
            pkts_recv=conn["pkts_recv"],
            start_time=datetime.utcfromtimestamp(conn["ts"]),
            duration_seconds=conn["duration"],
            dns_query=dns_query,
            tls_sni=ssl_info.get("tls_sni"),
            ja3_hash=ssl_info.get("ja3_hash"),
            sensor_id=sensor_id,
            source_format="zeek",
        )
        flows.append(flow)

    return flows

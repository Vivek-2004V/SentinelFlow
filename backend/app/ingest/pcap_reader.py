from __future__ import annotations

import logging
import time
from typing import List, Tuple

from scapy.all import DNS, IP, TCP, UDP, IPv6, PcapReader
from scapy.layers.tls.all import TLS_Ext_ServerName, TLSClientHello

from app.ingest.flow_builder import FlowBuilder
from app.schemas.flow import RawFlow

logger = logging.getLogger("sentinelflow.pcap_reader")


def parse_pcap_file(
    file_path: str,
    max_packets: int = 50_000,
    flow_timeout_sec: float = 30.0,
) -> Tuple[List[RawFlow], int]:
    """
    Passively extracts network flows from a .pcap or .pcapng capture file.
    Streams packets individually to maintain a low memory footprint.
    """
    builder = FlowBuilder(inactivity_timeout_sec=flow_timeout_sec)
    packet_count = 0
    t0 = time.time()

    try:
        with PcapReader(file_path) as reader:
            for packet in reader:
                packet_count += 1
                if packet_count > max_packets:
                    logger.warning("Reached maximum packet processing limit (%d)", max_packets)
                    break

                # Support both IPv4 and IPv6
                if IP in packet:
                    ip_layer = packet[IP]
                    src_ip = str(ip_layer.src)
                    dst_ip = str(ip_layer.dst)
                    proto_num = ip_layer.proto
                elif IPv6 in packet:
                    ip_layer = packet[IPv6]
                    src_ip = str(ip_layer.src)
                    dst_ip = str(ip_layer.dst)
                    proto_num = ip_layer.nh
                else:
                    # Skip non-IP packets (ARP, STP, etc.)
                    continue

                packet_len = len(packet)
                pkt_time = float(packet.time) if hasattr(packet, "time") else t0

                src_port = None
                dst_port = None
                proto_str = "OTHER"
                is_fin_rst = False
                dns_query = None
                tls_sni = None

                if TCP in packet:
                    tcp = packet[TCP]
                    src_port = int(tcp.sport)
                    dst_port = int(tcp.dport)
                    proto_str = "TCP"
                    flags = str(tcp.flags)
                    if "F" in flags or "R" in flags:
                        is_fin_rst = True

                    # Extract TLS SNI if ClientHello present
                    try:
                        if TLSClientHello in packet and TLS_Ext_ServerName in packet:
                            server_names = packet[TLS_Ext_ServerName].servernames
                            if server_names:
                                tls_sni = server_names[0].servername.decode("utf-8", errors="ignore")
                    except Exception:
                        pass  # nosec B110

                elif UDP in packet:
                    udp = packet[UDP]
                    src_port = int(udp.sport)
                    dst_port = int(udp.dport)
                    proto_str = "UDP"

                    # Extract DNS query if port 53 or DNS layer present
                    if DNS in packet and packet[DNS].qd:
                        try:
                            qname = packet[DNS].qd.qname
                            if isinstance(qname, bytes):
                                dns_query = qname.decode("utf-8", errors="ignore").rstrip(".")
                            elif isinstance(qname, str):
                                dns_query = qname.rstrip(".")
                        except Exception:
                            pass  # nosec B110
                else:
                    proto_str = str(proto_num)

                builder.add_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto_str,
                    packet_len=packet_len,
                    timestamp=pkt_time,
                    is_fin_or_rst=is_fin_rst,
                    dns_query=dns_query,
                    tls_sni=tls_sni,
                )

    except Exception as e:
        logger.error("Error reading PCAP file %s: %s", file_path, e)
        if packet_count == 0:
            raise ValueError(f"Corrupt or unreadable PCAP file: {e}") from e

    # Flush remaining in-flight flows
    final_flows = builder.flush_all()
    logger.info("PCAP analysis complete: %d packets -> %d flows", packet_count, len(final_flows))
    return final_flows, packet_count

from __future__ import annotations


def calculate_recon_features(
    destination_ports: list[int],
    destination_hosts: list[str],
) -> dict[str, float]:
    unique_ports = len(set(destination_ports))
    unique_hosts = len(set(destination_hosts))

    return {
        "unique_dst_ports": float(unique_ports),
        "unique_dst_hosts": float(unique_hosts),
        "port_fanout": float(unique_ports),
        "host_fanout": float(unique_hosts),
    }


def calculate_byte_ratio(
    outbound_bytes: int,
    inbound_bytes: int,
) -> float:
    inbound = max(inbound_bytes, 1)

    return outbound_bytes / inbound

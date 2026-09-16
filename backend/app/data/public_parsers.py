from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def _normalize_row(row: dict[str, Any]) -> dict[str, str]:
    """Normalize dataset headers and values."""
    normalized: dict[str, str] = {}

    for key, value in row.items():
        if key is None:
            continue

        clean_key = str(key).strip().lstrip("\ufeff")
        clean_value = "" if value is None else str(value).strip()

        normalized[clean_key] = clean_value

    return normalized


def _normalize_cic_label(value: Any) -> str:
    """Normalize CIC-IDS2017 labels."""
    label = str(value or "").strip().upper()

    if label in {"BENIGN", "NORMAL", "0"}:
        return "BENIGN"

    if "DDOS" in label or label == "DOS":
        return "DDOS"

    if "PORTSCAN" in label or "SCAN" in label:
        return "RECON"

    if "BOT" in label:
        return "C2_BEACON"

    if not label:
        return "UNKNOWN"

    return label


def parse_cic_ids2017_csv(
    file_path: Path,
    max_rows: int = 1000,
    run_id: str = "run_a",
) -> list[dict[str, Any]]:
    """Parse a CIC-IDS2017 CSV fixture."""

    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError(
            f"CIC-IDS2017 fixture not found: {file_path}"
        )

    records: list[dict[str, Any]] = []

    with file_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:

        reader = csv.DictReader(handle)

        if not reader.fieldnames:
            raise ValueError(
                f"CIC-IDS2017 fixture has no header: {file_path}"
            )

        reader.fieldnames = [
            str(field).strip().lstrip("\ufeff")
            for field in reader.fieldnames
        ]

        for i, row in enumerate(reader):

            if i >= max_rows:
                break

            clean_row = _normalize_row(row)

            if not clean_row:
                continue

            raw_label = (
                clean_row.get("Label")
                or clean_row.get("label")
                or clean_row.get("Class")
                or clean_row.get("class")
            )

            if raw_label is None:
                continue

            threat_class = _normalize_cic_label(raw_label)

            try:
                duration_us = float(
                    clean_row.get("Flow Duration", "1000") or 1000
                )

                duration_seconds = max(
                    0.001,
                    duration_us / 1_000_000.0,
                )

                total_fwd_packets = int(
                    float(
                        clean_row.get(
                            "Total Fwd Packets",
                            "1",
                        ) or 1
                    )
                )

                total_bwd_packets = int(
                    float(
                        clean_row.get(
                            "Total Backward Packets",
                            "0",
                        ) or 0
                    )
                )

                total_fwd_bytes = int(
                    float(
                        clean_row.get(
                            "Total Length of Fwd Packets",
                            "60",
                        ) or 60
                    )
                )

                total_bwd_bytes = int(
                    float(
                        clean_row.get(
                            "Total Length of Bwd Packets",
                            "0",
                        ) or 0
                    )
                )

                src_port = int(
                    float(
                        clean_row.get(
                            "Source Port",
                            "49152",
                        ) or 49152
                    )
                )

                dst_port = int(
                    float(
                        clean_row.get(
                            "Destination Port",
                            "80",
                        ) or 80
                    )
                )

                protocol = clean_row.get(
                    "Protocol",
                    "6",
                )

                records.append(
                    {
                        "src_ip": clean_row.get(
                            "Source IP",
                            f"192.168.10.{i + 1}",
                        ),
                        "dst_ip": clean_row.get(
                            "Destination IP",
                            "192.168.10.1",
                        ),
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "proto": (
                            "TCP"
                            if protocol == "6"
                            else "UDP"
                        ),
                        "bytes_sent": total_fwd_bytes,
                        "bytes_recv": total_bwd_bytes,
                        "pkts_sent": total_fwd_packets,
                        "pkts_recv": total_bwd_packets,
                        "duration_seconds": duration_seconds,
                        "sensor_id": "public-cic-ids2017",
                        "source_format": "public_cic_ids2017",
                        "run_id": run_id,
                        "label": (
                            0
                            if threat_class == "BENIGN"
                            else 1
                        ),
                        "threat_class": threat_class,
                    }
                )

            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"Invalid CIC-IDS2017 row {i + 2} "
                    f"in {file_path}: {exc}"
                ) from exc

    if not records:
        raise ValueError(
            f"CIC-IDS2017 fixture produced no records: "
            f"{file_path}"
        )

    return records


def parse_ctu13_binetflow(
    file_path: Path,
    max_rows: int = 1000,
    run_id: str = "run_a",
) -> list[dict[str, Any]]:
    """Parse a CTU-13 .binetflow fixture."""

    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError(
            f"CTU-13 fixture not found: {file_path}"
        )

    records: list[dict[str, Any]] = []

    with file_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:

        reader = csv.DictReader(handle)

        if not reader.fieldnames:
            raise ValueError(
                f"CTU-13 fixture has no header: {file_path}"
            )

        reader.fieldnames = [
            str(field).strip().lstrip("\ufeff")
            for field in reader.fieldnames
        ]

        for i, row in enumerate(reader):

            if i >= max_rows:
                break

            clean_row = _normalize_row(row)

            raw_label = (
                clean_row.get("Label")
                or clean_row.get("label")
                or "Normal"
            ).upper()

            is_botnet = (
                "BOTNET" in raw_label
                or "BOT" in raw_label
            )

            try:
                duration = float(
                    clean_row.get("Dur", "0.1") or 0.1
                )

                total_packets = int(
                    float(
                        clean_row.get(
                            "TotPkts",
                            "1",
                        ) or 1
                    )
                )

                total_bytes = int(
                    float(
                        clean_row.get(
                            "TotBytes",
                            "64",
                        ) or 64
                    )
                )

                src_bytes = int(
                    float(
                        clean_row.get(
                            "SrcBytes",
                            str(total_bytes // 2),
                        )
                        or total_bytes // 2
                    )
                )

                sport_value = clean_row.get(
                    "Sport",
                    "40000",
                )

                dport_value = clean_row.get(
                    "Dport",
                    "80",
                )

                sport = (
                    int(sport_value)
                    if sport_value.isdigit()
                    else 40000
                )

                dport = (
                    int(dport_value)
                    if dport_value.isdigit()
                    else 80
                )

                records.append(
                    {
                        "src_ip": clean_row.get(
                            "SrcAddr",
                            "10.0.2.15",
                        ),
                        "dst_ip": clean_row.get(
                            "DstAddr",
                            "147.32.84.180",
                        ),
                        "src_port": sport,
                        "dst_port": dport,
                        "proto": clean_row.get(
                            "Proto",
                            "tcp",
                        ).upper(),
                        "bytes_sent": src_bytes,
                        "bytes_recv": max(
                            0,
                            total_bytes - src_bytes,
                        ),
                        "pkts_sent": max(
                            1,
                            total_packets // 2,
                        ),
                        "pkts_recv": max(
                            0,
                            total_packets
                            - total_packets // 2,
                        ),
                        "duration_seconds": max(
                            0.001,
                            duration,
                        ),
                        "sensor_id": "public-ctu-13",
                        "source_format": "public_ctu13",
                        "run_id": run_id,
                        "label": 1 if is_botnet else 0,
                        "threat_class": (
                            "C2_BEACON"
                            if is_botnet
                            else "BENIGN"
                        ),
                    }
                )

            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"Invalid CTU-13 row {i + 2} "
                    f"in {file_path}: {exc}"
                ) from exc

    if not records:
        raise ValueError(
            f"CTU-13 fixture produced no records: "
            f"{file_path}"
        )

    return records

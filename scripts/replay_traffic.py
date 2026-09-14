#!/usr/bin/env python3
"""
SentinelFlow Traffic Replay Tool.

Replays recorded flow telemetry (from data/sample/demo_flows.csv or JSONL)
into the SentinelFlow Ingestion API at configurable playback speeds:
- Live streaming simulation: sends 1 flow at a time
- Configurable playback velocity (e.g. 10, 50, 100 flows/second)
- Shows real-time detection feedback as alerts are triggered
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import httpx

DEFAULT_API_URL = "http://localhost:8000/api/v1/ingest/flow"
DEFAULT_SAMPLE_FILE = Path(__file__).resolve().parent.parent / "data" / "sample" / "demo_flows.csv"


def load_demo_csv(file_path: Path) -> List[Dict[str, Any]]:
    flows: List[Dict[str, Any]] = []
    if not file_path.exists():
        print(f"[-] Sample file not found: {file_path}")
        return flows

    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                flows.append({
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "src_port": int(row.get("src_port") or 49152),
                    "dst_port": int(row.get("dst_port") or 80),
                    "proto": row.get("protocol", "TCP"),
                    "bytes_sent": int(float(row.get("bytes") or 100)) // 2,
                    "bytes_recv": int(float(row.get("bytes") or 100)) // 2,
                    "pkts_sent": max(1, int(float(row.get("packets") or 2)) // 2),
                    "pkts_recv": max(0, int(float(row.get("packets") or 2)) // 2),
                    "duration_seconds": float(row.get("duration") or 0.05),
                    "sensor_id": "replay-tool",
                    "source_format": "traffic_replay",
                })
            except (KeyError, ValueError):
                continue

    return flows


def replay_traffic(
    flows: List[Dict[str, Any]],
    target_url: str = DEFAULT_API_URL,
    rate_fps: float = 20.0,
    loop: bool = False,
):
    print("==========================================================")
    print("        SentinelFlow Streaming Traffic Replayer           ")
    print("==========================================================")
    print(f" Target API:       {target_url}")
    print(f" Replay Velocity:  {rate_fps} flows/sec")
    print(f" Total Flow Pool:  {len(flows)} flows")
    print("----------------------------------------------------------")

    interval_sec = 1.0 / max(1.0, rate_fps)
    sent_count = 0
    alerts_triggered = 0

    client = httpx.Client(timeout=5.0)

    try:
        while True:
            for flow in flows:
                t0 = time.perf_counter()
                try:
                    resp = client.post(target_url, json=flow)
                    sent_count += 1
                    if resp.status_code == 200:
                        data = resp.json()
                        alerts_count = data.get("alerts_generated", 0)
                        if alerts_count > 0:
                            alerts_triggered += alerts_count
                            threat = "ALERT"
                            if data.get("alert"):
                                threat = data["alert"].get("threat_class", "ALERT")
                            print(f" [!] Flow #{sent_count:04d} -> THREAT DETECTED: {threat} from {flow['src_ip']} -> {flow['dst_ip']}")
                        else:
                            print(f" [.] Flow #{sent_count:04d} -> Benign ({flow['src_ip']}:{flow['dst_port']})", end="\r")
                    else:
                        print(f" [-] Flow #{sent_count:04d} -> HTTP {resp.status_code}")
                except Exception as e:
                    print(f" [-] Connection error: {e}")
                    print("     (Make sure backend is running: uvicorn app.main:app --port 8000)")
                    return

                elapsed = time.perf_counter() - t0
                sleep_time = max(0.0, interval_sec - elapsed)
                if sleep_time > 0:
                    time.sleep(sleep_time)

            if not loop:
                break
            print("\n[*] Looping flow pool...")

    except KeyboardInterrupt:
        print("\n[*] Replay cancelled by user.")

    print("\n----------------------------------------------------------")
    print(f" Replay Finished: {sent_count} flows replayed, {alerts_triggered} threats caught.")
    print("==========================================================")


def main():
    parser = argparse.ArgumentParser(description="SentinelFlow Traffic Replayer")
    parser.add_argument("--file", type=Path, default=DEFAULT_SAMPLE_FILE, help="Path to CSV flow dataset")
    parser.add_argument("--url", type=str, default=DEFAULT_API_URL, help="Ingest API URL")
    parser.add_argument("--rate", type=float, default=20.0, help="Replay rate in flows per second")
    parser.add_argument("--loop", action="store_true", help="Loop continuously")
    args = parser.parse_args()

    flows = load_demo_csv(args.file)
    if not flows:
        print("[-] No flows to replay.")
        sys.exit(1)

    replay_traffic(flows=flows, target_url=args.url, rate_fps=args.rate, loop=args.loop)


if __name__ == "__main__":
    main()

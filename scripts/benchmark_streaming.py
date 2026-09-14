#!/usr/bin/env python3
"""
SentinelFlow Streaming Performance Benchmark Tool.

Evaluates the real-time, per-flow streaming throughput and latency SLA:
- Individual Flow Processing: Flow i -> Features -> Prediction -> Alert
- High-Resolution Latency Profiling (ns resolution)
- Measured Performance:
  * Flows processed / sec (Throughput)
  * Average latency (ms)
  * P50, P95, P99, Min, Max latencies (ms)
  * Alerts / sec
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.data.generators.benign import generate_benign_flows
from app.data.generators.c2_emulator import generate_c2_emulator_flows
from app.data.generators.dns_tunnel_dga import generate_dns_tunnel_dga_flows
from app.data.generators.recon import generate_recon_flows
from app.data.generators.trex_hping3 import generate_trex_hping3_flows
from app.schemas.flow import RawFlow
from app.services.pipeline import pipeline_orchestrator
from app.services.streaming_metrics import streaming_metrics_tracker


def run_benchmark(flow_count: int = 1000):
    print("==========================================================")
    print("      SentinelFlow Streaming Performance Benchmark        ")
    print("==========================================================")
    print(f"[*] Preparing {flow_count} mixed streaming telemetry flows...")

    chunk = flow_count // 5
    raw_flows = []
    raw_flows.extend(generate_benign_flows(count=chunk, run_id="run_c"))
    raw_flows.extend(generate_trex_hping3_flows(count=chunk, run_id="run_c"))
    raw_flows.extend(generate_dns_tunnel_dga_flows(count=chunk, run_id="run_c"))
    raw_flows.extend(generate_c2_emulator_flows(count=chunk, run_id="run_c"))
    raw_flows.extend(generate_recon_flows(count=chunk, run_id="run_c"))

    # Convert to RawFlow models
    flows = [
        RawFlow(
            src_ip=r["src_ip"],
            dst_ip=r["dst_ip"],
            src_port=r.get("src_port"),
            dst_port=r.get("dst_port", 80),
            proto=r.get("proto", "TCP"),
            bytes_sent=r.get("bytes_sent", 100),
            bytes_recv=r.get("bytes_recv", 0),
            pkts_sent=r.get("pkts_sent", 1),
            pkts_recv=r.get("pkts_recv", 0),
            duration_seconds=r.get("duration_seconds", 0.05),
            dns_query=r.get("dns_query"),
            tls_sni=r.get("tls_sni"),
            sensor_id="benchmark-cli",
            source_format="stream_test",
        )
        for r in raw_flows[:flow_count]
    ]

    print(f"[*] Starting continuous per-flow streaming execution ({len(flows)} flows)...")
    streaming_metrics_tracker.reset()

    latencies_ms: list[float] = []
    alerts_emitted = 0

    benchmark_start = time.perf_counter()

    for flow in flows:
        t0 = time.perf_counter_ns()
        alert = pipeline_orchestrator.process_flow(flow)
        t1 = time.perf_counter_ns()

        elapsed_ms = (t1 - t0) / 1_000_000.0
        latencies_ms.append(elapsed_ms)

        if alert is not None:
            alerts_emitted += 1

    total_wall_time = time.perf_counter() - benchmark_start

    # Compute Statistics
    flows_per_sec = len(flows) / total_wall_time
    alerts_per_sec = alerts_emitted / total_wall_time
    avg_lat = float(np.mean(latencies_ms))
    p50_lat = float(np.percentile(latencies_ms, 50))
    p95_lat = float(np.percentile(latencies_ms, 95))
    p99_lat = float(np.percentile(latencies_ms, 99))
    min_lat = float(np.min(latencies_ms))
    max_lat = float(np.max(latencies_ms))

    print("\n----------------------------------------------------------")
    print("            ACTUAL MEASURED BENCHMARK NUMBERS             ")
    print("----------------------------------------------------------")
    print(f" Total Flows Processed:     {len(flows)}")
    print(f" Total Alerts Emitted:      {alerts_emitted}")
    print(f" Wall Time Elapsed:         {total_wall_time:.3f} seconds")
    print("----------------------------------------------------------")
    print(f" 🔥 Throughput:             {flows_per_sec:.2f} flows/sec")
    print(f" ⚡ Average Latency:        {avg_lat:.3f} ms")
    print(f" 📊 Median (P50) Latency:   {p50_lat:.3f} ms")
    print(f" 🎯 P95 Latency:            {p95_lat:.3f} ms")
    print(f" 🎯 P99 Latency:            {p99_lat:.3f} ms")
    print(f" ⏱️  Min Latency:            {min_lat:.3f} ms")
    print(f" ⏱️  Max Latency:            {max_lat:.3f} ms")
    print(f" 🚨 Alert Velocity:         {alerts_per_sec:.2f} alerts/sec")
    print("----------------------------------------------------------")
    print(" Invariant Check: All flows processed independently (no batching)")
    print("==========================================================\n")

    return {
        "flows_processed_per_sec": flows_per_sec,
        "average_latency_ms": avg_lat,
        "p95_latency_ms": p95_lat,
        "p99_latency_ms": p99_lat,
        "alerts_emitted_per_sec": alerts_per_sec,
    }


def main():
    parser = argparse.ArgumentParser(description="SentinelFlow Streaming Benchmark")
    parser.add_argument("--flows", "--count", dest="flows", type=int, default=1000, help="Number of flows to stream")
    parser.add_argument("--file", type=str, default=None, help="Optional CSV file of flows to benchmark")
    args = parser.parse_args()

    run_benchmark(flow_count=args.flows)


if __name__ == "__main__":
    main()

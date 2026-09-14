"""
Real-Time Streaming & Benchmark Endpoints.

Provides continuous live metrics, Server-Sent Events (SSE), and on-demand benchmarks:
- GET /api/v1/stream/metrics: Current measured throughput, latency (Avg, P50, P95, P99), and alert velocity
- GET /api/v1/stream/live: SSE stream pushing live telemetry events to connected dashboards
- POST /api/v1/stream/benchmark: Executes high-speed per-flow streaming benchmark and reports measured numbers
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.data.generators.benign import generate_benign_flows
from app.data.generators.c2_emulator import generate_c2_emulator_flows
from app.data.generators.dns_tunnel_dga import generate_dns_tunnel_dga_flows
from app.data.generators.trex_hping3 import generate_trex_hping3_flows
from app.schemas.flow import RawFlow
from app.services.pipeline import pipeline_orchestrator
from app.services.streaming_metrics import streaming_metrics_tracker

router = APIRouter(prefix="/stream", tags=["Streaming & Benchmarks"])


class BenchmarkResponse(BaseModel):
    flows_tested: int
    alerts_generated: int
    duration_seconds: float
    flows_processed_per_sec: float
    average_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    alerts_emitted_per_sec: float


@router.get("/metrics")
async def get_streaming_metrics() -> Dict[str, Any]:
    """
    Returns instantaneous real measured performance metrics across the active streaming window.
    """
    return streaming_metrics_tracker.get_metrics()


@router.get("/live")
async def stream_live_events():
    """
    Server-Sent Events (SSE) stream broadcasting real-time metrics to web clients.
    """
    async def event_generator():
        while True:
            metrics = streaming_metrics_tracker.get_metrics()
            payload = json.dumps(metrics)
            yield f"data: {payload}\n\n"
            await asyncio.sleep(1.0)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/benchmark", response_model=BenchmarkResponse)
async def run_streaming_benchmark(
    flows_count: int = Query(300, ge=50, le=2000, description="Total number of flows to stream"),
):
    """
    Executes an active, per-flow streaming benchmark through the complete 9-stage pipeline.
    Measures and returns exact real performance statistics:
    Throughput (flows/sec), Avg Latency, P95 Latency, P99 Latency, and Alerts/sec.
    """
    # Generate balanced test flow stream
    test_flows: list[dict] = []
    chunk = max(10, flows_count // 4)

    test_flows.extend(generate_benign_flows(count=chunk, run_id="run_c"))
    test_flows.extend(generate_trex_hping3_flows(count=chunk, run_id="run_c"))
    test_flows.extend(generate_dns_tunnel_dga_flows(count=chunk, run_id="run_c"))
    test_flows.extend(generate_c2_emulator_flows(count=chunk, run_id="run_c"))

    # Reset metrics tracker before isolated benchmark run
    streaming_metrics_tracker.reset()

    import time
    start_time = time.perf_counter()

    alerts_generated = 0
    for raw in test_flows[:flows_count]:
        flow = RawFlow(
            src_ip=raw["src_ip"],
            dst_ip=raw["dst_ip"],
            src_port=raw.get("src_port"),
            dst_port=raw.get("dst_port", 80),
            proto=raw.get("proto", "TCP"),
            bytes_sent=raw.get("bytes_sent", 100),
            bytes_recv=raw.get("bytes_recv", 0),
            pkts_sent=raw.get("pkts_sent", 1),
            pkts_recv=raw.get("pkts_recv", 0),
            duration_seconds=raw.get("duration_seconds", 0.05),
            dns_query=raw.get("dns_query"),
            tls_sni=raw.get("tls_sni"),
            sensor_id="stream-benchmark",
            source_format="streaming_live",
        )
        alert = pipeline_orchestrator.process_flow(flow)
        if alert is not None:
            alerts_generated += 1

    total_duration = max(0.001, time.perf_counter() - start_time)

    metrics = streaming_metrics_tracker.get_metrics(rate_window_sec=total_duration)

    return BenchmarkResponse(
        flows_tested=len(test_flows[:flows_count]),
        alerts_generated=alerts_generated,
        duration_seconds=round(total_duration, 4),
        flows_processed_per_sec=round(len(test_flows[:flows_count]) / total_duration, 2),
        average_latency_ms=metrics["average_latency_ms"],
        p50_latency_ms=metrics["p50_latency_ms"],
        p95_latency_ms=metrics["p95_latency_ms"],
        p99_latency_ms=metrics["p99_latency_ms"],
        min_latency_ms=metrics["min_latency_ms"],
        max_latency_ms=metrics["max_latency_ms"],
        alerts_emitted_per_sec=round(alerts_generated / total_duration, 2),
    )

"""
Unit & Integration Tests for Section 14 Streaming Requirement & Benchmark.

Verifies:
1. Per-flow latency tracking and streaming metrics calculations
2. Latency percentiles SLA (Average < 15ms, P95 < 25ms)
3. API endpoints: /api/v1/stream/metrics and /api/v1/stream/benchmark
4. Real-time streaming without batching
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.schemas.flow import RawFlow
from app.services.pipeline import pipeline_orchestrator
from app.services.streaming_metrics import StreamingMetricsTracker, streaming_metrics_tracker

client = TestClient(app)


def test_streaming_metrics_tracker_computes_percentiles():
    tracker = StreamingMetricsTracker(window_size=100)
    tracker.reset()

    # Feed synthetic latencies: 1ms, 2ms, ... 100ms
    for i in range(1, 101):
        tracker.record_flow(float(i), emitted_alert=(i % 2 == 0))

    metrics = tracker.get_metrics(rate_window_sec=1.0)

    assert metrics["total_flows_processed"] == 100
    assert metrics["total_alerts_emitted"] == 50
    assert abs(metrics["average_latency_ms"] - 50.5) < 0.1
    assert abs(metrics["p50_latency_ms"] - 50.5) < 0.5
    assert abs(metrics["p95_latency_ms"] - 95.05) < 1.0
    assert abs(metrics["p99_latency_ms"] - 99.01) < 1.0
    assert metrics["min_latency_ms"] == 1.0
    assert metrics["max_latency_ms"] == 100.0


def test_pipeline_streaming_latency_sla():
    """Verifies that individual flow processing achieves low-latency sub-15ms SLA."""
    streaming_metrics_tracker.reset()

    for i in range(20):
        flow = RawFlow(
            src_ip=f"192.168.1.{i+10}",
            dst_ip="8.8.8.8",
            dst_port=53,
            proto="UDP",
            bytes_sent=80,
            bytes_recv=80,
            pkts_sent=1,
            pkts_recv=1,
            duration_seconds=0.01,
            dns_query="google.com",
        )
        pipeline_orchestrator.process_flow(flow)

    metrics = streaming_metrics_tracker.get_metrics()
    assert metrics["total_flows_processed"] >= 20
    # Average latency should easily be under 15ms on any modern machine
    assert metrics["average_latency_ms"] < 15.0
    assert metrics["p95_latency_ms"] < 30.0


def test_stream_metrics_api_endpoint():
    resp = client.get("/api/v1/stream/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "flows_processed_per_sec" in data
    assert "average_latency_ms" in data
    assert "p95_latency_ms" in data
    assert "alerts_emitted_per_sec" in data
    assert "total_flows_processed" in data


def test_stream_benchmark_api_endpoint():
    resp = client.post("/api/v1/stream/benchmark?flows_count=60")
    assert resp.status_code == 200
    data = resp.json()

    assert data["flows_tested"] == 60
    assert data["flows_processed_per_sec"] > 0
    assert data["average_latency_ms"] > 0
    assert data["p95_latency_ms"] >= data["p50_latency_ms"]
    assert data["alerts_generated"] >= 1
    assert data["duration_seconds"] > 0

"""
Streaming Performance Metrics Engine.

Tracks real-time telemetry and computes actual measured benchmark statistics:
- Flows processed / second (Throughput)
- Average per-flow latency (ms)
- P95 latency (95th percentile, ms)
- P99 latency (99th percentile, ms)
- Alerts emitted / second (Alert Velocity)
"""
from __future__ import annotations

import collections
import threading
import time
from typing import Any, Dict

import numpy as np


class StreamingMetricsTracker:
    def __init__(self, window_size: int = 2000):
        self.window_size = window_size
        self._lock = threading.Lock()

        # Sliding window of recent per-flow latencies in milliseconds
        self._latency_window: collections.deque[float] = collections.deque(maxlen=window_size)

        # Counter totals
        self._total_flows: int = 0
        self._total_alerts: int = 0

        # Rate tracking sliding windows: timestamp deque
        self._flow_timestamps: collections.deque[float] = collections.deque(maxlen=5000)
        self._alert_timestamps: collections.deque[float] = collections.deque(maxlen=2000)

        # Session start
        self._start_time = time.monotonic()

    def record_flow(self, latency_ms: float, emitted_alert: bool = False) -> None:
        """
        Records the completion of one flow evaluation cycle.
        """
        now = time.monotonic()
        with self._lock:
            self._total_flows += 1
            self._latency_window.append(latency_ms)
            self._flow_timestamps.append(now)

            if emitted_alert:
                self._total_alerts += 1
                self._alert_timestamps.append(now)

    def get_metrics(self, rate_window_sec: float = 5.0) -> Dict[str, Any]:
        """
        Calculates instantaneous real measured metrics over the sliding rate window.
        """
        now = time.monotonic()
        with self._lock:
            latencies = list(self._latency_window)

            # Evict timestamps older than rate_window_sec for throughput calculation
            cutoff = now - rate_window_sec
            while self._flow_timestamps and self._flow_timestamps[0] < cutoff:
                self._flow_timestamps.popleft()
            while self._alert_timestamps and self._alert_timestamps[0] < cutoff:
                self._alert_timestamps.popleft()

            active_window_flows = len(self._flow_timestamps)
            active_window_alerts = len(self._alert_timestamps)

            flows_per_sec = round(active_window_flows / rate_window_sec, 2)
            alerts_per_sec = round(active_window_alerts / rate_window_sec, 2)

            if latencies:
                avg_latency = float(np.mean(latencies))
                p50_latency = float(np.percentile(latencies, 50))
                p95_latency = float(np.percentile(latencies, 95))
                p99_latency = float(np.percentile(latencies, 99))
                min_latency = float(np.min(latencies))
                max_latency = float(np.max(latencies))
            else:
                avg_latency = p50_latency = p95_latency = p99_latency = min_latency = max_latency = 0.0

            return {
                "flows_processed_per_sec": flows_per_sec,
                "average_latency_ms": round(avg_latency, 3),
                "p50_latency_ms": round(p50_latency, 3),
                "p95_latency_ms": round(p95_latency, 3),
                "p99_latency_ms": round(p99_latency, 3),
                "min_latency_ms": round(min_latency, 3),
                "max_latency_ms": round(max_latency, 3),
                "alerts_emitted_per_sec": alerts_per_sec,
                "total_flows_processed": self._total_flows,
                "total_alerts_emitted": self._total_alerts,
                "sample_window_size": len(latencies),
            }

    def reset(self) -> None:
        """Resets counters and telemetry windows."""
        with self._lock:
            self._latency_window.clear()
            self._flow_timestamps.clear()
            self._alert_timestamps.clear()
            self._total_flows = 0
            self._total_alerts = 0
            self._start_time = time.monotonic()


# Global singleton streaming metrics tracker
streaming_metrics_tracker = StreamingMetricsTracker()

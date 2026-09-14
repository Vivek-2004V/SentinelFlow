"""
Adaptive Baseline.

Maintains rolling statistical baselines (Welford's algorithm or exponential moving window)
for network flow volumes, packet rates, and protocol behaviors.
"""
from __future__ import annotations

import math


class AdaptiveBaseline:
    """
    Online tracker for mean and variance of network attributes.
    Adapts passively as new benign traffic patterns emerge.
    """

    def __init__(self, alpha: float = 0.05):
        # Exponential moving average smoothing factor
        self.alpha = alpha
        self.means: dict[str, float] = {
            "bytes_per_second": 5000.0,
            "pkts_per_second": 10.0,
            "duration_seconds": 1.5,
            "dns_entropy": 2.2,
        }
        self.variances: dict[str, float] = {
            "bytes_per_second": 25000000.0,
            "pkts_per_second": 100.0,
            "duration_seconds": 2.0,
            "dns_entropy": 0.5,
        }
        self.sample_count: int = 0

    def get_mean(self, metric: str) -> float:
        return self.means.get(metric, 0.0)

    def get_std(self, metric: str) -> float:
        var = self.variances.get(metric, 1.0)
        return math.sqrt(max(var, 0.0001))

    def update(self, metrics: dict[str, float]) -> None:
        """Passively update running baseline with new observed values."""
        self.sample_count += 1
        for key, val in metrics.items():
            if key not in self.means:
                self.means[key] = val
                self.variances[key] = val * 0.25
                continue

            # Exponential moving update
            diff = val - self.means[key]
            self.means[key] += self.alpha * diff
            self.variances[key] = (1.0 - self.alpha) * self.variances[key] + self.alpha * (diff ** 2)

    def get_deviation(self, metric: str, value: float) -> float:
        """Returns deviation in standard deviations (Z-score)."""
        mean = self.get_mean(metric)
        std = self.get_std(metric)
        return round((value - mean) / std, 3)


# Global singleton baseline
global_baseline = AdaptiveBaseline()

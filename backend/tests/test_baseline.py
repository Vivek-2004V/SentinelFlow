"""
Test Suite: Adaptive Baseline Engine (Step 10.2)
Verifies rolling baseline calculation, Z-score deviation, and minimum sample bounds.
"""
from app.baseline.adaptive import AdaptiveBaseline


def test_baseline_initialization():
    baseline = AdaptiveBaseline(window_size=50)
    assert baseline.window_size == 50
    assert len(baseline.history) == 0


def test_baseline_insufficient_samples():
    baseline = AdaptiveBaseline(window_size=50)
    entity = "10.0.0.15"

    # With fewer than 5 samples, deviation should return 0.0 (still learning)
    for val in [100.0, 105.0, 95.0, 102.0]:
        baseline.update(entity, val)

    assert baseline.deviation(entity, 500.0) == 0.0


def test_baseline_normal_deviation():
    baseline = AdaptiveBaseline(window_size=50)
    entity = "10.0.0.15"

    # Establish baseline with tight variance
    for _ in range(10):
        baseline.update(entity, 100.0)
    baseline.update(entity, 102.0)
    baseline.update(entity, 98.0)

    # A normal value close to mean should have low Z-score deviation (< 1.5)
    dev_normal = baseline.deviation(entity, 101.0)
    assert dev_normal < 2.0


def test_baseline_anomalous_deviation():
    baseline = AdaptiveBaseline(window_size=50)
    entity = "10.0.0.25"

    # Establish baseline around 50.0 +- 2
    for val in [48.0, 50.0, 52.0, 49.0, 51.0, 50.0, 50.5, 49.5]:
        baseline.update(entity, val)

    # A surge to 500.0 is an extreme outlier
    dev_surge = baseline.deviation(entity, 500.0)
    assert dev_surge > 5.0

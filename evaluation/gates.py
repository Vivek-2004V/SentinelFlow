"""
SentinelFlow AI Evaluation Suite — Gate Orchestration
(evaluation/gates.py)
"""
from __future__ import annotations

from typing import Any, Dict, List

from evaluation.dataset_validator import validate_dataset_partitions
from evaluation.model_validator import validate_models_and_metrics
from evaluation.schemas import GateSummary


def evaluate_all_gates() -> Dict[str, Any]:
    """
    Executes all Four Gates sequentially and collects metrics and error diagnostics.
    """
    dataset_status, preflight_status, dataset_errors = validate_dataset_partitions()
    models_status, metrics, smoke_status, signal_status, controlled_status, model_errors = validate_models_and_metrics()

    gates = GateSummary(
        preflight=preflight_status,
        smoke=smoke_status,
        signal=signal_status,
        controlled=controlled_status,
    )

    all_errors: List[str] = dataset_errors + model_errors

    return {
        "gates": gates,
        "dataset": dataset_status,
        "models": models_status,
        "metrics": metrics,
        "errors": all_errors,
    }

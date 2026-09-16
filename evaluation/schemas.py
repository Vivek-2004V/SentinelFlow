"""
SentinelFlow AI Evaluation Suite — Schemas & Data Contracts
(evaluation/schemas.py)
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Literal
from pydantic import BaseModel, Field

GateStatus = Literal["PASS", "FAIL", "WARN", "UNVERIFIED"]


class GateSummary(BaseModel):
    preflight: GateStatus = "UNVERIFIED"
    smoke: GateStatus = "UNVERIFIED"
    signal: GateStatus = "UNVERIFIED"
    controlled: GateStatus = "UNVERIFIED"


class ModelsStatus(BaseModel):
    random_forest: str = "UNKNOWN"
    isolation_forest: str = "UNKNOWN"
    feature_columns: str = "UNKNOWN"
    label_encoder: str = "UNKNOWN"


class DatasetStatus(BaseModel):
    train: bool = False
    validation: bool = False
    test: bool = False
    leakage: bool = False
    train_samples: int = 0
    validation_samples: int = 0
    test_samples: int = 0


class MetricsSummary(BaseModel):
    validation_macro_f1: float = 0.0
    test_macro_f1: float = 0.0
    generalization_delta: float = 0.0
    throughput_fps: int = 0
    latency_us: float = 0.0
    per_class_f1: Dict[str, float] = Field(default_factory=dict)


class LLMSummary(BaseModel):
    grounding: GateStatus = "UNVERIFIED"
    safety: GateStatus = "UNVERIFIED"
    immutability: GateStatus = "UNVERIFIED"


class SecuritySummary(BaseModel):
    passive_only: bool = True
    return_path_blocked: bool = True
    action_alert_only: bool = True


class EvaluationReport(BaseModel):
    status: GateStatus = "UNVERIFIED"
    gates: GateSummary = Field(default_factory=GateSummary)
    models: ModelsStatus = Field(default_factory=ModelsStatus)
    dataset: DatasetStatus = Field(default_factory=DatasetStatus)
    metrics: MetricsSummary = Field(default_factory=MetricsSummary)
    llm: LLMSummary = Field(default_factory=LLMSummary)
    security: SecuritySummary = Field(default_factory=SecuritySummary)
    release_ready: bool = False
    release_status: Literal["READY", "BLOCKED"] = "BLOCKED"
    failure_reasons: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

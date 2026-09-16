"""
Evaluation API Endpoints (backend/app/api/v1/endpoints/evaluation.py)

Exposes the AI Quality Gate evaluation status and live verification runs
for the SOC dashboard.
"""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi import APIRouter, status

# Ensure root evaluation module is reachable
PROJECT_ROOT = Path(__file__).resolve().parents[5]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.evaluator import evaluation_engine
from evaluation.schemas import EvaluationReport

router = APIRouter(prefix="/evaluation", tags=["AI Quality Gate"])


@router.get("/status", response_model=EvaluationReport, status_code=status.HTTP_200_OK)
async def get_evaluation_status():
    """
    Returns the latest AI Quality Gate evaluation report.
    """
    return evaluation_engine.get_status()


@router.post("/run", response_model=EvaluationReport, status_code=status.HTTP_200_OK)
async def run_full_evaluation():
    """
    Triggers a live, end-to-end evaluation across all Four Gates
    (Preflight, Smoke, Signal, Controlled), LLM grounding/safety,
    and security boundaries. Zero-mock.
    """
    return evaluation_engine.run_evaluation()

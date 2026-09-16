"""
SentinelFlow AI Evaluation Engine (evaluation/evaluator.py)

Central evaluator service that runs comprehensive real-time evaluations
and produces verified EvaluationReport schemas.
"""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Optional

from evaluation.gates import evaluate_all_gates
from evaluation.llm_check import run_llm_check
from evaluation.regression_check import check_security_boundary
from evaluation.schemas import (
    EvaluationReport,
    LLMSummary,
    SecuritySummary,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "evaluation" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class EvaluationEngine:
    _cached_report: Optional[EvaluationReport] = None

    @classmethod
    def run_evaluation(cls) -> EvaluationReport:
        """
        Executes a real, zero-mock evaluation of datasets, models,
        LLM grounding/safety, and security boundaries.
        """
        gate_data = evaluate_all_gates()
        llm_res = run_llm_check()
        sec_res = check_security_boundary()

        gates = gate_data["gates"]
        dataset = gate_data["dataset"]
        models = gate_data["models"]
        metrics = gate_data["metrics"]
        errors = list(gate_data["errors"])

        llm_summary = LLMSummary(
            grounding=llm_res.get("evidence_grounding", "FAIL"),
            safety=llm_res.get("passive_safety_check", "FAIL"),
            immutability=llm_res.get("alert_immutability", "FAIL"),
        )
        if llm_res.get("errors"):
            errors.extend(llm_res["errors"])

        security_summary = SecuritySummary(
            passive_only=(sec_res.get("passive_architecture") == "PASS"),
            return_path_blocked=(sec_res.get("return_path_blocked") == "PASS"),
            action_alert_only=(sec_res.get("action_alert_only") == "PASS"),
        )
        if sec_res.get("errors"):
            errors.extend(sec_res["errors"])

        # Determine overall pass/fail
        all_gates_pass = (
            gates.preflight == "PASS"
            and gates.smoke == "PASS"
            and gates.signal == "PASS"
            and gates.controlled == "PASS"
            and llm_summary.grounding == "PASS"
            and llm_summary.safety == "PASS"
            and security_summary.passive_only
        )

        overall_status = "PASS" if all_gates_pass else "FAIL"
        release_ready = all_gates_pass
        release_status = "READY" if release_ready else "BLOCKED"

        report = EvaluationReport(
            status=overall_status,
            gates=gates,
            models=models,
            dataset=dataset,
            metrics=metrics,
            llm=llm_summary,
            security=security_summary,
            release_ready=release_ready,
            release_status=release_status,
            failure_reasons=errors,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )

        cls._cached_report = report

        # Persist report
        try:
            latest_path = REPORTS_DIR / "latest_evaluation.json"
            with open(latest_path, "w") as f:
                json.dump(report.model_dump(), f, indent=2)
        except Exception:
            pass

        return report

    @classmethod
    def get_status(cls) -> EvaluationReport:
        """
        Returns cached report if available, else executes a live evaluation.
        """
        if cls._cached_report is not None:
            return cls._cached_report

        # Try reading from latest_evaluation.json
        latest_path = REPORTS_DIR / "latest_evaluation.json"
        if latest_path.exists():
            try:
                data = json.loads(latest_path.read_text())
                cls._cached_report = EvaluationReport(**data)
                return cls._cached_report
            except Exception:
                pass

        return cls.run_evaluation()


evaluation_engine = EvaluationEngine()

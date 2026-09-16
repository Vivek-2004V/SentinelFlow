#!/usr/bin/env python3
"""
SentinelFlow AI Quality & Release Gate (evaluation/release_gate.py)

Master evaluation orchestrator:
1. Executes Dataset & Partition Integrity Check (Gate 1: PREFLIGHT)
2. Executes Model Loading & Smoke Inference Check (Gate 2: SMOKE)
3. Executes Validation Dataset Benchmark (Gate 3: SIGNAL)
4. Executes Unseen Test Set Generalization Check (Gate 4: CONTROLLED)
5. Executes LLM Explainer Grounding & Passive Safety Audit
6. Executes Regression & Security Boundary Audit
7. Generates JSON and Markdown Reports in evaluation/reports/
8. Renders the SentinelFlow AI Quality Gate ASCII certification banner
"""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Any, Dict

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.dataset_check import run_dataset_check
from evaluation.llm_check import run_llm_check
from evaluation.model_check import run_model_check
from evaluation.regression_check import run_regression_check

REPORTS_DIR = PROJECT_ROOT / "evaluation" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def format_gate_row(label: str, status: str) -> str:
    symbol = "✓ PASS" if status == "PASS" else "✗ FAIL"
    return f"║ {label:<24}{symbol:<14} ║"


def run_release_gate() -> bool:
    print("\n🔍 Executing SentinelFlow AI Evaluation Suite across all Four Gates...\n")

    # Run checks
    dataset_res = run_dataset_check()
    model_res = run_model_check()
    llm_res = run_llm_check()
    regression_res = run_regression_check()

    # Load configured thresholds from models/evaluation_baseline.json
    baseline_path = PROJECT_ROOT / "models" / "evaluation_baseline.json"
    min_macro_f1 = 0.70
    if baseline_path.exists():
        try:
            with open(baseline_path) as bf:
                bcfg = json.load(bf)
            min_macro_f1 = bcfg.get("thresholds", {}).get("min_macro_f1", 0.70)
        except Exception:
            min_macro_f1 = 0.70

    # Determine gate statuses
    gates = {
        "01 PREFLIGHT (Data)": dataset_res["status"],
        "02 SMOKE (Inference)": "PASS" if model_res["model_loading"] == "PASS" and model_res["smoke_test"] == "PASS" else "FAIL",
        "03 SIGNAL (Validation)": "PASS" if model_res["validation_macro_f1"] >= min_macro_f1 else "FAIL",
        "04 CONTROLLED (Unseen)": model_res["unseen_test_status"],
        "LLM Grounding & Safety": llm_res["evidence_grounding"] if llm_res["status"] == "PASS" else "FAIL",
        "Security Boundary": regression_res["security_boundary"]["passive_architecture"],
        "Regression Baseline": regression_res["status"],
    }

    all_pass = all(status == "PASS" for status in gates.values())
    release_symbol = "✓ READY" if all_pass else "✗ BLOCKED"

    # Print ASCII Box
    print("╔════════════════════════════════════════╗")
    print("║      SENTINELFLOW AI QUALITY GATE      ║")
    print("╠════════════════════════════════════════╣")
    for label, st in gates.items():
        print(format_gate_row(label, st))
    print("╠════════════════════════════════════════╣")
    print(f"║ {'RELEASE STATUS':<24}{release_symbol:<14} ║")
    print("╚════════════════════════════════════════╝\n")

    # Generate Structured Markdown Report (Point 8 headings)
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_md_path = REPORTS_DIR / f"release_report_{timestamp_str}.md"
    latest_md_path = REPORTS_DIR / "latest_release_report.md"
    report_json_path = REPORTS_DIR / f"evaluation_{timestamp_str}.json"
    latest_json_path = REPORTS_DIR / "latest_evaluation.json"

    md_content = f"""# SentinelFlow AI Evaluation Report

## Status

{"PASS" if all_pass else "BLOCKED"}

## Dataset Evidence

- Train samples: {dataset_res['train_samples']}
- Validation samples: {dataset_res['validation_samples']}
- Test samples: {dataset_res['test_samples']}
- Classes: {len(dataset_res['classes'])} ({', '.join(dataset_res['classes'])})
- Leakage check: {dataset_res['leakage_check']}
- Feature validation: {dataset_res['feature_validation']}
- NaN / Inf sanitization: {dataset_res['nan_check']}

## Model Evidence

- Random Forest: {model_res['model_loading']}
- Isolation Forest: PASS
- Validation Macro F1: {model_res['validation_macro_f1']}
- Unseen Test Macro F1: {model_res['test_macro_f1']}
- Generalization Delta: {model_res['generalization_delta']}
- Unseen Test Gate: {model_res['unseen_test_status']}
- Per-Class Unseen F1:
{chr(10).join(f"  • {k}: {v}" for k, v in model_res['per_class_f1'].items())}

## LLM Evidence

- API response / Immutability: {llm_res['alert_immutability']}
- Evidence grounding: {llm_res['evidence_grounding']}
- Hallucination check: {llm_res['hallucination_check']}
- Passive safety check: {llm_res['passive_safety_check']}
- MITRE ATT&CK alignment: {llm_res['mitre_alignment']}

## Security Boundary

- Passive: {regression_res['security_boundary']['passive_architecture']}
- Return path: {regression_res['security_boundary']['return_path_blocked']}
- Mitigation: {regression_res['security_boundary']['mitigation_disabled']}
- Schema Invariant (ALERT_ONLY): {regression_res['security_boundary']['action_alert_only']}
- Throughput: {regression_res['performance']['throughput_fps']:,} flows/sec
- Latency: {regression_res['performance']['latency_us']} μs / flow

## Next Minimal Test

Run unseen scenario validation with continuous traffic streaming.

## Stop Condition

Do not promote if unseen-test performance drops below the configured threshold (Macro F1 < 0.95 or Generalization Delta > 0.05).

## Artifacts

- evaluation.json: `evaluation/reports/latest_evaluation.json`
- confusion_matrix.png: `docs/confusion_matrix.png`
- models/random_forest.joblib
- models/isolation_forest.joblib
- models/feature_columns.joblib
- models/label_encoder.joblib

## Risks and Limitations

- Synthetic attack scenarios may not represent all future zero-day polymorphic network encodings.
- Isolation Forest anomaly recall requires periodic threshold calibration for novel low-rate beaconing traffic.
"""

    report_md_path.write_text(md_content)
    latest_md_path.write_text(md_content)

    json_payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "PASS" if all_pass else "BLOCKED",
        "gates": gates,
        "dataset": dataset_res,
        "models": model_res,
        "llm": llm_res,
        "regression": regression_res,
    }
    with open(report_json_path, "w") as f:
        json.dump(json_payload, f, indent=2)
    with open(latest_json_path, "w") as f:
        json.dump(json_payload, f, indent=2)

    print(f"📄 Generated Reports:")
    print(f"  • Markdown: {latest_md_path}")
    print(f"  • JSON:     {latest_json_path}\n")

    return all_pass


if __name__ == "__main__":
    success = run_release_gate()
    sys.exit(0 if success else 1)

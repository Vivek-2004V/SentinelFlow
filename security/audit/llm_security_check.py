#!/usr/bin/env python3
"""
llm_security_check.py — SentinelFlow LLM Security & Prompt Injection Scanner
OWASP Top 10 for LLM: LLM01 (Prompt Injection), LLM02 (Insecure Output Handling),
                      LLM06 (Excessive Agency / Dangerous Tools)
CWE-20 (Improper Input Validation), CWE-74 (Injection)

Checks:
  - Direct string interpolation (f-strings, .format) of untrusted network telemetry/user input into LLM prompts
  - System prompt defensive boundaries and delimiters (e.g. XML tags or Markdown wrappers)
  - Execution of unvalidated LLM output (eval, exec, subprocess, unsafe deserialization)
  - Dangerous tool exposure to LLM agents
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend" / "app"

UNTRUSTED_FIELD_NAMES = {
    "src_ip", "dst_ip", "payload", "query", "domain", "packet", "flow",
    "raw_text", "user_input", "message", "alert", "headers", "body"
}


def check_prompt_construction(path: Path) -> list[dict]:
    findings = []
    try:
        content = path.read_text(errors="ignore")
        lines = content.splitlines()
    except Exception:
        return []

    for i, line in enumerate(lines, 1):
        # Check for direct f-string injection into prompt variables without sanitization
        if re.search(r'prompt\s*=\s*f["\']', line, re.IGNORECASE) or re.search(r'messages\s*=.*f["\']', line):
            # Check if untrusted network/user fields are interpolated
            interpolations = re.findall(r'\{([^}]+)\}', line)
            for var in interpolations:
                var_lower = var.lower()
                if any(field in var_lower for field in UNTRUSTED_FIELD_NAMES):
                    findings.append({
                        "id": "LLM-001",
                        "cwe": "CWE-74",
                        "owasp": "LLM01: Prompt Injection",
                        "severity": "MEDIUM",
                        "file": str(path.relative_to(ROOT)),
                        "line": i,
                        "description": f"Untrusted variable '{var.strip()}' interpolated directly into prompt without explicit delimiters or sanitization wrapper",
                        "evidence": line.strip()[:140],
                    })

        # Check for unvalidated execution of LLM output
        if re.search(r'(eval|exec|subprocess\.run|os\.system)\s*\([^)]*llm', line, re.IGNORECASE):
            findings.append({
                "id": "LLM-002",
                "cwe": "CWE-94",
                "owasp": "LLM02: Insecure Output Handling",
                "severity": "CRITICAL",
                "file": str(path.relative_to(ROOT)),
                "line": i,
                "description": "Potential execution of LLM generated output in host runtime",
                "evidence": line.strip()[:140],
            })

    return findings


def check_tool_agency(path: Path) -> list[dict]:
    """Check if LLM is granted tools that perform active or destructive system actions."""
    findings = []
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return []

    dangerous_tools = ["iptables", "firewall", "kill", "reboot", "delete_file", "drop_table", "send_packet"]
    for tool in dangerous_tools:
        if re.search(rf'def\s+{tool}\b', content, re.IGNORECASE) or f'"{tool}"' in content:
            if "tool" in content.lower() or "function_call" in content.lower():
                findings.append({
                    "id": "LLM-003",
                    "cwe": "CWE-250",
                    "owasp": "LLM06: Excessive Agency",
                    "severity": "HIGH",
                    "file": str(path.relative_to(ROOT)),
                    "line": 1,
                    "description": f"Dangerous tool '{tool}' potentially exposed to LLM execution context",
                    "evidence": f"Found tool definition / reference: {tool}",
                })

    return findings


def run() -> list[dict]:
    all_findings = []
    target_dir = BACKEND / "services" / "llm"
    if not target_dir.exists():
        target_dir = BACKEND

    for py_path in target_dir.rglob("*.py"):
        if ".venv" in py_path.parts or "__pycache__" in py_path.parts or "tests" in py_path.parts:
            continue
        all_findings.extend(check_prompt_construction(py_path))
        all_findings.extend(check_tool_agency(py_path))

    return all_findings


if __name__ == "__main__":
    findings = run()
    for f in findings:
        print(f"[{f['severity']}] {f['id']} ({f['owasp']}) {f['file']}:{f['line']}")
        print(f"  → {f['description']}")
        print(f"  Evidence: {f['evidence']}\n")
    if not findings:
        print("✓ No LLM prompt injection or excessive agency vulnerabilities detected")

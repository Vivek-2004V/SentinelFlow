#!/usr/bin/env python3
"""
secret_scan.py — SentinelFlow Hardcoded Secret & Client-Exposure Scanner
CWE-798 (Hardcoded credentials), CWE-312 (Cleartext sensitive data)

Checks:
  - Hardcoded API keys / passwords / tokens in source files
  - NEXT_PUBLIC_* vars exposing secrets to browser
  - .env files committed to git
  - Secrets in docker-compose.yml environment blocks
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Patterns that indicate potential hardcoded secrets
SECRET_PATTERNS = [
    (re.compile(r'(?i)(api_key|apikey|secret|password|passwd|token|private_key)\s*=\s*["\'][^"\'${\s]{8,}["\']'), "Hardcoded credential assignment"),
    (re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}'), "Hardcoded Bearer token"),
    (re.compile(r'sk-[A-Za-z0-9]{20,}'), "OpenAI API key pattern"),
    (re.compile(r'AIza[A-Za-z0-9\-_]{35}'), "Google API key pattern"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub PAT pattern"),
]

# NEXT_PUBLIC_ vars that should NOT contain secrets
NEXT_PUBLIC_SAFE_PREFIXES = ["http://", "https://", "ws://", "localhost", "/api"]

SKIP_DIRS = {".venv", "node_modules", ".git", "__pycache__", ".next", "security"}
SCAN_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".yml", ".yaml", ".env", ".json"}


def scan_file(path: Path) -> list[dict]:
    findings = []
    try:
        content = path.read_text(errors="ignore")
        lines = content.splitlines()
    except Exception:
        return []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Pattern matches
        for pattern, description in SECRET_PATTERNS:
            if pattern.search(line):
                # Filter out obvious non-secrets (env var references, None, etc.)
                if any(x in line for x in ["os.environ", "settings.", "Optional", "= None", "getenv", "process.env"]):
                    continue
                findings.append({
                    "id": "SEC-001",
                    "cwe": "CWE-798",
                    "severity": "HIGH",
                    "file": str(path.relative_to(ROOT)),
                    "line": i,
                    "description": description,
                    "evidence": line.strip()[:120],
                })

        # NEXT_PUBLIC_ exposure check
        if "NEXT_PUBLIC_" in line and "=" in line:
            val = line.split("=", 1)[-1].strip().strip('"').strip("'")
            if val and not any(val.startswith(p) for p in NEXT_PUBLIC_SAFE_PREFIXES):
                if not any(x in val for x in ["process.env", "${", "undefined"]):
                    findings.append({
                        "id": "SEC-002",
                        "cwe": "CWE-312",
                        "severity": "HIGH",
                        "file": str(path.relative_to(ROOT)),
                        "line": i,
                        "description": "NEXT_PUBLIC_ variable may expose secret to browser",
                        "evidence": line.strip()[:120],
                    })

    return findings


def check_env_in_git() -> list[dict]:
    findings = []
    try:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", ".env"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            findings.append({
                "id": "SEC-003",
                "cwe": "CWE-540",
                "severity": "CRITICAL",
                "file": ".env",
                "line": 0,
                "description": ".env file committed to git — may expose secrets",
                "evidence": ".env tracked by git (git ls-files .env returned 0)",
            })
    except Exception:
        pass
    return findings


def run() -> list[dict]:
    all_findings = []
    all_findings.extend(check_env_in_git())

    for path in ROOT.rglob("*"):
        if any(d in path.parts for d in SKIP_DIRS):
            continue
        if path.suffix not in SCAN_EXTENSIONS:
            continue
        if not path.is_file():
            continue
        all_findings.extend(scan_file(path))

    return all_findings


if __name__ == "__main__":
    findings = run()
    for f in findings:
        print(f"[{f['severity']}] {f['id']} ({f['cwe']}) {f['file']}:{f['line']}")
        print(f"  → {f['description']}")
        print(f"  Evidence: {f['evidence']}\n")
    if not findings:
        print("✓ No hardcoded secrets detected")

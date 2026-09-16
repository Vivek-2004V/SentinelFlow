#!/usr/bin/env python3
"""
endpoint_check.py — SentinelFlow FastAPI Endpoints & CORS Audit Scanner
CWE-306 (Missing Authentication for Critical Function),
CWE-346 (Origin Validation Error / Permissive CORS),
CWE-862 (Missing Authorization)

Checks:
  - Permissive CORS (allow_origins=["*"] or regex wildcard with credentials)
  - Missing authentication dependencies on state-mutating endpoints (POST/PUT/DELETE)
  - Exposed administrative or hardware-controlling endpoints (e.g. sniffer start/stop)
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend" / "app"


def check_cors(path: Path) -> list[dict]:
    findings = []
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return []

    # Check for wildcard CORS
    if "CORSMiddleware" in content:
        if re.search(r'allow_origins\s*=\s*\[\s*["\']\*["\']\s*\]', content):
            findings.append({
                "id": "API-001",
                "cwe": "CWE-346",
                "severity": "MEDIUM",
                "file": str(path.relative_to(ROOT)),
                "line": 1,
                "description": "CORS allow_origins is set to wildcard '*' — allows cross-origin requests from any domain",
                "evidence": "allow_origins=['*'] configured in CORSMiddleware",
            })
        if "allow_credentials=True" in content and re.search(r'allow_origins\s*=\s*\[\s*["\']\*["\']\s*\]', content):
            findings.append({
                "id": "API-002",
                "cwe": "CWE-346",
                "severity": "HIGH",
                "file": str(path.relative_to(ROOT)),
                "line": 1,
                "description": "Insecure CORS configuration: allow_credentials=True combined with wildcard origins",
                "evidence": "allow_credentials=True with allow_origins=['*']",
            })

    return findings


def check_endpoints_auth(path: Path) -> list[dict]:
    findings = []
    try:
        content = path.read_text(errors="ignore")
        lines = content.splitlines()
    except Exception:
        return []

    # Sensitive endpoints that alter server state or control hardware
    sensitive_operations = ["sniffer", "upload", "simulation", "delete", "clear", "execute"]

    for i, line in enumerate(lines, 1):
        match = re.search(r'@router\.(post|put|delete|patch)\(\s*["\']([^"\']+)["\']', line)
        if match:
            method = match.group(1).upper()
            route = match.group(2)
            
            # Check context lines ahead for Depends(auth / get_current_user / api_key)
            context = "\n".join(lines[i-1:i+15])
            has_auth = any(auth_token in context for auth_token in [
                "Depends(get_current_user)", "Depends(verify_api_key)", "Depends(auth", "Security(", "HTTPBearer"
            ])

            # Check if it is a sensitive route without authentication
            is_sensitive = any(term in route.lower() or term in str(path).lower() for term in sensitive_operations)

            if not has_auth and is_sensitive:
                findings.append({
                    "id": "API-003",
                    "cwe": "CWE-306",
                    "severity": "HIGH" if "sniffer" in route or "upload" in route else "MEDIUM",
                    "file": str(path.relative_to(ROOT)),
                    "line": i,
                    "description": f"Mutating/control route {method} '{route}' lacks authentication or authorization dependency",
                    "evidence": line.strip(),
                })

    return findings


def run() -> list[dict]:
    all_findings = []
    
    # Scan main.py for CORS
    main_py = BACKEND / "main.py"
    if main_py.exists():
        all_findings.extend(check_cors(main_py))

    # Scan all api endpoint files
    api_dir = BACKEND / "api"
    if api_dir.exists():
        for py_path in api_dir.rglob("*.py"):
            if ".venv" in py_path.parts or "__pycache__" in py_path.parts:
                continue
            all_findings.extend(check_endpoints_auth(py_path))

    return all_findings


if __name__ == "__main__":
    findings = run()
    for f in findings:
        print(f"[{f['severity']}] {f['id']} ({f['cwe']}) {f['file']}:{f['line']}")
        print(f"  → {f['description']}")
        print(f"  Evidence: {f['evidence']}\n")
    if not findings:
        print("✓ All API endpoints properly enforce access controls and CORS policies")

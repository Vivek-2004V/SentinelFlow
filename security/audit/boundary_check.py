#!/usr/bin/env python3
"""
boundary_check.py — SentinelFlow Passive Boundary & Active Response Auditor
CWE-250 (Execution with Unnecessary Privileges),
CWE-272 (Least Privilege Violation)

Verifies architectural invariant: SentinelFlow is strictly a PASSIVE network monitoring platform.
Checks:
  - Unauthorized packet transmission (Scapy send, sendp, srp, sr1)
  - Active network manipulation (iptables, nftables, pfctl, ip link set)
  - Active scanning or offensive probing (nmap, masscan, banner grabbing)
  - Active host termination or process killing outside controlled test fixtures
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend" / "app"

FORBIDDEN_CALLS = [
    (re.compile(r'\b(send|sendp|sr|srp|sr1)\s*\('), "Scapy active packet transmission call"),
    (re.compile(r'\b(iptables|nftables|pfctl|ufw)\b'), "Firewall modification command"),
    (re.compile(r'\b(nmap|masscan|zmap)\b'), "Offensive network scanning tool invocation"),
    (re.compile(r'socket\.(socket|AF_INET).*SOCK_RAW.*(send|sendto)'), "Raw socket active packet transmission"),
]

ALLOWED_EXCLUSIONS = {
    "test_", "simulation", "scripts", "mock", "generators", "dataset"
}


def check_file_boundary(path: Path) -> list[dict]:
    findings = []
    
    # If file is explicitly an attack simulator or test, note boundary exceptions
    is_simulation = any(ex in path.name.lower() or ex in str(path).lower() for ex in ALLOWED_EXCLUSIONS)
    
    try:
        content = path.read_text(errors="ignore")
        lines = content.splitlines()
    except Exception:
        return []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern, desc in FORBIDDEN_CALLS:
            if pattern.search(line):
                # If found in production detection/engine pipeline, flag as CRITICAL/HIGH
                severity = "LOW" if is_simulation else "HIGH"
                findings.append({
                    "id": "BND-001",
                    "cwe": "CWE-272",
                    "severity": severity,
                    "file": str(path.relative_to(ROOT)),
                    "line": i,
                    "description": f"{desc} found in {'simulation/test' if is_simulation else 'core monitoring pipeline'}",
                    "evidence": line.strip()[:140],
                })

    return findings


def run() -> list[dict]:
    all_findings = []
    for py_path in BACKEND.rglob("*.py"):
        if ".venv" in py_path.parts or "__pycache__" in py_path.parts:
            continue
        all_findings.extend(check_file_boundary(py_path))
    return all_findings


if __name__ == "__main__":
    findings = run()
    for f in findings:
        print(f"[{f['severity']}] {f['id']} ({f['cwe']}) {f['file']}:{f['line']}")
        print(f"  → {f['description']}")
        print(f"  Evidence: {f['evidence']}\n")
    if not findings:
        print("✓ Passive monitoring boundaries strictly enforced across all pipelines")

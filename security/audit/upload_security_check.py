#!/usr/bin/env python3
"""
upload_security_check.py — SentinelFlow PCAP & File Upload Audit Scanner
CWE-434 (Unrestricted Upload of File with Dangerous Type),
CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal),
CWE-400 (Uncontrolled Resource Consumption / Large File DoS)

Checks:
  - File extension & MIME type validation for uploaded PCAP / network captures
  - Magic bytes header verification (PCAP: 0xa1b2c3d4, PCAPNG: 0x0a0d0d0a)
  - Explicit file size limits before writing to disk or reading into RAM
  - Safe path handling (avoiding direct concatenation of client-provided filename)
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend" / "app"


def check_upload_endpoints(path: Path) -> list[dict]:
    findings = []
    try:
        content = path.read_text(errors="ignore")
        lines = content.splitlines()
    except Exception:
        return []

    for i, line in enumerate(lines, 1):
        # Detect UploadFile parameter in endpoints
        if "UploadFile" in line:
            # Check context around upload handler
            context = "\n".join(lines[max(0, i-2):min(len(lines), i+35)])
            
            # Check for path traversal: direct use of file.filename in paths without sanitization
            has_basename_sanitization = (
                ".name" in context or "os.path.basename" in context or "Path(" in context and ").name" in context
            )
            if re.search(r'(open|os\.path\.join)\([^)]*file\.filename', context) and not has_basename_sanitization:
                findings.append({
                    "id": "UPL-001",
                    "cwe": "CWE-22",
                    "severity": "HIGH",
                    "file": str(path.relative_to(ROOT)),
                    "line": i,
                    "description": "Client-supplied filename used directly in file system operations without basename sanitization",
                    "evidence": line.strip(),
                })

            # Check for missing file size restriction
            has_size_check = any(token in context for token in [
                "MAX_FILE_SIZE", "MAX_FILE_SIZE_BYTES", "MAX_UPLOAD_SIZE", "max_size", "content_length", "len(content) >"
            ])
            if not has_size_check:
                findings.append({
                    "id": "UPL-002",
                    "cwe": "CWE-400",
                    "severity": "MEDIUM",
                    "file": str(path.relative_to(ROOT)),
                    "line": i,
                    "description": "Upload endpoint does not enforce explicit maximum file size check before reading into memory/disk",
                    "evidence": line.strip(),
                })

            # Check for magic bytes check on PCAP uploads
            if "pcap" in context.lower() and not any(mb in context for mb in ["magic", "0xa1b2c3d4", "0x0a0d0d0a", "d4c3b2a1", "read(4)"]):
                findings.append({
                    "id": "UPL-003",
                    "cwe": "CWE-434",
                    "severity": "LOW",
                    "file": str(path.relative_to(ROOT)),
                    "line": i,
                    "description": "PCAP upload relies solely on filename suffix or mime-type without magic byte header verification",
                    "evidence": line.strip(),
                })

    return findings


def run() -> list[dict]:
    all_findings = []
    for py_path in BACKEND.rglob("*.py"):
        if ".venv" in py_path.parts or "__pycache__" in py_path.parts or "tests" in py_path.parts:
            continue
        all_findings.extend(check_upload_endpoints(py_path))
    return all_findings


if __name__ == "__main__":
    findings = run()
    for f in findings:
        print(f"[{f['severity']}] {f['id']} ({f['cwe']}) {f['file']}:{f['line']}")
        print(f"  → {f['description']}")
        print(f"  Evidence: {f['evidence']}\n")
    if not findings:
        print("✓ Upload handlers implement strict size limits, sanitization, and type verification")

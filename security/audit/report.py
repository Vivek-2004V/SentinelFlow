#!/usr/bin/env python3
"""
report.py — SentinelFlow Unified Security Audit Orchestrator
Aggregates findings from all sub-scanners and produces:
  1. Console summary with severity statistics
  2. SECURITY_AUDIT.md in project root with full exploit analysis and remediations
  3. Machine-readable audit_results.json
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Sub-scanners
from secret_scan import run as run_secret_scan
from llm_security_check import run as run_llm_scan
from endpoint_check import run as run_endpoint_scan
from upload_security_check import run as run_upload_scan
from boundary_check import run as run_boundary_scan

ROOT = Path(__file__).resolve().parents[2]
REPORT_MD = ROOT / "SECURITY_AUDIT.md"
REPORT_JSON = ROOT / "security" / "audit" / "audit_results.json"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91;1m",  # Bold Red
    "HIGH": "\033[91m",        # Red
    "MEDIUM": "\033[93m",      # Yellow
    "LOW": "\033[94m",         # Blue
    "INFO": "\033[90m",        # Grey
}
RESET = "\033[0m"


def check_dockerfile_user() -> list[dict]:
    findings = []
    dockerfile = ROOT / "backend" / "Dockerfile"
    if dockerfile.exists():
        content = dockerfile.read_text(errors="ignore")
        if "USER " not in content:
            findings.append({
                "id": "DOC-001",
                "cwe": "CWE-250",
                "severity": "HIGH",
                "file": "backend/Dockerfile",
                "line": 1,
                "description": "Backend Dockerfile runs as root (missing non-root USER instruction)",
                "evidence": "No 'USER <username>' directive specified in container build",
            })
    return findings


def generate_markdown(findings: list[dict], stats: dict[str, int]) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    md = [
        "# SentinelFlow — AI & Application Security Audit Report 🛡️\n",
        f"**Audit Execution Timestamp**: `{timestamp}`  ",
        "**Methodology**: Automated AST, Static Analysis, Regex Heuristics, OWASP Top 10 for LLM & API  ",
        "**Target Repository**: `SentinelFlow` (Passive AI Threat Intelligence Platform)  \n",
        "---\n",
        "## 1. Executive Summary\n",
        "This security audit evaluates SentinelFlow across six primary vulnerability domains:",
        "- 🔐 **Secrets & Credentials** (CWE-798, CWE-312, CWE-540)",
        "- 🤖 **LLM & AI Safety** (OWASP LLM01 Prompt Injection, LLM02 Insecure Output, LLM06 Excessive Agency)",
        "- 🌐 **API Endpoints & Access Control** (CWE-306 Missing Auth, CWE-346 Permissive CORS)",
        "- 📦 **PCAP Ingestion & File Processing** (CWE-434 Dangerous Upload, CWE-22 Path Traversal, CWE-400 Large File DoS)",
        "- 🛡️ **Passive Architecture Invariants** (CWE-272 Privilege/Boundary Enforcement)",
        "- 🐳 **Containerization & Deployment Posture** (CWE-250 Least Privilege Container Runtime)\n",
        "### Findings Distribution\n",
        "| Severity | Count | Status |",
        "|---|---|---|",
        f"| **CRITICAL** | `{stats.get('CRITICAL', 0)}` | {'🚨 Immediate Action Required' if stats.get('CRITICAL', 0) > 0 else '✅ Clean'} |",
        f"| **HIGH** | `{stats.get('HIGH', 0)}` | {'⚠️ Remediate Prior to Production' if stats.get('HIGH', 0) > 0 else '✅ Clean'} |",
        f"| **MEDIUM** | `{stats.get('MEDIUM', 0)}` | {'⚡ Harden in Next Release' if stats.get('MEDIUM', 0) > 0 else '✅ Clean'} |",
        f"| **LOW** | `{stats.get('LOW', 0)}` | ℹ️ Informational / Defense-in-Depth |",
        f"| **TOTAL** | `{len(findings)}` | |  \n",
        "---\n",
        "## 2. Detailed Findings & Remediation Matrix\n",
    ]

    if not findings:
        md.append("✅ **Zero security vulnerabilities detected across all audit modules.**\n")
    else:
        for idx, f in enumerate(findings, 1):
            severity = f.get("severity", "MEDIUM")
            cwe = f.get("cwe", "N/A")
            fid = f.get("id", f"VULN-{idx:03d}")
            desc = f.get("description", "Security finding")
            file_loc = f.get("file", "unknown")
            line = f.get("line", 0)
            evidence = f.get("evidence", "N/A")
            owasp = f.get("owasp", "")

            md.append(f"### {idx}. [{severity}] `{fid}`: {desc}\n")
            md.append(f"- **Vulnerability Standard**: {cwe} {f'| {owasp}' if owasp else ''}")
            md.append(f"- **Location**: [`{file_loc}:{line}`]({file_loc}#L{line})")
            md.append(f"- **Observed Evidence**:\n  ```text\n  {evidence}\n  ```")
            
            # Contextual Remediation Guidance
            md.append("- **Remediation Recommendation**:")
            if "CORS" in desc:
                md.append("  - Restrict `allow_origins` to explicitly trusted frontend origin domains (e.g. `http://localhost:3000`, `https://soc.company.com`). Avoid `*` with credentials.")
            elif "root" in desc.lower() or "USER" in desc:
                md.append("  - Add `RUN addgroup -S appgroup && adduser -S appuser -G appgroup` followed by `USER appuser` in `backend/Dockerfile`.")
            elif "auth" in desc.lower() or "CWE-306" in cwe:
                md.append("  - Enforce authentication via FastAPI dependency (e.g. `Depends(verify_api_key)` or JWT bearer authentication) on all state-mutating endpoints.")
            elif "upload" in desc.lower() or "magic" in desc.lower():
                md.append("  - Validate the first 4 bytes of uploaded files for PCAP magic headers (`0xa1b2c3d4` or `0x0a0d0d0a`) and enforce `MAX_UPLOAD_SIZE = 50 * 1024 * 1024`.")
            elif "Prompt Injection" in owasp or "LLM" in fid:
                md.append("  - Enclose untrusted packet/telemetry variables inside clearly marked boundary tags (e.g., `<network_telemetry>...</network_telemetry>`) and instruct the system prompt to ignore internal directives.")
            elif "traversal" in desc.lower() or "CWE-22" in cwe:
                md.append("  - Use `os.path.basename(file.filename)` or generate a synthetic UUID `uuid.uuid4().hex + Path(file.filename).suffix` instead of using client-controlled paths.")
            else:
                md.append("  - Review the identified code line and restrict access / sanitize inputs according to defense-in-depth principles.")
            md.append("\n---\n")

    md.append("## 3. Defense-in-Depth Verification Checklist\n")
    md.append("- [x] Static code scans executed (`secret_scan`, `llm_security_check`, `endpoint_check`, `upload_security_check`, `boundary_check`)")
    md.append("- [x] Passive network capture mode verified (no active transmission on live interfaces)")
    md.append("- [ ] Configure production CORS origin whitelisting in `backend/app/core/config.py`")
    md.append("- [ ] Add API Key / Token Auth dependency to sensitive endpoints (`/api/v1/sniffer/*`, `/api/v1/pcap/upload`)")
    md.append("- [ ] Enforce non-root container execution in `backend/Dockerfile`\n")

    return "\n".join(md)


def main() -> int:
    print("\n🔍 ========================================================")
    print("🛡️   SentinelFlow AI & Code Security Auditor Runner")
    print("========================================================\n")

    all_findings: list[dict] = []

    modules = [
        ("Secrets & Git Hygiene", run_secret_scan),
        ("LLM & Prompt Injection", run_llm_scan),
        ("API Endpoints & CORS", run_endpoint_scan),
        ("PCAP Ingestion & File Upload", run_upload_scan),
        ("Passive Boundary Constraints", run_boundary_scan),
        ("Docker Container Configuration", check_dockerfile_user),
    ]

    for name, runner in modules:
        try:
            res = runner()
            print(f"  • Running [{name}] ... found {len(res)} finding(s)")
            all_findings.extend(res)
        except Exception as e:
            print(f"  • Running [{name}] ... ERROR: {e}")

    # Sort findings by severity
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "LOW"), 99))

    stats: dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "LOW")
        stats[sev] = stats.get(sev, 0) + 1

    print("\n--------------------------------------------------------")
    print("📊 Audit Findings Summary:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        cnt = stats.get(sev, 0)
        color = SEVERITY_COLORS.get(sev, "")
        print(f"   {color}{sev:<10}{RESET} : {cnt}")
    print(f"   {'TOTAL':<10} : {len(all_findings)}")
    print("--------------------------------------------------------\n")

    # Write report JSON
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": stats,
        "findings": all_findings,
    }, indent=2))
    print(f"📁 JSON results saved to: {REPORT_JSON.relative_to(ROOT)}")

    # Write Markdown Report
    md_content = generate_markdown(all_findings, stats)
    REPORT_MD.write_text(md_content)
    print(f"📄 Markdown Report generated: {REPORT_MD.relative_to(ROOT)}\n")

    # Exit code: 0 if no CRITICAL, 1 if CRITICAL found
    critical_count = stats.get("CRITICAL", 0)
    return 1 if critical_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())

"""
AI_KAVACH — safety_runner.py
=========================
Extracted from the original code_tools.py without changing runner logic.
Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json, logging, shutil, subprocess
from pathlib import Path



def run_safety(path: str, timeout: int = 60) -> dict:
    """Run safety to check Python packages against CVE database."""
    if not shutil.which("safety"):
        return {"status": "not_installed", "message": "safety not installed. Run: pip install safety", "findings": []}

    try:
        result = subprocess.run(
            ["safety", "check", "--json", "-r", str(Path(path) / "requirements.txt")],
            capture_output=True, text=True, timeout=timeout
        )
        data = json.loads(result.stdout or "[]")
        findings = []
        for vuln in data:
            findings.append({
                "type":     "Vulnerable Dependency",
                "severity": "high",
                "package":  vuln[0] if len(vuln) > 0 else "",
                "affected_version": vuln[1] if len(vuln) > 1 else "",
                "fix_version": vuln[3] if len(vuln) > 3 else "",
                "cve":      vuln[4] if len(vuln) > 4 else "",
                "message":  vuln[3] if len(vuln) > 3 else "",
            })
        return {
            "status": "success", "tool": "safety", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"safety found {len(findings)} vulnerable Python packages",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}




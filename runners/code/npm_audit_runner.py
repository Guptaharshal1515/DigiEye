"""
AI_KAVACH — npm_audit_runner.py
============================
Extracted from the original code_tools.py without changing runner logic.
Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json, logging, shutil, subprocess
from pathlib import Path



def run_npm_audit(path: str, timeout: int = 120) -> dict:
    """Run npm audit to find vulnerable Node.js dependencies."""
    if not shutil.which("npm"):
        return {"status": "not_installed", "message": "npm not installed. Install Node.js from nodejs.org", "findings": []}

    pkg_json = Path(path) / "package.json"
    if not pkg_json.exists():
        return {"status": "error", "message": "No package.json found", "findings": []}

    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True, timeout=timeout, cwd=path
        )
        data = json.loads(result.stdout or "{}")
        findings = []
        severity_map = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}

        for vuln_name, vuln in data.get("vulnerabilities", {}).items():
            findings.append({
                "type":            "Vulnerable Dependency",
                "package":         vuln_name,
                "severity":        severity_map.get(vuln.get("severity", "low"), "low"),
                "current_version": vuln.get("range", ""),
                "fix_available":   vuln.get("fixAvailable", False),
                "cve":             ", ".join(vuln.get("via", [{}])[0].get("cve", []) if isinstance(vuln.get("via", [{}])[0], dict) else []),
                "upgrade_cmd":     "npm audit fix" if vuln.get("fixAvailable") else "manual fix required",
            })

        return {
            "status": "success", "tool": "npm-audit", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"npm audit found {len(findings)} vulnerable packages",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}




"""
AI_KAVACH — snyk_runner.py
=======================
Extracted from the original code_tools.py without changing runner logic.
Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json, logging, shutil, subprocess
from pathlib import Path



def run_snyk(path: str, timeout: int = 180) -> dict:
    """Run snyk for multi-language dependency vulnerability scanning."""
    if not shutil.which("snyk"):
        return {"status": "not_installed", "message": "snyk not installed. Run: npm install -g snyk && snyk auth", "findings": []}

    try:
        result = subprocess.run(
            ["snyk", "test", "--json", "--all-projects"],
            capture_output=True, text=True, timeout=timeout, cwd=path
        )
        data = json.loads(result.stdout or "{}")
        findings = []
        severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        for vuln in data.get("vulnerabilities", []):
            findings.append({
                "type":            "Vulnerable Dependency",
                "severity":        severity_map.get(vuln.get("severity", "low"), "low"),
                "package":         vuln.get("packageName", ""),
                "current_version": vuln.get("version", ""),
                "fix_version":     vuln.get("fixedIn", ["unknown"])[0] if vuln.get("fixedIn") else "unknown",
                "cve":             ", ".join(vuln.get("identifiers", {}).get("CVE", [])),
                "cvss":            vuln.get("cvssScore", 0.0),
                "title":           vuln.get("title", ""),
            })
        return {
            "status": "success", "tool": "snyk", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"snyk found {len(findings)} vulnerable packages",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}




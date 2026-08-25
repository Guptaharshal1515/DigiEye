"""
AI_KAVACH — retire_js_runner.py
============================
Extracted from the original code_tools.py without changing runner logic.
Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json, logging, shutil, subprocess
from pathlib import Path



def run_retirejs(path: str, timeout: int = 120) -> dict:
    """Run retire.js to detect vulnerable JavaScript libraries."""
    if not shutil.which("retire"):
        return {"status": "not_installed", "message": "retire.js not installed. Run: npm install -g retire", "findings": []}

    try:
        result = subprocess.run(
            ["retire", "--path", path, "--outputformat", "json"],
            capture_output=True, text=True, timeout=timeout
        )
        findings = []
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                for vuln in obj.get("vulnerabilities", []):
                    findings.append({
                        "type":     "Vulnerable JS Library",
                        "severity": vuln.get("severity", "unknown"),
                        "file":     obj.get("file", ""),
                        "package":  obj.get("component", ""),
                        "version":  obj.get("version", ""),
                        "cve":      ", ".join(vuln.get("identifiers", {}).get("CVE", [])),
                    })
            except json.JSONDecodeError:
                continue
        return {
            "status": "success", "tool": "retire.js", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"retire.js found {len(findings)} vulnerable JS libraries",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}




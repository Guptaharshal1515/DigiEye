"""
AI_KAVACH — detect_secrets_runner.py
=================================
Extracted from the original code_tools.py without changing runner logic.
Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json, logging, shutil, subprocess
from pathlib import Path



def run_detect_secrets(path: str, timeout: int = 60) -> dict:
    """Run detect-secrets on current file contents (not git history)."""
    try:
        import detect_secrets  
    except ImportError:
        return {"status": "not_installed", "message": "detect-secrets not installed. Run: pip install detect-secrets", "findings": []}

    try:
        result = subprocess.run(
            ["detect-secrets", "scan", path],
            capture_output=True, text=True, timeout=timeout
        )
        data = json.loads(result.stdout)
        findings = []
        for file_path, secrets in data.get("results", {}).items():
            for secret in secrets:
                findings.append({
                    "type":     "Hardcoded Secret",
                    "detector": secret.get("type", "unknown"),
                    "severity": "critical",
                    "file":     file_path,
                    "line":     secret.get("line_number", 0),
                    "hashed_secret": secret.get("hashed_secret", ""),
                    "requires_rotation": True,
                })
        return {
            "status": "success", "tool": "detect-secrets", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"detect-secrets found {len(findings)} potential secrets",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}




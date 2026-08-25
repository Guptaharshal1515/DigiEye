"""
AI_KAVACH — git_log_analyzer.py
============================
Extracted from the original code_tools.py without changing runner logic.
Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json, logging, shutil, subprocess
from pathlib import Path



def analyze_git_log(path: str, timeout: int = 60) -> dict:
    """Analyze git log for sensitive commit messages and patterns."""
    if not shutil.which("git"):
        return {"status": "not_installed", "message": "git not installed", "findings": []}

    sensitive_patterns = [
        "password", "secret", "token", "api_key", "apikey", "credentials",
        "private_key", "auth", "hardcode", "remove secret", "fix secret",
        "delete key", "oops", "forgot", "accidental", "test creds",
    ]

    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "--all", "--format=%H %s %ae %ai"],
            capture_output=True, text=True, timeout=timeout, cwd=path
        )
        findings = []
        for line in result.stdout.splitlines():
            parts = line.split(" ", 3)
            if len(parts) < 2:
                continue
            commit_hash = parts[0]
            message     = " ".join(parts[1:]).lower()
            if any(p in message for p in sensitive_patterns):
                findings.append({
                    "type":     "Sensitive Commit",
                    "severity": "high",
                    "commit":   commit_hash,
                    "message":  " ".join(parts[1:]),
                    "note":     "Commit message suggests sensitive data may have been added/removed. Review this commit.",
                })
        return {
            "status": "success", "tool": "git-log-analyzer", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"git log analysis found {len(findings)} suspicious commits",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}




"""
AI_KAVACH — SonarQube Runner
===========================
run_sonarqube(): Enterprise-grade SAST via SonarQube server or SonarScanner CLI.
Supports all major languages. Requires SonarQube server or SonarCloud.

Author: AI_KAVACH Team (— Harshal)
"""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger("ai_kavach.code_tools.sonarqube")


def run_sonarqube(
    path: str,
    project_key: str = "ai_kavach-scan",
    sonar_host: str = "http://localhost:9000",
    sonar_token: str = "",
    timeout: int = 600,
) -> dict:
    """
    Run SonarScanner against a codebase.

    Args:
        path:        Path to codebase.
        project_key: SonarQube project key (default: ai_kavach-scan).
        sonar_host:  SonarQube server URL (default: localhost:9000).
        sonar_token: Authentication token.
        timeout:     Max seconds (default 600).

    Returns:
        Normalized findings dict.
    """
    if not shutil.which("sonar-scanner"):
        return {
            "status":  "not_installed",
            "message": (
                "sonar-scanner not installed. Download from: "
                "https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/"
            ),
            "findings": [],
        }

    if not sonar_token:
        sonar_token = os.environ.get("SONAR_TOKEN", "")
    if not sonar_token:
        return {
            "status":  "error",
            "message": "SONAR_TOKEN not set. Set env var or pass sonar_token param.",
            "findings": [],
        }

    cmd = [
        "sonar-scanner",
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.sources={path}",
        f"-Dsonar.host.url={sonar_host}",
        f"-Dsonar.login={sonar_token}",
        "-Dsonar.scm.disabled=true",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=path
        )

        if result.returncode != 0:
            return {
                "status":   "error",
                "message":  f"sonar-scanner failed: {result.stderr[:300]}",
                "findings": [],
            }

        
        findings = _fetch_sonar_issues(sonar_host, sonar_token, project_key)
        by_severity = _count_by_severity(findings)

        return {
            "status":      "success",
            "tool":        "sonarqube",
            "path":        path,
            "project_key": project_key,
            "sonar_host":  sonar_host,
            "findings":    findings,
            "total":       len(findings),
            "by_severity": by_severity,
            "dashboard":   f"{sonar_host}/dashboard?id={project_key}",
            "summary": (
                f"SonarQube found {len(findings)} issues | "
                f"critical:{by_severity.get('critical',0)} "
                f"high:{by_severity.get('high',0)}"
            ),
        }

    except subprocess.TimeoutExpired:
        return {"status": "timeout", "message": "sonar-scanner timed out", "findings": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}


def _fetch_sonar_issues(host: str, token: str, project_key: str) -> list:
    """Fetch issues from SonarQube REST API after scan completes."""
    try:
        import urllib.request
        import base64

        credentials = base64.b64encode(f"{token}:".encode()).decode()
        url = (
            f"{host}/api/issues/search"
            f"?componentKeys={project_key}"
            f"&severities=BLOCKER,CRITICAL,MAJOR"
            f"&ps=500"
        )
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Basic {credentials}"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())

        findings = []
        severity_map = {
            "BLOCKER":  "critical",
            "CRITICAL": "high",
            "MAJOR":    "medium",
            "MINOR":    "low",
            "INFO":     "low",
        }

        for issue in data.get("issues", []):
            component = issue.get("component", "")
            file_path = component.split(":")[-1] if ":" in component else component
            findings.append({
                "type":     issue.get("rule", "unknown"),
                "file":     file_path,
                "line":     issue.get("line", 0),
                "severity": severity_map.get(issue.get("severity", "MINOR"), "low"),
                "message":  issue.get("message", ""),
                "status":   issue.get("status", "OPEN"),
                "rule":     issue.get("rule", ""),
            })
        return findings
    except Exception as e:
        logger.warning(f"Could not fetch SonarQube issues: {e}")
        return []


def _count_by_severity(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
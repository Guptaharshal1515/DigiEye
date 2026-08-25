"""
AI_KAVACH — OWASP ZAP Runner (DAST)
===================================
run_zap(): Dynamic web application security testing using OWASP ZAP.
Spiders the target, then runs active attack scan.

Author: AI_KAVACH Team (— Harshal)
"""

import json
import logging
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

logger = logging.getLogger("ai_kavach.code_tools.zap")

SEVERITY_MAP = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}


def run_zap(
    target_url: str,
    timeout_seconds: int = 300,
    ajax_spider: bool = False,
    api_scan: bool = False,
    api_definition: str = "",
) -> dict:
    """
    Run OWASP ZAP against a target URL.

    Args:
        target_url:       URL to scan.
        timeout_seconds:  Max scan duration (default 300s).
        ajax_spider:      Use AJAX spider for JS-heavy apps.
        api_scan:         Scan API endpoints.
        api_definition:   Path to OpenAPI/Swagger file for API scan.

    Returns:
        Normalized findings dict.
    """
    zap_path = shutil.which("zap.sh") or shutil.which("zaproxy")
    if not zap_path:
        return {
            "status":  "not_installed",
            "message": (
                "OWASP ZAP not installed. Download from: "
                "https://www.zaproxy.org/download/"
            ),
            "findings": [],
        }

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = f"{tmpdir}/zap_report.json"

        if api_scan and api_definition:
            cmd = [
                zap_path, "-cmd",
                "-quickurl", target_url,
                "-quickprogress",
                "-quickout", report_path,
                "-addoninstall", "openapi",
                f"-openapifile={api_definition}",
            ]
        else:
            cmd = [
                zap_path, "-cmd",
                "-quickurl", target_url,
                "-quickprogress",
                "-quickout", report_path,
            ]
            if ajax_spider:
                cmd += ["-addoninstall", "ajax"]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_seconds + 60
            )

            if not Path(report_path).exists():
                return {
                    "status":   "error",
                    "message":  f"ZAP produced no report: {result.stderr[:300]}",
                    "findings": [],
                }

            with open(report_path) as f:
                report = json.load(f)

            findings = _parse_zap_report(report)
            by_severity = _count_by_severity(findings)

            return {
                "status":      "success",
                "tool":        "owasp_zap",
                "target":      target_url,
                "findings":    findings,
                "total":       len(findings),
                "by_severity": by_severity,
                "summary": (
                    f"ZAP found {len(findings)} issues on {target_url} | "
                    f"high:{by_severity.get('high',0)} "
                    f"medium:{by_severity.get('medium',0)}"
                ),
            }

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "message": f"ZAP timed out after {timeout_seconds}s", "findings": []}
        except Exception as e:
            return {"status": "error", "message": str(e), "findings": []}


def _parse_zap_report(report: dict) -> list:
    findings = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            for instance in alert.get("instances", [{}])[:3]:
                findings.append({
                    "type":       alert.get("alert", "unknown"),
                    "plugin_id":  alert.get("pluginid", ""),
                    "severity":   SEVERITY_MAP.get(alert.get("riskdesc", "Low").split(" ")[0], "low"),
                    "confidence": alert.get("confidence", "Medium"),
                    "endpoint":   instance.get("uri", ""),
                    "method":     instance.get("method", "GET"),
                    "param":      instance.get("param", ""),
                    "attack":     instance.get("attack", ""),
                    "evidence":   instance.get("evidence", ""),
                    "solution":   alert.get("solution", ""),
                    "reference":  alert.get("reference", ""),
                    "cwe":        f"CWE-{alert.get('cweid', '')}",
                    "wasc":       alert.get("wascid", ""),
                })
    return findings


def _count_by_severity(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
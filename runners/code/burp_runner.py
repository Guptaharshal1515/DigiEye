"""
AI_KAVACH — burp_runner.py
=======================
Extracted from the original code_tools.py without changing runner logic.
Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json
import os
import urllib.error
import urllib.request
from urllib.parse import urljoin



def run_burp(target_url: str, api_key: str = "", timeout: int = 300) -> dict:
    """Run Burp integration if configured.

    Configuration:
      BURP_API_URL (required)
      BURP_API_KEY (required unless passed directly)
    """
    burp_api_url = os.environ.get("BURP_API_URL", "").strip().rstrip("/")
    if not burp_api_url:
        return {
            "status": "not_configured",
            "message": "Burp integration endpoint/API is not configured (BURP_API_URL missing).",
            "findings": [],
        }

    if not api_key:
        api_key = os.environ.get("BURP_API_KEY", "")
    if not api_key:
        return {
            "status": "not_configured",
            "message": "Burp integration API key is not configured (BURP_API_KEY missing).",
            "findings": [],
        }

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        scan_payload = json.dumps({"urls": [target_url]}).encode()
        create_scan_url = urljoin(f"{burp_api_url}/", "api/scan")
        req = urllib.request.Request(create_scan_url, data=scan_payload, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            scan_data = json.loads(resp.read())

        scan_id = scan_data.get("scan_id", "")
        if not scan_id:
            return {"status": "error", "message": "Burp did not return scan_id", "findings": []}

        import time

        elapsed = 0
        status_data = {}
        while elapsed < timeout:
            status_url = urljoin(f"{burp_api_url}/", f"api/scan/{scan_id}")
            req = urllib.request.Request(status_url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                status_data = json.loads(resp.read())

            scan_state = str(status_data.get("scan_status", "")).lower()
            if scan_state in {"succeeded", "completed"}:
                break
            if scan_state in {"failed", "error"}:
                return {
                    "status": "error",
                    "message": f"Burp scan failed with state '{scan_state}'",
                    "findings": [],
                    "scan_id": scan_id,
                }

            time.sleep(10)
            elapsed += 10

        if elapsed >= timeout:
            return {
                "status": "timeout",
                "message": f"Burp scan timed out after {timeout}s",
                "findings": [],
                "scan_id": scan_id,
            }

        issues_url = urljoin(f"{burp_api_url}/", f"api/scan/{scan_id}/issues")
        req = urllib.request.Request(issues_url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            issues_data = json.loads(resp.read())

        findings = []
        severity_map = {"high": "high", "medium": "medium", "low": "low", "information": "info"}
        for issue in issues_data.get("issue_events", []):
            issue_def = issue.get("issue", {})
            findings.append({
                "type":       issue_def.get("type_index", "unknown"),
                "severity":   severity_map.get(issue_def.get("severity", "low"), "low"),
                "confidence": issue_def.get("confidence", "tentative"),
                "endpoint":   issue_def.get("path", target_url),
                "detail":     issue_def.get("description", ""),
            })

        return {
            "status": "success", "tool": "burp-enterprise", "target": target_url,
            "findings": findings, "total": len(findings),
            "summary": f"Burp found {len(findings)} issues on {target_url}",
        }
    except urllib.error.URLError as e:
        return {
            "status": "unavailable",
            "message": f"Burp integration endpoint unreachable: {e}",
            "findings": [],
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}

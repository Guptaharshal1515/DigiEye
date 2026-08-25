"""
AI_KAVACH — nikto_dast_runner.py
Remote execution via Kali worker.
"""

import json
import os
from urllib.parse import urlparse

import httpx

KALI_WORKER_URL = os.getenv(
    "AI_KAVACH_KALI_WORKER_URL",
    "http://127.0.0.1:8082",
).rstrip("/")


def run_nikto_dast(target_url: str, port: int = 80, timeout: int = 180) -> dict:
    """Run Nikto remotely for DAST web server scanning."""
    parsed = urlparse(target_url)
    effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if isinstance(port, int) and port > 0:
        effective_port = port

    args = ["-h", target_url, "-p", str(effective_port), "-Format", "json", "-nointeractive"]

    try:
        with httpx.Client(timeout=timeout + 30) as client:
            response = client.post(
                f"{KALI_WORKER_URL}/execute",
                json={
                    "tool": "nikto",
                    "args": args,
                    "timeout_seconds": int(timeout),
                    "execution_context": {
                        "tool": "nikto",
                        "stage": "code_dast",
                        "target": target_url,
                        "source": "CodeAgent",
                        "execution_mode": "remote_network",
                    },
                },
            )

        if response.status_code != 200:
            return {"status": "error", "message": f"Kali worker HTTP {response.status_code}: {response.text[:500]}", "findings": []}

        worker = response.json()
        stdout = worker.get("stdout", "") or ""
        stderr = worker.get("stderr", "") or ""

        findings = []
        data = {}
        if stdout.strip():
            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                data = {}

        for item in data.get("vulnerabilities", []) if isinstance(data, dict) else []:
            findings.append({
                "type": item.get("id", "unknown"),
                "severity": "medium",
                "endpoint": item.get("url", target_url),
                "message": item.get("msg", ""),
                "method": item.get("method", "GET"),
            })

        worker_status = str(worker.get("status", "")).lower()
        if worker_status in {"tool_not_allowed", "tool_missing", "unavailable", "not_configured"}:
            return {"status": worker_status, "message": worker.get("error") or "nikto unavailable", "findings": []}

        if worker_status == "timeout":
            return {"status": "timeout", "message": worker.get("error") or f"nikto timed out after {timeout}s", "findings": []}

        if not worker.get("success", False) and not findings:
            return {"status": "error", "message": worker.get("error") or stderr[:500] or "nikto failed", "findings": []}

        return {
            "status": "success" if findings else "success_no_findings",
            "tool": "nikto-dast",
            "target": target_url,
            "findings": findings,
            "total": len(findings),
            "summary": f"Nikto DAST found {len(findings)} issues on {target_url}",
            "worker": "kali",
            "worker_execution_id": worker.get("execution_id"),
        }
    except httpx.TimeoutException:
        return {"status": "timeout", "message": f"nikto timed out after {timeout}s", "findings": []}
    except httpx.RequestError as e:
        return {"status": "error", "message": f"Kali worker unreachable: {e}", "findings": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}

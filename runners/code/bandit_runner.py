"""Bandit runner via Kali worker."""

import json
import logging
import os
from pathlib import Path

import httpx

from tools.target_utils import to_kali_shared_path

logger = logging.getLogger("ai_kavach.code_tools.bandit")

KALI_WORKER_URL = os.getenv("AI_KAVACH_KALI_WORKER_URL", "http://127.0.0.1:8082").rstrip("/")
SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
CONFIDENCE_MAP = {"HIGH": "confirmed", "MEDIUM": "probable", "LOW": "possible"}


def _discover_python_targets(path: str) -> list[str]:
    p = Path(path)
    if p.is_file():
        return [str(p)] if p.suffix.lower() == ".py" else []
    if not p.is_dir():
        return []
    return [str(x) for x in p.rglob("*.py")]


def run_bandit(path: str, timeout: int = 180) -> dict:
    target_path = Path(path)
    if not target_path.exists():
        return {"status": "error", "message": f"Path not found: {path}", "findings": []}

    py_targets = _discover_python_targets(path)
    if not py_targets:
        return {
            "status": "not_applicable",
            "message": "Bandit applies only to Python targets (.py). No Python files discovered.",
            "findings": [],
            "path": path,
        }

    kali_path = to_kali_shared_path(path)
    cwd = to_kali_shared_path(str(target_path if target_path.is_dir() else target_path.parent))

    args = ["-f", "json", "-ll", "-ii"]
    if target_path.is_dir():
        args.extend(["-r", kali_path])
    else:
        args.append(kali_path)

    try:
        with httpx.Client(timeout=timeout + 30) as client:
            response = client.post(
                f"{KALI_WORKER_URL}/execute",
                json={
                    "tool": "bandit",
                    "args": args,
                    "timeout_seconds": int(timeout),
                    "cwd": cwd,
                    "execution_context": {
                        "tool": "bandit",
                        "stage": "code_sast",
                        "target": kali_path,
                        "source": "CodeAgent",
                        "execution_mode": "shared_folder",
                    },
                },
            )

        if response.status_code != 200:
            return {"status": "error", "message": f"Kali worker HTTP {response.status_code}: {response.text[:500]}", "findings": []}

        worker = response.json() if response.text else {}
        if not isinstance(worker, dict):
            return {"status": "error", "message": "Kali worker returned invalid response format", "findings": []}

        status = str(worker.get("status", "")).lower()
        stdout = worker.get("stdout") or ""
        stderr = worker.get("stderr") or ""
        exit_code = worker.get("returncode")

        if status in {"timeout"}:
            return {"status": "timeout", "message": worker.get("error") or f"bandit timed out after {timeout}s", "findings": [], "stdout": stdout, "stderr": stderr, "exit_code": exit_code}
        if status in {"tool_not_allowed", "tool_missing", "unavailable", "not_configured"}:
            return {"status": status, "message": worker.get("error") or "bandit unavailable", "findings": [], "stdout": stdout, "stderr": stderr, "exit_code": exit_code}

        if not stdout.strip():
            return {"status": "error", "message": (worker.get("error") or stderr or "bandit output empty")[:1000], "findings": [], "stdout": stdout, "stderr": stderr, "exit_code": exit_code}

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {"status": "error", "message": f"bandit output not JSON: {stdout[:300]}", "findings": [], "stdout": stdout, "stderr": stderr, "exit_code": exit_code}

        findings = []
        for r in data.get("results", []):
            findings.append({
                "type": r.get("test_name", "unknown"),
                "test_id": r.get("test_id", ""),
                "file": r.get("filename", ""),
                "line": r.get("line_number", 0),
                "severity": SEVERITY_MAP.get(r.get("issue_severity", "LOW"), "low"),
                "confidence": CONFIDENCE_MAP.get(r.get("issue_confidence", "LOW"), "possible"),
                "message": r.get("issue_text", ""),
                "code": r.get("code", ""),
                "cwe": r.get("issue_cwe", {}).get("id", ""),
                "more_info": r.get("more_info", ""),
            })

        totals = data.get("metrics", {}).get("_totals", {})
        by_severity = {
            "high": int(totals.get("SEVERITY.HIGH", 0)),
            "medium": int(totals.get("SEVERITY.MEDIUM", 0)),
            "low": int(totals.get("SEVERITY.LOW", 0)),
        }

        return {
            "status": "success" if findings else "success_no_findings",
            "tool": "bandit",
            "path": path,
            "findings": findings,
            "total": len(findings),
            "by_severity": by_severity,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "worker_execution_id": worker.get("execution_id"),
            "summary": f"bandit found {len(findings)} Python issues | high:{by_severity['high']} medium:{by_severity['medium']}",
        }
    except httpx.TimeoutException:
        return {"status": "timeout", "message": f"bandit timed out after {timeout}s", "findings": []}
    except httpx.RequestError as e:
        return {"status": "error", "message": f"Kali worker unreachable: {e}", "findings": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}

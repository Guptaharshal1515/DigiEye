"""
AI_KAVACH — gitleaks_runner.py
Remote execution via Kali worker.
"""

import json
import os
from pathlib import Path

import httpx

KALI_WORKER_URL = os.getenv(
    "AI_KAVACH_KALI_WORKER_URL",
    "http://127.0.0.1:8082",
).rstrip("/")


def _to_kali_shared_path(path: str) -> str:
    if not path:
        return path
    if path.startswith(f"/mnt/hgfs/{os.getenv("AI_KAVACH_SHARED_ROOT", "AI_Kavach_CodeAgent")}"):
        return path

    ai_kavach_root = os.path.abspath(str(Path(__file__).resolve().parents[2]))
    input_abs = os.path.abspath(path)
    try:
        common = os.path.commonpath([os.path.normcase(ai_kavach_root), os.path.normcase(input_abs)])
    except ValueError:
        return path.replace("\\", "/")

    if common == os.path.normcase(ai_kavach_root):
        rel = os.path.relpath(input_abs, ai_kavach_root)
        rel_posix = Path(rel).as_posix()
        return f"/mnt/hgfs/{os.getenv("AI_KAVACH_SHARED_ROOT", "AI_Kavach_CodeAgent")}" if rel_posix == "." else f"/mnt/hgfs/AI_Kavach_CodeAgent/{rel_posix}"

    return path.replace("\\", "/")


def run_gitleaks(path: str, timeout: int = 120) -> dict:
    """Run gitleaks remotely and parse JSON findings."""
    if not Path(path).exists():
        return {"status": "error", "message": f"Path not found: {path}", "findings": []}

    kali_path = _to_kali_shared_path(path)
    args = ["detect", "--source", kali_path, "--report-format", "json", "--no-banner"]

    try:
        with httpx.Client(timeout=timeout + 30) as client:
            response = client.post(f"{KALI_WORKER_URL}/execute", json={"tool": "gitleaks", "args": args})

        if response.status_code != 200:
            return {"status": "error", "message": f"Kali worker HTTP {response.status_code}: {response.text[:500]}", "findings": []}

        worker = response.json()
        stdout = worker.get("stdout", "") or ""
        stderr = worker.get("stderr", "") or ""

        findings = []
        raw_data = []
        if stdout.strip():
            try:
                raw_data = json.loads(stdout)
            except json.JSONDecodeError:
                raw_data = []

        for leak in (raw_data or []):
            findings.append({
                "type": "Hardcoded Secret",
                "rule_id": leak.get("RuleID", ""),
                "severity": "critical",
                "file": leak.get("File", ""),
                "line": leak.get("StartLine", 0),
                "commit": leak.get("Commit", ""),
                "author": leak.get("Author", ""),
                "date": leak.get("Date", ""),
                "secret_preview": (leak.get("Secret", "")[:20] + "...") if leak.get("Secret") else "",
                "requires_rotation": True,
                "in_git_history": True,
            })

        if not worker.get("success", False) and not findings and stderr:
            return {"status": "error", "message": stderr[:500], "findings": []}

        return {
            "status": "success",
            "tool": "gitleaks",
            "path": path,
            "findings": findings,
            "total": len(findings),
            "summary": f"gitleaks found {len(findings)} secrets (including git history)",
            "worker": "kali",
            "worker_execution_id": worker.get("execution_id"),
        }
    except httpx.TimeoutException:
        return {"status": "timeout", "message": f"gitleaks timed out after {timeout}s", "findings": []}
    except httpx.RequestError as e:
        return {"status": "error", "message": f"Kali worker unreachable: {e}", "findings": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}

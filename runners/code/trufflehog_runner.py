"""
AI_KAVACH — trufflehog_runner.py
Remote execution via Kali worker.
"""

import json
import logging
import os
from pathlib import Path

import httpx

logger_th = logging.getLogger("ai_kavach.code_tools.trufflehog")

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


def run_trufflehog(path: str, only_verified: bool = False, timeout: int = 300) -> dict:
    """Run trufflehog remotely on Kali and parse NDJSON output."""
    if not Path(path).exists():
        return {"status": "error", "message": f"Path not found: {path}", "findings": []}

    kali_path = _to_kali_shared_path(path)
    args = ["filesystem", kali_path, "--json", "--no-update"]
    if only_verified:
        args.append("--only-verified")

    try:
        with httpx.Client(timeout=timeout + 30) as client:
            response = client.post(f"{KALI_WORKER_URL}/execute", json={"tool": "trufflehog", "args": args})

        if response.status_code != 200:
            return {"status": "error", "message": f"Kali worker HTTP {response.status_code}: {response.text[:500]}", "findings": []}

        worker = response.json()
        stdout = worker.get("stdout", "") or ""
        stderr = worker.get("stderr", "") or ""

        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            findings.append({
                "type": "Hardcoded Secret",
                "detector": obj.get("DetectorName", "unknown"),
                "severity": "critical",
                "file": obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                "line": obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                "verified": obj.get("Verified", False),
                "raw_preview": (obj.get("Raw", "")[:50] + "...") if obj.get("Raw") else "",
                "requires_rotation": True,
            })

        if not worker.get("success", False) and not findings:
            return {"status": "error", "message": worker.get("error") or stderr[:500] or "trufflehog failed", "findings": []}

        return {
            "status": "success",
            "tool": "trufflehog",
            "path": path,
            "findings": findings,
            "total": len(findings),
            "summary": f"trufflehog found {len(findings)} secrets in {path}",
            "worker": "kali",
            "worker_execution_id": worker.get("execution_id"),
        }
    except httpx.TimeoutException:
        return {"status": "timeout", "message": f"trufflehog timed out after {timeout}s", "findings": []}
    except httpx.RequestError as e:
        return {"status": "error", "message": f"Kali worker unreachable: {e}", "findings": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}

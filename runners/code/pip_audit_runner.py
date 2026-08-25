"""
AI_KAVACH — pip_audit_runner.py
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


def run_pip_audit(path: str, timeout: int = 120) -> dict:
    """Run pip-audit remotely and parse JSON output."""
    if not Path(path).exists():
        return {"status": "error", "message": f"Path not found: {path}", "findings": []}

    kali_path = _to_kali_shared_path(path)
    req_file = Path(path) / "requirements.txt"
    pyproject = Path(path) / "pyproject.toml"

    args = ["--format", "json"]
    if req_file.exists():
        args += ["-r", _to_kali_shared_path(str(req_file))]
    elif pyproject.exists():
        args += ["--path", kali_path]
    else:
        return {"status": "error", "message": "No requirements.txt or pyproject.toml found", "findings": []}

    try:
        with httpx.Client(timeout=timeout + 30) as client:
            response = client.post(f"{KALI_WORKER_URL}/execute", json={"tool": "pip-audit", "args": args})

        if response.status_code != 200:
            return {"status": "error", "message": f"Kali worker HTTP {response.status_code}: {response.text[:500]}", "findings": []}

        worker = response.json()
        stdout = worker.get("stdout", "") or ""
        stderr = worker.get("stderr", "") or ""

        if not stdout.strip():
            return {"status": "error", "message": worker.get("error") or stderr[:500] or "pip-audit output empty", "findings": []}

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {"status": "error", "message": f"pip-audit output not JSON: {stdout[:300]}", "findings": []}

        findings = []
        for pkg in (data if isinstance(data, list) else data.get("dependencies", [])):
            for vuln in pkg.get("vulns", []):
                fix_versions = vuln.get("fix_versions", []) or []
                fix = fix_versions[0] if fix_versions else "unknown"
                findings.append({
                    "type": "Vulnerable Dependency",
                    "severity": "medium",
                    "package": pkg.get("name", ""),
                    "current_version": pkg.get("version", ""),
                    "fix_version": fix,
                    "cve": vuln.get("id", ""),
                    "description": vuln.get("description", ""),
                    "upgrade_cmd": f"pip install {pkg.get('name','')}=={fix}" if fix != "unknown" else "",
                })

        return {
            "status": "success",
            "tool": "pip-audit",
            "path": path,
            "findings": findings,
            "total": len(findings),
            "summary": f"pip-audit found {len(findings)} vulnerable Python packages",
            "worker": "kali",
            "worker_execution_id": worker.get("execution_id"),
        }
    except httpx.TimeoutException:
        return {"status": "timeout", "message": f"pip-audit timed out after {timeout}s", "findings": []}
    except httpx.RequestError as e:
        return {"status": "error", "message": f"Kali worker unreachable: {e}", "findings": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}

"""
AI_KAVACH — Flawfinder Runner
Remote execution via Kali worker.
"""

import logging
import os
import re
from pathlib import Path

import httpx

logger = logging.getLogger("ai_kavach.code_tools.flawfinder")

KALI_WORKER_URL = os.getenv(
    "AI_KAVACH_KALI_WORKER_URL",
    "http://127.0.0.1:8082",
).rstrip("/")

RISK_SEVERITY = {5: "critical", 4: "high", 3: "high", 2: "medium", 1: "low", 0: "low"}


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


def run_flawfinder(path: str, min_level: int = 1, timeout: int = 120) -> dict:
    if not Path(path).exists():
        return {"status": "error", "message": f"Path not found: {path}", "findings": []}

    kali_path = _to_kali_shared_path(path)
    args = ["--quiet", "--dataonly", f"--minlevel={min_level}", "--columns", kali_path]

    try:
        with httpx.Client(timeout=timeout + 30) as client:
            response = client.post(f"{KALI_WORKER_URL}/execute", json={"tool": "flawfinder", "args": args})

        if response.status_code != 200:
            return {"status": "error", "message": f"Kali worker HTTP {response.status_code}: {response.text[:500]}", "findings": []}

        worker = response.json()
        raw = worker.get("stdout", "") or ""
        findings = _parse_flawfinder_output(raw)
        by_severity = _count_by_severity(findings)

        if not worker.get("success", False) and not findings:
            return {"status": "error", "message": worker.get("error") or (worker.get("stderr", "")[:500]), "findings": []}

        return {
            "status": "success",
            "tool": "flawfinder",
            "path": path,
            "findings": findings,
            "total": len(findings),
            "by_severity": by_severity,
            "summary": (
                f"flawfinder found {len(findings)} C/C++ issues | "
                f"critical:{by_severity.get('critical',0)} high:{by_severity.get('high',0)}"
            ),
            "worker": "kali",
            "worker_execution_id": worker.get("execution_id"),
        }
    except httpx.TimeoutException:
        return {"status": "timeout", "message": "flawfinder timed out", "findings": []}
    except httpx.RequestError as e:
        return {"status": "error", "message": f"Kali worker unreachable: {e}", "findings": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}


def _parse_flawfinder_output(raw: str) -> list:
    findings = []
    pattern = re.compile(
        r'(?P<file>[^\s:]+):(?P<line>\d+):\s+'
        r'(?P<level>\[\d+\])\s+'
        r'(?P<func>\w+)\s+'
        r'(?P<message>.+)',
        re.MULTILINE,
    )
    for m in pattern.finditer(raw):
        try:
            level = int(m.group("level").strip("[]"))
        except ValueError:
            level = 1

        findings.append({
            "type": _classify_function(m.group("func")),
            "function": m.group("func"),
            "file": m.group("file"),
            "line": int(m.group("line")),
            "severity": RISK_SEVERITY.get(level, "low"),
            "risk_level": level,
            "message": m.group("message").strip(),
        })
    return findings


def _classify_function(func: str) -> str:
    func = func.lower()
    if any(x in func for x in ["strcpy", "strcat", "gets", "sprintf", "scanf"]):
        return "Buffer Overflow"
    if any(x in func for x in ["printf", "fprintf", "syslog"]):
        return "Format String"
    if any(x in func for x in ["system", "exec", "popen", "chmod"]):
        return "Shell Injection"
    if any(x in func for x in ["rand", "srand"]):
        return "Weak Random"
    if any(x in func for x in ["tmp", "tmpnam", "tempnam"]):
        return "Race Condition"
    return "Unsafe Function"


def _count_by_severity(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts

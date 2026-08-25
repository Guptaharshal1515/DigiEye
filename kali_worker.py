import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="AI_KAVACH Kali Worker")


class ToolRequest(BaseModel):
    tool: str
    args: list[str] = Field(default_factory=list)
    timeout_seconds: int = 120
    cwd: str | None = None
    execution_context: dict[str, Any] = Field(default_factory=dict)


class JobCreateRequest(ToolRequest):
    execution_id: str | None = None


ALLOWED_TOOLS = {
    "semgrep": "semgrep",
    "bandit": "bandit",
    "nmap": "nmap",
    "ffuf": "ffuf",
    "sqlmap": "sqlmap",
    "trufflehog": "trufflehog",
    "pip-audit": "pip-audit",
    "gitleaks": "gitleaks",
    "afl-fuzz": "afl-fuzz",
    "flawfinder": "flawfinder",
    "nikto": "nikto",
}

JOBS: dict[str, dict] = {}
_JOB_LOCK = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _sanitize(value: Any) -> str:
    s = str(value or "")
    for token in ["authorization", "api_key", "token", "password", "secret", "bearer"]:
        s = s.replace(token, "***")
        s = s.replace(token.upper(), "***")
    return s


def _print_event(title: str, payload: dict[str, Any]) -> None:
    print(f"[{_ts()}] {title}")
    for k, v in payload.items():
        if v is None or v == "":
            continue
        print(f"{k:14}: {_sanitize(v)}")
    print("-" * 44)


def _run_job(job_id: str) -> None:
    with _JOB_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        tool = job["tool"]
        binary = ALLOWED_TOOLS[tool]
        job["status"] = "running"
        job["started_at"] = _utc_now()
        started_ts = time.time()

    command = [binary, *job.get("args", [])]
    _print_event("JOB STARTED", {
        "execution_id": job_id,
        "tool": tool,
        "command": " ".join(command),
        "target": job.get("execution_context", {}).get("target"),
        "stage": job.get("execution_context", {}).get("stage"),
        "source": job.get("execution_context", {}).get("source"),
        "cwd": job.get("cwd"),
        "timeout": job.get("timeout_seconds"),
        "mode": job.get("execution_context", {}).get("execution_mode", "local"),
    })

    proc = None
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=job.get("cwd") or None,
        )
        with _JOB_LOCK:
            if job_id in JOBS:
                JOBS[job_id]["pid"] = proc.pid

        try:
            stdout, stderr = proc.communicate(timeout=int(job.get("timeout_seconds", 120)))
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            duration_ms = round((time.time() - started_ts) * 1000)
            with _JOB_LOCK:
                if job_id in JOBS:
                    JOBS[job_id].update({
                        "status": "timeout",
                        "success": False,
                        "returncode": None,
                        "stdout": stdout,
                        "stderr": stderr,
                        "error": "Tool execution timed out",
                        "completed_at": _utc_now(),
                        "duration_ms": duration_ms,
                    })
            _print_event("JOB FAILED", {
                "execution_id": job_id,
                "tool": tool,
                "status": "timeout",
                "reason": "Tool execution timed out",
            })
            return

        returncode = proc.returncode
        success = returncode == 0
        status = "success" if success else "error"
        duration_ms = round((time.time() - started_ts) * 1000)

        with _JOB_LOCK:
            if job_id in JOBS:
                JOBS[job_id].update({
                    "status": status,
                    "success": success,
                    "returncode": returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                    "error": "" if success else (stderr.strip() or stdout.strip() or "tool exited non-zero"),
                    "completed_at": _utc_now(),
                    "duration_ms": duration_ms,
                })

        _print_event("TOOL OUTPUT", {
            "execution_id": job_id,
            "stdout": (stdout or "")[:2000],
            "stderr": (stderr or "")[:2000],
        })
        _print_event("JOB COMPLETED" if success else "JOB FAILED", {
            "execution_id": job_id,
            "tool": tool,
            "status": status,
            "exit_code": returncode,
            "duration_ms": duration_ms,
        })

    except Exception as e:
        duration_ms = round((time.time() - started_ts) * 1000)
        with _JOB_LOCK:
            if job_id in JOBS:
                JOBS[job_id].update({
                    "status": "error",
                    "success": False,
                    "returncode": None,
                    "stdout": "",
                    "stderr": "",
                    "error": str(e),
                    "completed_at": _utc_now(),
                    "duration_ms": duration_ms,
                })
        _print_event("JOB FAILED", {
            "execution_id": job_id,
            "tool": tool,
            "status": "error",
            "reason": str(e),
        })


@app.get("/health")
def health():
    return {
        "status": "ok",
        "worker": "kali",
        "tools": list(ALLOWED_TOOLS.keys()),
        "timestamp": _utc_now(),
    }


@app.post("/execute")
def execute(req: ToolRequest):
    execution_id = str(uuid.uuid4())

    if req.tool not in ALLOWED_TOOLS:
        _print_event("JOB REJECTED", {
            "execution_id": execution_id,
            "tool": req.tool,
            "status": "tool_not_allowed",
            "reason": "not permitted by worker allowlist",
        })
        return {
            "success": False,
            "tool": req.tool,
            "execution_id": execution_id,
            "status": "tool_not_allowed",
            "error": "Tool not allowed",
        }

    binary = ALLOWED_TOOLS[req.tool]
    if shutil.which(binary) is None:
        _print_event("JOB REJECTED", {
            "execution_id": execution_id,
            "tool": req.tool,
            "status": "tool_missing",
            "reason": f"Executable not found: {binary}",
        })
        return {
            "success": False,
            "tool": req.tool,
            "execution_id": execution_id,
            "status": "tool_missing",
            "error": f"Executable not found: {binary}",
        }

    with _JOB_LOCK:
        JOBS[execution_id] = {
            "execution_id": execution_id,
            "tool": req.tool,
            "args": req.args,
            "timeout_seconds": int(req.timeout_seconds or 120),
            "cwd": req.cwd,
            "execution_context": req.execution_context,
            "status": "queued",
            "success": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": "",
            "created_at": _utc_now(),
        }

    _print_event("JOB CREATED", {
        "execution_id": execution_id,
        "tool": req.tool,
        "stage": req.execution_context.get("stage"),
        "target": req.execution_context.get("target"),
        "source": req.execution_context.get("source"),
        "status": "queued",
    })

    _run_job(execution_id)
    with _JOB_LOCK:
        return dict(JOBS.get(execution_id, {}))


@app.post("/jobs")
def create_job(req: JobCreateRequest):
    execution_id = req.execution_id or str(uuid.uuid4())

    if req.tool not in ALLOWED_TOOLS:
        return {
            "success": False,
            "tool": req.tool,
            "execution_id": execution_id,
            "status": "tool_not_allowed",
            "error": "Tool not allowed",
        }

    binary = ALLOWED_TOOLS[req.tool]
    if shutil.which(binary) is None:
        return {
            "success": False,
            "tool": req.tool,
            "execution_id": execution_id,
            "status": "tool_missing",
            "error": f"Executable not found: {binary}",
        }

    with _JOB_LOCK:
        JOBS[execution_id] = {
            "execution_id": execution_id,
            "tool": req.tool,
            "args": req.args,
            "timeout_seconds": int(req.timeout_seconds or 120),
            "cwd": req.cwd,
            "execution_context": req.execution_context,
            "status": "queued",
            "success": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": "",
            "created_at": _utc_now(),
        }

    _print_event("JOB CREATED", {
        "execution_id": execution_id,
        "tool": req.tool,
        "stage": req.execution_context.get("stage"),
        "target": req.execution_context.get("target"),
        "source": req.execution_context.get("source"),
        "status": "queued",
    })

    thread = threading.Thread(target=_run_job, args=(execution_id,), daemon=True)
    thread.start()
    return {"execution_id": execution_id, "status": "queued", "tool": req.tool, "success": True}


@app.get("/jobs/{execution_id}")
def get_job(execution_id: str):
    with _JOB_LOCK:
        job = JOBS.get(execution_id)
    if not job:
        return {"execution_id": execution_id, "status": "error", "error": "job_not_found", "success": False}
    return job


@app.post("/jobs/{execution_id}/stop")
def stop_job(execution_id: str):
    with _JOB_LOCK:
        job = JOBS.get(execution_id)
    if not job:
        return {"execution_id": execution_id, "status": "error", "error": "job_not_found", "success": False}

    pid = job.get("pid")
    if not pid:
        return {"execution_id": execution_id, "status": job.get("status", "queued"), "success": False, "error": "job_not_running"}

    try:
        import os
        os.kill(pid, 9)
    except Exception:
        pass

    with _JOB_LOCK:
        if execution_id in JOBS:
            JOBS[execution_id]["status"] = "timeout"
            JOBS[execution_id]["error"] = "Stopped by control plane"
            JOBS[execution_id]["completed_at"] = _utc_now()

    _print_event("JOB FAILED", {
        "execution_id": execution_id,
        "tool": job.get("tool"),
        "status": "timeout",
        "reason": "Stopped by control plane",
    })
    return dict(JOBS.get(execution_id, {}))


if __name__ == "__main__":
    import uvicorn

    print("=" * 44)
    print(" AI_KAVACH KALI WORKER")
    print("=" * 44)
    uvicorn.run(app, host="0.0.0.0", port=8082)

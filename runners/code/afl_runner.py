"""AFL++ runner with job-oriented Kali worker execution."""

import os
import re
import time
import uuid
from pathlib import Path

import httpx

from tools.target_utils import to_kali_shared_path

KALI_WORKER_URL = os.getenv("AI_KAVACH_KALI_WORKER_URL", "http://127.0.0.1:8082").rstrip("/")


def _is_fuzzable_binary(binary_path: Path) -> bool:
    return binary_path.exists() and binary_path.is_file() and binary_path.suffix.lower() not in {".py", ".js", ".ts", ".java"}


def _extract_metric(text: str, pattern: str) -> int:
    m = re.search(pattern, text, flags=re.IGNORECASE)
    if not m:
        return 0
    try:
        return int(m.group(1))
    except Exception:
        return 0


def run_afl(binary_path: str, corpus_dir: str = "", timeout_seconds: int = 300, memory_limit_mb: int = 512, input_file: str = "", qemu_mode: bool = False) -> dict:
    binary = Path(binary_path)
    if not binary.exists():
        return {"status": "error", "message": f"Binary not found: {binary_path}", "findings": []}
    if not _is_fuzzable_binary(binary):
        return {"status": "not_applicable", "message": "AFL requires a fuzzable executable target.", "findings": []}
    if not corpus_dir:
        return {"status": "skipped", "message": "AFL seed corpus not provided.", "findings": []}
    if not Path(corpus_dir).exists():
        return {"status": "error", "message": f"Corpus dir not found: {corpus_dir}", "findings": []}

    kali_bin = to_kali_shared_path(binary_path)
    kali_corpus = to_kali_shared_path(corpus_dir)
    safe_timeout = max(10, min(int(timeout_seconds), 600))
    kali_out = f"/tmp/ai_kavach_afl_{binary.stem}"
    job_id = f"afl-{uuid.uuid4().hex[:10]}"

    args = ["-i", kali_corpus, "-o", kali_out, "-m", str(memory_limit_mb), "-t", "1000", "-V", str(safe_timeout)]
    if qemu_mode:
        args.append("-Q")
    args += ["--", kali_bin, input_file if input_file else "@@"]

    try:
        with httpx.Client(timeout=safe_timeout + 45) as client:
            create = client.post(
                f"{KALI_WORKER_URL}/jobs",
                json={
                    "execution_id": job_id,
                    "tool": "afl-fuzz",
                    "args": args,
                    "timeout_seconds": safe_timeout + 20,
                    "cwd": to_kali_shared_path(str(binary.parent)),
                    "execution_context": {
                        "tool": "afl-fuzz",
                        "stage": "code_fuzzer",
                        "target": kali_bin,
                        "source": "CodeAgent",
                        "execution_mode": "shared_folder",
                    },
                },
            )
            if create.status_code != 200:
                return {"status": "error", "message": f"Kali worker HTTP {create.status_code}: {create.text[:500]}", "findings": []}

            worker = {}
            terminal = None
            for _ in range(max(10, safe_timeout)):
                status_resp = client.get(f"{KALI_WORKER_URL}/jobs/{job_id}")
                if status_resp.status_code != 200:
                    break
                worker = status_resp.json()
                s = str(worker.get("status", "")).lower()
                if s in {"success", "success_no_findings", "error", "timeout", "tool_not_allowed", "tool_missing", "not_configured", "unavailable"}:
                    terminal = s
                    break
                time.sleep(1)

            if terminal is None:
                client.post(f"{KALI_WORKER_URL}/jobs/{job_id}/stop")
                worker = {"status": "timeout", "error": f"AFL job exceeded control budget ({safe_timeout}s)", "stdout": "", "stderr": ""}

        status = str(worker.get("status", "")).lower()
        stdout = worker.get("stdout", "") or ""
        stderr = worker.get("stderr", "") or ""
        combined = f"{stdout}\n{stderr}"

        crashes = _extract_metric(combined, r"unique_crashes\s*[:=]\s*(\d+)")
        hangs = _extract_metric(combined, r"unique_hangs\s*[:=]\s*(\d+)")
        execs = _extract_metric(combined, r"execs_done\s*[:=]\s*(\d+)")

        findings = []
        if crashes > 0:
            findings.append({"type": "Crash", "severity": "critical", "binary": binary_path, "message": f"AFL++ reported {crashes} crash artifacts", "requires_triage": True})
        if hangs > 0:
            findings.append({"type": "Hang", "severity": "high", "binary": binary_path, "message": f"AFL++ reported {hangs} hang artifacts", "requires_triage": True})

        if status in {"tool_not_allowed", "tool_missing", "unavailable", "not_configured"}:
            return {"status": status, "message": worker.get("error") or "AFL unavailable", "findings": [], "job_id": job_id}
        if status == "timeout":
            return {"status": "timeout", "message": worker.get("error") or f"AFL fuzzing budget reached ({safe_timeout}s)", "findings": findings, "job_id": job_id, "stdout": stdout, "stderr": stderr}
        if status == "error" and not findings:
            return {"status": "error", "message": worker.get("error") or stderr[:500] or "afl-fuzz failed", "findings": [], "job_id": job_id}

        return {
            "status": "success" if findings else "success_no_findings",
            "tool": "afl++",
            "binary": binary_path,
            "fuzz_duration_s": safe_timeout,
            "crashes": crashes,
            "hangs": hangs,
            "executions": execs,
            "findings": findings,
            "total": len(findings),
            "summary": f"AFL++ ran {safe_timeout}s | crashes:{crashes} hangs:{hangs} execs:{execs}",
            "worker": "kali",
            "worker_execution_id": worker.get("execution_id") or job_id,
            "job_id": job_id,
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "afl_output_dir": kali_out,
        }
    except httpx.TimeoutException:
        return {"status": "timeout", "message": f"afl-fuzz timed out after {safe_timeout}s", "findings": []}
    except httpx.RequestError as e:
        return {"status": "error", "message": f"Kali worker unreachable: {e}", "findings": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}

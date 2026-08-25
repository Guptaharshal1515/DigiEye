"""
AI_KAVACH — Atheris Runner (Python Fuzzer)
=========================================
run_atheris(): Python fuzzing using Google's Atheris (libFuzzer-based).
Finds: exceptions, assertion errors, crashes in Python code.

Author: AI_KAVACH Team (— Harshal)
"""

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

logger = logging.getLogger("ai_kavach.code_tools.atheris")


def run_atheris(
    target_module: str,
    target_function: str = "fuzz",
    corpus_dir: str = "",
    timeout_seconds: int = 120,
    max_input_size: int = 4096,
) -> dict:
    """
    Run Atheris fuzzer on a Python module.

    Args:
        target_module:    Python module path containing the fuzz target.
        target_function:  Function name to fuzz (must accept bytes).
        corpus_dir:       Initial seed corpus directory.
        timeout_seconds:  Fuzz duration (default 120s).
        max_input_size:   Max input size in bytes.

    Returns:
        Normalized findings dict.
    """
    try:
        import atheris  
    except ImportError:
        return {
            "status":  "not_installed",
            "message": "atheris not installed. Run: pip install atheris",
            "findings": [],
        }

    if not Path(target_module).exists():
        return {"status": "error", "message": f"Module not found: {target_module}", "findings": []}

    with tempfile.TemporaryDirectory() as tmpdir:
        corpus = corpus_dir or os.path.join(tmpdir, "corpus")
        os.makedirs(corpus, exist_ok=True)
        if not os.listdir(corpus):
            for i, seed in enumerate([b"test", b"\x00\x01\x02", b"A" * 100]):
                with open(os.path.join(corpus, f"seed{i}"), "wb") as f:
                    f.write(seed)

        crash_dir = os.path.join(tmpdir, "crashes")
        os.makedirs(crash_dir, exist_ok=True)

        
        harness_path = os.path.join(tmpdir, "harness.py")
        harness_code = f"""
import atheris
import sys
import importlib.util

spec = importlib.util.spec_from_file_location("target", "{target_module}")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

@atheris.instrument_func
def TestOneInput(data):
    try:
        getattr(mod, "{target_function}")(data)
    except SystemExit:
        pass

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
"""
        with open(harness_path, "w") as f:
            f.write(harness_code)

        cmd = [
            "python", harness_path,
            "-max_len={}".format(max_input_size),
            f"-artifact_prefix={crash_dir}/",
            "-timeout=10",
            "-rss_limit_mb=512",
            corpus,
        ]

        crashes = []
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=tmpdir
            )
            time.sleep(timeout_seconds)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

            _, stderr = proc.communicate()

            
            crash_files = list(Path(crash_dir).iterdir()) if Path(crash_dir).exists() else []
            for cf in crash_files:
                try:
                    content = cf.read_bytes()
                    crashes.append({
                        "filename":   cf.name,
                        "size_bytes": len(content),
                        "hex_preview": content[:32].hex(),
                    })
                except Exception:
                    pass

            
            stderr_text = stderr.decode("utf-8", errors="replace") if stderr else ""
            exceptions  = _parse_atheris_crashes(stderr_text)

            findings = []
            for crash in crashes:
                findings.append({
                    "type":     "Python Crash",
                    "severity": "high",
                    "module":   target_module,
                    "function": target_function,
                    "input":    crash.get("hex_preview", ""),
                    "message":  f"Atheris found crash: {crash.get('filename','')}",
                })
            for exc in exceptions:
                findings.append({
                    "type":     f"Python Exception: {exc.get('exception_type','')}",
                    "severity": "high",
                    "module":   target_module,
                    "function": target_function,
                    "message":  exc.get("message", ""),
                    "traceback": exc.get("traceback", ""),
                })

            return {
                "status":          "success",
                "tool":            "atheris",
                "module":          target_module,
                "fuzz_duration_s": timeout_seconds,
                "crashes":         len(crashes),
                "findings":        findings,
                "total":           len(findings),
                "summary": (
                    f"Atheris ran {timeout_seconds}s on {target_module}.{target_function} | "
                    f"crashes:{len(crashes)}"
                ),
            }

        except Exception as e:
            return {"status": "error", "message": str(e), "findings": []}


def _parse_atheris_crashes(stderr: str) -> list:
    """Parse exception info from Atheris stderr output."""
    exceptions = []
    if "Traceback" in stderr:
        blocks = stderr.split("==")
        for block in blocks:
            if "Traceback" in block:
                lines = block.strip().split("\n")
                exc_type = ""
                for line in reversed(lines):
                    if line and not line.startswith(" "):
                        exc_type = line.split(":")[0]
                        break
                exceptions.append({
                    "exception_type": exc_type,
                    "message":        "\n".join(lines[-3:]),
                    "traceback":      block[:500],
                })
    return exceptions
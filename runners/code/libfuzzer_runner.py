"""
AI_KAVACH — libFuzzer Runner
===========================
run_libfuzzer(): LLVM libFuzzer for C/C++ targets compiled with -fsanitize=fuzzer.
Faster than AFL++ for instrumented targets. Built into LLVM/Clang.

Author: AI_KAVACH Team (— Harshal)
"""

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

logger = logging.getLogger("ai_kavach.code_tools.libfuzzer")


def run_libfuzzer(
    binary_path: str,
    corpus_dir: str = "",
    timeout_seconds: int = 300,
    max_input_size: int = 4096,
    jobs: int = 1,
) -> dict:
    """
    Run libFuzzer-instrumented binary.

    Args:
        binary_path:      Path to binary compiled with -fsanitize=fuzzer.
        corpus_dir:       Seed corpus directory.
        timeout_seconds:  Fuzz duration (default 300s).
        max_input_size:   Max input size (-max_len).
        jobs:             Parallel jobs (-jobs).

    Returns:
        Normalized findings dict.
    """
    if not Path(binary_path).exists():
        return {"status": "error", "message": f"Binary not found: {binary_path}", "findings": []}

    if not os.access(binary_path, os.X_OK):
        return {"status": "error", "message": f"Binary not executable: {binary_path}", "findings": []}

    with tempfile.TemporaryDirectory() as tmpdir:
        corpus = corpus_dir or os.path.join(tmpdir, "corpus")
        os.makedirs(corpus, exist_ok=True)
        if not os.listdir(corpus):
            with open(os.path.join(corpus, "seed0"), "wb") as f:
                f.write(b"\x00" * 8)

        crash_dir = os.path.join(tmpdir, "crashes")
        os.makedirs(crash_dir, exist_ok=True)

        cmd = [
            binary_path,
            corpus,
            f"-max_len={max_input_size}",
            f"-jobs={jobs}",
            f"-workers={jobs}",
            f"-artifact_prefix={crash_dir}/",
            "-timeout=10",
            "-rss_limit_mb=1024",
            f"-max_total_time={timeout_seconds}",
            "-print_final_stats=1",
        ]

        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=1"
        env["UBSAN_OPTIONS"] = "print_stacktrace=1"

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
            )
            try:
                _, stderr = proc.communicate(timeout=timeout_seconds + 30)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, stderr = proc.communicate()

            stderr_text = stderr.decode("utf-8", errors="replace") if stderr else ""

            
            crashes = []
            if Path(crash_dir).exists():
                for cf in Path(crash_dir).iterdir():
                    try:
                        content = cf.read_bytes()
                        crashes.append({
                            "filename":    cf.name,
                            "size_bytes":  len(content),
                            "hex_preview": content[:32].hex(),
                        })
                    except Exception:
                        pass

            stats = _parse_libfuzzer_stats(stderr_text)
            findings = []
            for crash in crashes:
                crash_type = "Heap Buffer Overflow"
                if "stack-buffer" in stderr_text:
                    crash_type = "Stack Buffer Overflow"
                elif "use-after-free" in stderr_text.lower():
                    crash_type = "Use After Free"
                elif "null" in stderr_text.lower():
                    crash_type = "Null Dereference"

                findings.append({
                    "type":       crash_type,
                    "severity":   "critical",
                    "binary":     binary_path,
                    "input_file": crash.get("filename", ""),
                    "input_hex":  crash.get("hex_preview", ""),
                    "message":    f"libFuzzer crash: {crash_type}",
                })

            return {
                "status":          "success",
                "tool":            "libfuzzer",
                "binary":          binary_path,
                "fuzz_duration_s": timeout_seconds,
                "crashes":         len(crashes),
                "executions":      stats.get("executions", 0),
                "findings":        findings,
                "total":           len(findings),
                "summary": (
                    f"libFuzzer ran {timeout_seconds}s | "
                    f"crashes:{len(crashes)} execs:{stats.get('executions',0)}"
                ),
            }

        except Exception as e:
            return {"status": "error", "message": str(e), "findings": []}


def _parse_libfuzzer_stats(stderr: str) -> dict:
    stats = {}
    for line in stderr.splitlines():
        if "stat::" in line:
            parts = line.split("stat::")
            for p in parts[1:]:
                if ":" in p:
                    k, v = p.split(":", 1)
                    try:
                        stats[k.strip()] = int(v.strip().split()[0])
                    except (ValueError, IndexError):
                        pass
    return stats
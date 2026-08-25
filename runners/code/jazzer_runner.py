"""
AI_KAVACH — Jazzer Runner (JVM Fuzzer)
=====================================
run_jazzer(): Coverage-guided fuzzing for Java, Kotlin, Scala via Jazzer.
Finds: exceptions, assertion errors, injection flaws in JVM code.

Author: AI_KAVACH Team (— Harshal)
"""

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

logger = logging.getLogger("ai_kavach.code_tools.jazzer")


def run_jazzer(
    target_class: str,
    classpath: str,
    corpus_dir: str = "",
    timeout_seconds: int = 180,
    jvm_args: str = "",
) -> dict:
    """
    Run Jazzer fuzzer on a JVM target class.

    Args:
        target_class:     Fully qualified class name with fuzzerTestOneInput method.
        classpath:        Classpath string for the target (jars and class dirs).
        corpus_dir:       Initial seed corpus.
        timeout_seconds:  Fuzz duration (default 180s).
        jvm_args:         Additional JVM arguments.

    Returns:
        Normalized findings dict.
    """
    if not shutil.which("jazzer"):
        return {
            "status":  "not_installed",
            "message": (
                "jazzer not installed. Download from: "
                "https://github.com/CodeIntelligenceTesting/jazzer/releases"
            ),
            "findings": [],
        }

    with tempfile.TemporaryDirectory() as tmpdir:
        corpus = corpus_dir or os.path.join(tmpdir, "corpus")
        os.makedirs(corpus, exist_ok=True)
        if not os.listdir(corpus):
            with open(os.path.join(corpus, "seed0"), "wb") as f:
                f.write(b"test")

        crash_dir = tmpdir

        cmd = [
            "jazzer",
            f"--target_class={target_class}",
            f"--cp={classpath}",
            f"--artifact_prefix={crash_dir}/",
            "-timeout=10",
            f"-max_total_time={timeout_seconds}",
            corpus,
        ]

        if jvm_args:
            cmd.append(f"--jvm_args={jvm_args}")

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=tmpdir
            )
            time.sleep(timeout_seconds)
            proc.terminate()
            try:
                _, stderr = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, stderr = proc.communicate()

            stderr_text = stderr.decode("utf-8", errors="replace") if stderr else ""

            crashes = []
            for cf in Path(crash_dir).iterdir():
                if cf.is_file() and cf.suffix not in (".py", ".java", ".class"):
                    try:
                        content = cf.read_bytes()
                        crashes.append({
                            "filename":    cf.name,
                            "size_bytes":  len(content),
                            "hex_preview": content[:32].hex(),
                        })
                    except Exception:
                        pass

            exceptions = _parse_jazzer_exceptions(stderr_text)
            findings = []

            for crash in crashes:
                findings.append({
                    "type":     "JVM Crash",
                    "severity": "high",
                    "class":    target_class,
                    "input":    crash.get("hex_preview", ""),
                    "message":  f"Jazzer crash: {crash.get('filename','')}",
                })
            for exc in exceptions:
                findings.append({
                    "type":      f"Java Exception: {exc.get('type','')}",
                    "severity":  "high",
                    "class":     target_class,
                    "message":   exc.get("message", ""),
                    "stacktrace": exc.get("stacktrace", ""),
                })

            return {
                "status":          "success",
                "tool":            "jazzer",
                "target_class":    target_class,
                "fuzz_duration_s": timeout_seconds,
                "crashes":         len(crashes),
                "findings":        findings,
                "total":           len(findings),
                "summary": (
                    f"Jazzer ran {timeout_seconds}s on {target_class} | "
                    f"crashes:{len(crashes)} exceptions:{len(exceptions)}"
                ),
            }

        except Exception as e:
            return {"status": "error", "message": str(e), "findings": []}


def _parse_jazzer_exceptions(stderr: str) -> list:
    exceptions = []
    lines = stderr.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if "== Java Exception:" in line or "Exception in thread" in line:
            exc_type = ""
            if ":" in line:
                exc_type = line.split(":")[-1].strip().split("(")[0].strip()
            stacktrace = "\n".join(lines[i:i+10])
            exceptions.append({
                "type":       exc_type,
                "message":    line.strip(),
                "stacktrace": stacktrace,
            })
        i += 1
    return exceptions
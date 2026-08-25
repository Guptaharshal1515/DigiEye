"""
AI_KAVACH — Radamsa Runner (Mutation Fuzzer)
==========================================
run_radamsa(): Language-agnostic mutation-based fuzzer.
No compilation needed. Works on any program that reads input.
Good for: file parsers, network protocols, CLI tools.

Author: AI_KAVACH Team (— Harshal)
"""

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger("ai_kavach.code_tools.radamsa")


def run_radamsa(
    target_binary: str,
    seed_inputs: list,
    iterations: int = 1000,
    timeout_per_run: int = 5,
) -> dict:
    """
    Run radamsa mutation fuzzer.

    Args:
        target_binary:   Binary to fuzz (must read from stdin or file arg).
        seed_inputs:     List of seed input strings or file paths.
        iterations:      Number of mutations to test (default 1000).
        timeout_per_run: Seconds per execution (default 5).

    Returns:
        Normalized findings dict.
    """
    if not shutil.which("radamsa"):
        return {
            "status":  "not_installed",
            "message": (
                "radamsa not installed. "
                "Linux: apt install radamsa | "
                "Build: https://gitlab.com/akihe/radamsa"
            ),
            "findings": [],
        }

    if not shutil.which(target_binary.split()[0]):
        if not Path(target_binary).exists():
            return {"status": "error", "message": f"Binary not found: {target_binary}", "findings": []}

    crashes = []
    total_runs = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        
        seed_files = []
        for i, seed in enumerate(seed_inputs):
            seed_path = os.path.join(tmpdir, f"seed{i}.txt")
            if isinstance(seed, bytes):
                with open(seed_path, "wb") as f:
                    f.write(seed)
            else:
                with open(seed_path, "w") as f:
                    f.write(str(seed))
            seed_files.append(seed_path)

        if not seed_files:
            seed_path = os.path.join(tmpdir, "default_seed.txt")
            with open(seed_path, "w") as f:
                f.write("test input")
            seed_files.append(seed_path)

        
        for i in range(iterations):
            try:
                
                radamsa_cmd = ["radamsa"] + seed_files
                mutated = subprocess.run(
                    radamsa_cmd, capture_output=True, timeout=5
                )
                if mutated.returncode != 0:
                    continue

                mutated_input = mutated.stdout

                
                target_result = subprocess.run(
                    target_binary.split(),
                    input=mutated_input,
                    capture_output=True,
                    timeout=timeout_per_run,
                )
                total_runs += 1

                
                returncode = target_result.returncode
                if returncode in (-6, -11, -8, -4, 139, 134, 136, 132):
                    
                    crashes.append({
                        "iteration":   i,
                        "returncode":  returncode,
                        "signal":      _signal_name(returncode),
                        "input_hex":   mutated_input[:32].hex(),
                        "input_size":  len(mutated_input),
                        "stderr":      target_result.stderr[:200].decode("utf-8", errors="replace"),
                    })

            except subprocess.TimeoutExpired:
                
                crashes.append({
                    "iteration":  i,
                    "returncode": "HANG",
                    "signal":     "SIGALRM",
                    "input_hex":  "",
                    "input_size": 0,
                    "stderr":     "",
                })
            except Exception:
                continue

    findings = []
    for crash in crashes:
        findings.append({
            "type":      f"Crash ({crash.get('signal','unknown')})",
            "severity":  "high",
            "binary":    target_binary,
            "iteration": crash.get("iteration", 0),
            "returncode": crash.get("returncode", ""),
            "input_hex": crash.get("input_hex", ""),
            "message":   (
                f"radamsa found crash at iteration {crash.get('iteration',0)}: "
                f"signal {crash.get('signal','unknown')}"
            ),
        })

    return {
        "status":       "success",
        "tool":         "radamsa",
        "binary":       target_binary,
        "iterations":   total_runs,
        "crashes":      len(crashes),
        "findings":     findings,
        "total":        len(findings),
        "summary": (
            f"radamsa ran {total_runs} iterations on {target_binary} | "
            f"crashes:{len(crashes)}"
        ),
    }


def _signal_name(returncode: int) -> str:
    signals = {
        -6: "SIGABRT", -11: "SIGSEGV", -8: "SIGFPE", -4: "SIGILL",
        139: "SIGSEGV", 134: "SIGABRT", 136: "SIGFPE", 132: "SIGILL",
    }
    return signals.get(returncode, f"signal_{abs(returncode)}")
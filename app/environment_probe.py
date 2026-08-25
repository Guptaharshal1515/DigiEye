"""Runtime capability detection for the code-security agent."""

import logging
import os
import platform
import shutil
import subprocess
import sys
import sysconfig
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.config import KALI_WORKER_URL, LOCAL_LLM_URL, LOCAL_LLM_MODEL
from tools.registry import TOOL_REGISTRY, get_tools_for_agent

logger = logging.getLogger("ai_kavach.environment_probe")

_cache: Optional[dict] = None
_cache_timestamp: Optional[float] = None
_CACHE_TTL_SECONDS = 300

_TOOL_BINARY_MAP = {
    "run_semgrep": "semgrep",
    "run_bandit": "bandit",
    "run_codeql": "codeql",
    "run_flawfinder": "flawfinder",
    "run_sonarqube": "sonar-scanner",
    "run_afl": "afl-fuzz",
    "run_atheris": "python",
    "run_libfuzzer": "clang",
    "run_jazzer": "jazzer",
    "run_radamsa": "radamsa",
    "run_zap": "zap.sh",
    "run_nikto_dast": "nikto",
    "run_burp": "curl",
    "run_trufflehog": "trufflehog",
    "run_gitleaks": "gitleaks",
    "run_pip_audit": "pip-audit",
    "run_npm_audit": "npm",
    "run_safety": "safety",
    "run_snyk": "snyk",
    "run_retirejs": "retire",
    "analyze_git_log": "git",
    "manage_sandbox": "docker",
    "check_headers": "curl",
    "scan_endpoint": "curl",
}

_INTERNAL_TOOLS = {
    "generate_report", "lookup_cve", "check_ssl", "run_bandit",
    "run_pip_audit", "run_npm_audit", "run_safety",
    "run_detect_secrets", "analyze_git_log", "generate_patch",
    "apply_patch", "manage_sandbox",
}

def _get_python_scripts_dirs() -> list[str]:
    dirs = []
    scripts = sysconfig.get_path("scripts")
    if scripts:
        dirs.append(scripts)
    exe_dir = os.path.dirname(sys.executable)
    scripts_dir = os.path.join(exe_dir, "Scripts")
    if os.path.isdir(scripts_dir):
        dirs.append(scripts_dir)
    return dirs

def _which(binary: str) -> Optional[str]:
    path = shutil.which(binary)
    if path:
        return path
    for scripts_dir in _get_python_scripts_dirs():
        for ext in ("", ".exe", ".cmd"):
            candidate = os.path.join(scripts_dir, binary + ext)
            if os.path.isfile(candidate):
                return candidate
    return None

def _extract_version(output: str) -> str:
    import re
    for pattern in (r"v(\d+\.\d+[\.\d]*)", r"[Vv]ersion[:\s]+(\d+\.\d+[\.\d]*)", r"(\d+\.\d+\.\d+)"):
        match = re.search(pattern, output[:300])
        if match:
            return match.group(1)
    return output.strip().splitlines()[0][:80] if output.strip() else "unknown"

def _probe_tools() -> tuple[list, list, dict, dict]:
    available, missing, versions, paths = [], [], {}, {}
    for name, binary in _TOOL_BINARY_MAP.items():
        path = _which(binary)
        if not path:
            missing.append(name)
            continue
        try:
            result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 or result.stdout or result.stderr:
                available.append(name)
                versions[name] = _extract_version(result.stdout + result.stderr)
                paths[name] = path
            else:
                missing.append(name)
        except Exception:
            missing.append(name)
    for name in _INTERNAL_TOOLS:
        if name in TOOL_REGISTRY:
            available.append(name)
            versions[name] = "internal"
            paths[name] = "internal"
    return sorted(set(available)), sorted(set(missing)), versions, paths

def _probe_kali_worker_tools() -> tuple[list[str], Optional[str]]:
    try:
        with httpx.Client(timeout=5) as client:
            response = client.get(f"{KALI_WORKER_URL}/health")
        if response.status_code != 200:
            return [], f"Kali worker health check failed: HTTP {response.status_code}"
        data = response.json()
        tools = data.get("tools", [])
        return [str(x).lower() for x in tools], None
    except Exception as e:
        return [], f"Kali worker unreachable: {e}"

def _probe_ollama() -> tuple[bool, Optional[str]]:
    try:
        with httpx.Client(timeout=5) as client:
            response = client.get(f"{LOCAL_LLM_URL}/api/version")
        if response.status_code == 200:
            return True, response.json().get("version", "unknown")
    except Exception:
        pass
    return False, None

def _probe_model() -> bool:
    try:
        with httpx.Client(timeout=20) as client:
            response = client.post(
                f"{LOCAL_LLM_URL}/api/chat",
                json={"model": LOCAL_LLM_MODEL, "messages": [{"role": "user", "content": "ping"}], "stream": False,
                      "options": {"num_predict": 5}},
            )
        return response.status_code == 200
    except Exception:
        return False

def probe_environment(force: bool = False) -> dict:
    global _cache, _cache_timestamp
    now = time.time()
    if not force and _cache is not None and _cache_timestamp and now - _cache_timestamp < _CACHE_TTL_SECONDS:
        return _cache

    tools_available, tools_missing, tool_versions, tool_paths = _probe_tools()
    remote_tools, remote_warning = _probe_kali_worker_tools()
    remote_set = set(remote_tools)
    for tool_name, binary in _TOOL_BINARY_MAP.items():
        if binary in remote_set and tool_name not in tools_available:
            tools_available.append(tool_name)
            tool_versions[tool_name] = "remote"
            tool_paths[tool_name] = f"kali_worker:{KALI_WORKER_URL}"

    ollama_running, ollama_version = _probe_ollama()
    model_loaded = _probe_model() if ollama_running else False
    warnings = []
    if remote_warning:
        warnings.append(remote_warning)
    if not ollama_running:
        warnings.append(f"Ollama is not responding at {LOCAL_LLM_URL}")
    elif not model_loaded:
        warnings.append(f"Model '{LOCAL_LLM_MODEL}' is not responding")

    stat = shutil.disk_usage(".")
    result = {
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count() or 0,
        "disk_free_gb": round(stat.free / (1024**3), 1),
        "tools_available": sorted(set(tools_available)),
        "tools_missing": sorted(set(tools_missing)),
        "tool_versions": tool_versions,
        "tool_paths": tool_paths,
        "ollama_running": ollama_running,
        "ollama_version": ollama_version,
        "model_loaded": model_loaded,
        "model_name": LOCAL_LLM_MODEL,
        "probe_timestamp": datetime.now(timezone.utc).isoformat(),
        "probe_duration_ms": 0,
        "warnings": warnings,
    }
    _cache = result
    _cache_timestamp = now
    return result

def invalidate_cache() -> None:
    global _cache, _cache_timestamp
    _cache = None
    _cache_timestamp = None

def get_available_tools_for_agent(agent_type: str, env: Optional[dict] = None) -> list[str]:
    env = env or probe_environment()
    installed = set(env.get("tools_available", []))
    result = []
    for tool in get_tools_for_agent(agent_type):
        name = tool["name"]
        if name in installed:
            result.append(name)
    return result

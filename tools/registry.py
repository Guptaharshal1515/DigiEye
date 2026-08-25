"""Tool registry for Code Agent execution."""

import importlib
import logging
import os
import shutil
from typing import Callable, Optional

logger = logging.getLogger("ai_kavach.tools.registry")

TOOL_REGISTRY = {'generate_report': {'name': 'generate_report', 'description': 'Generate deterministic human-readable JSON and PDF security assessment reports from structured findings.', 'module': 'app.report_generator', 'function': 'generate_report', 'enabled': True, 'source': 'builtin', 'version': '1.0.0', 'agents': ['code_sast', 'code_orchestrator'], 'parameters': {'type': 'object', 'properties': {'findings': {'type': 'array'}, 'target': {'type': 'string'}, 'task_id': {'type': 'string'}, 'output_dir': {'type': 'string'}, 'summary': {'type': 'object'}}, 'required': ['findings', 'target', 'task_id', 'output_dir']}}, 'lookup_cve': {'name': 'lookup_cve', 'description': 'Query NIST NVD API for CVE details with 7-day local cache. Use for exact CVE IDs or keyword search. Only call when tool output provides a CVE ID or specific vulnerability.', 'parameters': {'cve_id': "string — 'CVE-2021-44228' OR 'search:sql injection php'"}, 'agents': ['code_sast', 'code_dast', 'code_dependency', 'code_orchestrator'], 'module': 'tools.cve_lookup', 'function': 'lookup_cve', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_semgrep': {'name': 'run_semgrep', 'description': 'Multi-language SAST using semgrep OWASP and security rulesets. Covers Python, JS, Java, Go, PHP, C/C++, Ruby, C#.', 'parameters': {'path': 'string — path to codebase directory or single file', 'rulesets': 'list — ruleset tags (default: owasp-top-ten, security-audit, secrets)'}, 'agents': ['code_sast', 'code_orchestrator'], 'module': 'runners.code.semgrep_runner', 'function': 'run_semgrep', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_bandit': {'name': 'run_bandit', 'description': 'Python-specific SAST. Detects SQLi, XSS, weak crypto, shell injection, pickle deserialization.', 'parameters': {'path': 'string — path to Python file or directory', 'timeout': 'integer — max seconds (default 180)'}, 'agents': ['code_sast', 'code_orchestrator'], 'module': 'runners.code.bandit_runner', 'function': 'run_bandit', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_codeql': {'name': 'run_codeql', 'description': 'Deep semantic code analysis using CodeQL. Finds complex multi-step vulnerabilities. Slow but thorough.', 'parameters': {'path': 'string — path to codebase', 'language': "string — 'python','javascript','java','cpp','csharp','go','ruby' or 'auto'", 'timeout': 'integer — max seconds (default 600)'}, 'agents': ['code_sast', 'code_orchestrator'], 'module': 'runners.code.codeql_runner', 'function': 'run_codeql', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_flawfinder': {'name': 'run_flawfinder', 'description': 'C/C++ SAST. Detects buffer overflows, format string bugs, unsafe functions like strcpy, gets, sprintf.', 'parameters': {'path': 'string — path to C/C++ source', 'min_level': 'integer — minimum risk level 0-5 (default 1)'}, 'agents': ['code_sast', 'code_orchestrator'], 'module': 'runners.code.flawfinder_runner', 'function': 'run_flawfinder', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_sonarqube': {'name': 'run_sonarqube', 'description': 'Enterprise SAST via SonarQube server. Most comprehensive coverage across all languages.', 'parameters': {'path': 'string — path to codebase', 'project_key': 'string — SonarQube project key (default: code-scan)', 'sonar_host': 'string — SonarQube URL (default: http://localhost:9000)', 'sonar_token': 'string — auth token (uses SONAR_TOKEN env var if empty)'}, 'agents': ['code_sast', 'code_orchestrator'], 'module': 'runners.code.sonarqube_runner', 'function': 'run_sonarqube', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_afl': {'name': 'run_afl', 'description': 'AFL++ coverage-guided fuzzer for C/C++ compiled binaries. Finds crashes and memory errors.', 'parameters': {'binary_path': 'string — path to AFL-instrumented or QEMU binary', 'corpus_dir': 'string — seed corpus directory (auto-created if empty)', 'timeout_seconds': 'integer — fuzz duration (default 300)', 'qemu_mode': 'boolean — use QEMU for non-instrumented binaries (default false)'}, 'agents': ['code_fuzzer', 'code_orchestrator'], 'module': 'runners.code.afl_runner', 'function': 'run_afl', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_atheris': {'name': 'run_atheris', 'description': 'Google Atheris Python fuzzer (libFuzzer-based). Finds crashes and exceptions in Python code.', 'parameters': {'target_module': 'string — path to Python module to fuzz', 'target_function': "string — function name that accepts bytes (default: 'fuzz')", 'timeout_seconds': 'integer — fuzz duration (default 120)'}, 'agents': ['code_fuzzer', 'code_orchestrator'], 'module': 'runners.code.atheris_runner', 'function': 'run_atheris', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_libfuzzer': {'name': 'run_libfuzzer', 'description': 'LLVM libFuzzer for C/C++ targets compiled with -fsanitize=fuzzer. Faster than AFL for instrumented targets.', 'parameters': {'binary_path': 'string — path to libFuzzer-instrumented binary', 'corpus_dir': 'string — seed corpus directory', 'timeout_seconds': 'integer — fuzz duration (default 300)'}, 'agents': ['code_fuzzer', 'code_orchestrator'], 'module': 'runners.code.libfuzzer_runner', 'function': 'run_libfuzzer', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_jazzer': {'name': 'run_jazzer', 'description': 'JVM fuzzer for Java, Kotlin, Scala. Finds exceptions and assertion errors in JVM code.', 'parameters': {'target_class': 'string — fully qualified class name with fuzzerTestOneInput method', 'classpath': 'string — classpath for the target', 'timeout_seconds': 'integer — fuzz duration (default 180)'}, 'agents': ['code_fuzzer', 'code_orchestrator'], 'module': 'runners.code.jazzer_runner', 'function': 'run_jazzer', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_radamsa': {'name': 'run_radamsa', 'description': 'Language-agnostic mutation fuzzer. Works on any program reading stdin. No compilation needed.', 'parameters': {'target_binary': 'string — binary to fuzz', 'seed_inputs': 'list — seed input strings', 'iterations': 'integer — number of mutations (default 1000)'}, 'agents': ['code_fuzzer', 'code_orchestrator'], 'module': 'runners.code.radamsa_runner', 'function': 'run_radamsa', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_zap': {'name': 'run_zap', 'description': 'OWASP ZAP DAST — spiders target then runs active attack scan for SQLi, XSS, IDOR, etc.', 'parameters': {'target_url': 'string — URL to scan', 'ajax_spider': 'boolean — use AJAX spider for JS-heavy apps (default false)', 'timeout_seconds': 'integer — max scan duration (default 300)'}, 'agents': ['code_dast', 'code_orchestrator'], 'module': 'runners.code.owasp_zap_runner', 'function': 'run_zap', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_nikto_dast': {'name': 'run_nikto_dast', 'description': 'Nikto DAST web server scanner for dynamic analysis of running application.', 'parameters': {'target_url': 'string — URL to scan', 'port': 'integer — port (default 80)'}, 'agents': ['code_dast', 'code_orchestrator'], 'module': 'runners.code.nikto_dast_runner', 'function': 'run_nikto_dast', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_burp': {'name': 'run_burp', 'description': 'Optional Burp external integration via REST API. Requires BURP_API_URL and BURP_API_KEY configuration.', 'parameters': {'target_url': 'string — URL to scan', 'api_key': 'string — Burp API key (uses BURP_API_KEY env var if empty)', 'timeout': 'integer — max seconds (default 300)'}, 'agents': ['code_dast', 'code_orchestrator'], 'module': 'runners.code.burp_runner', 'function': 'run_burp', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_trufflehog': {'name': 'run_trufflehog', 'description': 'Scan git history and files for hardcoded secrets — API keys, tokens, private keys.', 'parameters': {'path': 'string — path to codebase', 'only_verified': 'boolean — only report verified secrets (default false)'}, 'agents': ['code_secrets', 'code_orchestrator'], 'module': 'runners.code.trufflehog_runner', 'function': 'run_trufflehog', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_gitleaks': {'name': 'run_gitleaks', 'description': 'Scan git history for secrets. Reports commit hash, author, date for each finding.', 'parameters': {'path': 'string — path to git repository'}, 'agents': ['code_secrets', 'code_orchestrator'], 'module': 'runners.code.gitleaks_runner', 'function': 'run_gitleaks', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_detect_secrets': {'name': 'run_detect_secrets', 'description': 'Scan current file contents for secrets using detect-secrets library.', 'parameters': {'path': 'string — path to codebase'}, 'agents': ['code_secrets', 'code_orchestrator'], 'module': 'runners.code.detect_secrets_runner', 'function': 'run_detect_secrets', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_pip_audit': {'name': 'run_pip_audit', 'description': 'Audit Python dependencies (requirements.txt / pyproject.toml) against NIST NVD.', 'parameters': {'path': 'string — path to Python project root'}, 'agents': ['code_dependency', 'code_orchestrator'], 'module': 'runners.code.pip_audit_runner', 'function': 'run_pip_audit', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_npm_audit': {'name': 'run_npm_audit', 'description': 'Audit Node.js dependencies (package.json) against npm advisory database.', 'parameters': {'path': 'string — path to Node.js project root'}, 'agents': ['code_dependency', 'code_orchestrator'], 'module': 'runners.code.npm_audit_runner', 'function': 'run_npm_audit', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_safety': {'name': 'run_safety', 'description': 'Check Python packages against Safety DB for known CVEs. Complements pip-audit.', 'parameters': {'path': 'string — path to Python project with requirements.txt'}, 'agents': ['code_dependency', 'code_orchestrator'], 'module': 'runners.code.safety_runner', 'function': 'run_safety', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_snyk': {'name': 'run_snyk', 'description': 'Multi-language dependency audit via Snyk. Covers Python, Node, Java, Go, Ruby, PHP.', 'parameters': {'path': 'string — path to project root'}, 'agents': ['code_dependency', 'code_orchestrator'], 'module': 'runners.code.snyk_runner', 'function': 'run_snyk', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'run_retirejs': {'name': 'run_retirejs', 'description': 'Detect vulnerable JavaScript libraries in client-side code.', 'parameters': {'path': 'string — path to JavaScript project'}, 'agents': ['code_dependency', 'code_orchestrator'], 'module': 'runners.code.retire_js_runner', 'function': 'run_retirejs', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'analyze_git_log': {'name': 'analyze_git_log', 'description': 'Scan git commit messages for sensitive keywords suggesting secrets were added/removed.', 'parameters': {'path': 'string — path to git repository'}, 'agents': ['code_secrets', 'code_orchestrator'], 'module': 'runners.code.git_log_analyzer', 'function': 'analyze_git_log', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'generate_patch': {'name': 'generate_patch', 'description': 'Generate a unified diff patch to fix a confirmed vulnerability in source code.', 'parameters': {'file_path': 'string — path to vulnerable file', 'vulnerability_type': "string — type e.g. 'SQL Injection', 'XSS', 'Hardcoded Secret'", 'line_number': 'integer — line number of the vulnerability', 'code_snippet': 'string — the vulnerable code snippet', 'language': "string — 'python','javascript','java','c/c++', etc."}, 'agents': ['code_patch', 'code_orchestrator'], 'module': 'runners.code.patch_generator', 'function': 'generate_patch', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'apply_patch': {'name': 'apply_patch', 'description': 'Apply a unified diff patch to fix a vulnerability. Creates backup before patching.', 'parameters': {'file_path': 'string — path to file to patch', 'patch_content': 'string — unified diff string from generate_patch', 'backup': 'boolean — create .code-agent_backup before patching (default true)'}, 'agents': ['code_patch', 'code_orchestrator'], 'module': 'runners.code.patch_applier', 'function': 'apply_patch', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}, 'manage_sandbox': {'name': 'manage_sandbox', 'description': 'Manage Docker sandbox lifecycle — create, mount, start_app, collect, destroy.', 'parameters': {'action': "string — 'create','mount','start_app','collect','destroy'", 'sandbox_id': 'string — unique sandbox identifier (use task_id)', 'path': 'string — codebase path to mount (for mount action)', 'port': 'integer — app port inside container (for start_app, default 8888)', 'readonly': 'boolean — mount read-only (default true, set false for patching)'}, 'agents': ['code_sandbox', 'code_orchestrator'], 'module': 'runners.code.sandbox_manager', 'function': 'manage_sandbox', 'enabled': True, 'source': 'builtin', 'version': '1.0.0'}}


def get_tool_function(tool_name: str) -> Callable:
    if tool_name not in TOOL_REGISTRY:
        raise KeyError(f"Tool '{tool_name}' not in registry")
    tool = TOOL_REGISTRY[tool_name]
    module = importlib.import_module(tool["module"])
    return getattr(module, tool["function"])

def toggle_tool(tool_name: str, enabled: bool) -> bool:
    if tool_name not in TOOL_REGISTRY:
        return False
    TOOL_REGISTRY[tool_name]["enabled"] = enabled
    return True

def list_all_tools() -> list[dict]:
    result = []
    for tool in TOOL_REGISTRY.values():
        entry = dict(tool)
        entry["available"] = _check_binary_available(tool)
        result.append(entry)
    return result

def get_tool_info(tool_name: str) -> Optional[dict]:
    return TOOL_REGISTRY.get(tool_name)

def validate_registry() -> dict[str, str]:
    results = {}
    for name, tool in TOOL_REGISTRY.items():
        try:
            mod = importlib.import_module(tool["module"])
            fn = getattr(mod, tool["function"], None)
            results[name] = "OK" if fn else f"MISSING FUNCTION: {tool['function']}"
        except Exception as e:
            results[name] = f"ERROR: {e}"
    return results

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

def _which_with_python_scripts(binary: Optional[str]) -> Optional[str]:
    if not binary:
        return None
    path = shutil.which(binary)
    if path:
        return path
    for scripts_dir in _get_python_scripts_dirs():
        for ext in ["", ".exe", ".cmd"]:
            candidate = os.path.join(scripts_dir, binary + ext)
            if os.path.isfile(candidate):
                return candidate
    return None

def _check_binary_available(tool: dict) -> bool:
    python_only = {
        "generate_report",
        "lookup_cve",
        "check_headers",
        "check_ssl",
        "scan_endpoint",
        "generate_patch",
        "apply_patch",
        "manage_sandbox",
        "run_bandit",
        "run_pip_audit",
        "run_npm_audit",
        "run_safety",
        "run_detect_secrets",
        "analyze_git_log",
    }
    if tool["name"] in python_only:
        return True

    binary_map = {
        "run_semgrep": "semgrep",
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
        "run_snyk": "snyk",
        "run_retirejs": "retire",
    }
    binary = binary_map.get(tool["name"])
    return _which_with_python_scripts(binary) is not None if binary else True

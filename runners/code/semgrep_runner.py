"""
AI_KAVACH — Semgrep Runner
========================
run_semgrep(): Multi-language SAST using semgrep rules.
Covers Python, JS/TS, Java, Go, Ruby, PHP, C#, C/C++, Rust.

Author: AI_KAVACH Team (— Harshal)
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("ai_kavach.code_tools.semgrep")


KALI_WORKER_URL = os.getenv(
    "AI_KAVACH_KALI_WORKER_URL",
    "http://127.0.0.1:8082",
).rstrip("/")


RULESETS = [
    "p/owasp-top-ten",
    "p/security-audit",
    "p/secrets",
    "p/python",
    "p/javascript",
    "p/java",
    "p/golang",
    "p/php",
]

SEVERITY_MAP = {
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": "medium",
}


def _to_kali_shared_path(path: str) -> str:
    """
    Convert a Windows path under the local AI_KAVACH project root into
    the Kali shared-folder mount path.

    Local (Windows): C:/.../AI_KAVACH/...
    Kali mount:      /mnt/hgfs/AI_Kavach_CodeAgent/...
    """
    if not path:
        return path

    if path.startswith(f"/mnt/hgfs/{os.getenv("AI_KAVACH_SHARED_ROOT", "AI_Kavach_CodeAgent")}"):
        return path

    ai_kavach_root = os.path.abspath(str(Path(__file__).resolve().parents[2]))
    input_abs = os.path.abspath(path)

    try:
        common = os.path.commonpath(
            [os.path.normcase(ai_kavach_root), os.path.normcase(input_abs)]
        )
    except ValueError:
        return path.replace("\\", "/")

    if common == os.path.normcase(ai_kavach_root):
        relative = os.path.relpath(input_abs, ai_kavach_root)
        relative_posix = Path(relative).as_posix()
        if relative_posix == ".":
            return f"/mnt/hgfs/{os.getenv("AI_KAVACH_SHARED_ROOT", "AI_Kavach_CodeAgent")}"
        return f"/mnt/hgfs/AI_Kavach_CodeAgent/{relative_posix}"

    return path.replace("\\", "/")


def _is_python_target(path: str) -> bool:
    p = Path(path)
    if p.is_file():
        return p.suffix.lower() == ".py"
    if p.is_dir():
        try:
            for _ in p.rglob("*.py"):
                return True
        except Exception:
            return False
    return False


def _normalize_rulesets(rulesets: Optional[list]) -> list[str]:
    """Return only verified/safe semgrep config identifiers."""
    source = rulesets or RULESETS
    valid = []

    aliases = {
        "owasp-top-ten": "p/owasp-top-ten",
        "security-audit": "p/security-audit",
        "secrets": "p/secrets",
        "python": "p/python",
        "python-security": "p/python",
        "all": "auto",
        "auto": "auto",
    }

    for item in source:
        if not isinstance(item, str):
            continue
        token = item.strip()
        if not token:
            continue

        lowered = token.lower()
        if lowered in aliases:
            cfg = aliases[lowered]
        elif token.startswith("p/"):
            cfg = token
        else:
            
            continue

        if cfg not in valid:
            valid.append(cfg)

    return valid


def _remote_execute_semgrep(
    args: list[str], timeout: int
) -> tuple[Optional[dict], Optional[dict]]:
    """
    Execute Semgrep on Kali worker.

    Returns:
        (worker_result_dict, error_result_dict)
    """
    try:
        with httpx.Client(timeout=timeout + 30) as client:
            response = client.post(
                f"{KALI_WORKER_URL}/execute",
                json={
                    "tool": "semgrep",
                    "args": args,
                },
            )

        if response.status_code != 200:
            return None, {
                "status": "error",
                "message": f"Kali worker HTTP {response.status_code}: {response.text[:500]}",
                "findings": [],
            }

        try:
            worker_result = response.json()
        except Exception:
            return None, {
                "status": "error",
                "message": f"Kali worker returned non-JSON response: {response.text[:500]}",
                "findings": [],
            }

        if not isinstance(worker_result, dict):
            return None, {
                "status": "error",
                "message": "Kali worker returned invalid response format",
                "findings": [],
            }

        if not worker_result.get("success", False):
            stderr = worker_result.get("stderr", "")
            stdout = worker_result.get("stdout", "")
            err = (
                worker_result.get("error")
                or stderr
                or stdout
                or "Remote semgrep execution failed"
            )
            return None, {
                "status": "error",
                "message": str(err)[:1000],
                "findings": [],
            }

        
        returncode = worker_result.get("returncode")
        if isinstance(returncode, int) and returncode != 0:
            stderr = worker_result.get("stderr", "")
            stdout = worker_result.get("stdout", "")
            return None, {
                "status": "error",
                "message": f"Remote semgrep failed (returncode {returncode}): {(stderr or stdout)[:1000]}",
                "findings": [],
            }

        return worker_result, None

    except httpx.TimeoutException:
        return None, {
            "status": "timeout",
            "message": f"semgrep timed out after {timeout}s",
            "findings": [],
        }
    except httpx.RequestError as e:
        return None, {
            "status": "error",
            "message": f"Kali worker unreachable: {e}",
            "findings": [],
        }


def _parse_semgrep_json(worker_result: dict) -> tuple[Optional[dict], Optional[dict]]:
    stdout = worker_result.get("stdout") or ""
    stderr = worker_result.get("stderr") or ""

    raw = stdout or stderr
    if not raw.strip():
        return None, {
            "status": "error",
            "message": "semgrep output empty from Kali worker",
            "findings": [],
        }

    try:
        return json.loads(raw), None
    except json.JSONDecodeError:
        extra = f" | stderr: {stderr[:300]}" if stderr else ""
        return None, {
            "status": "error",
            "message": f"semgrep output not JSON: {raw[:300]}{extra}",
            "findings": [],
        }


def run_semgrep(
    path: str,
    rulesets: Optional[list] = None,
    timeout: int = 300,
    max_findings: int = 200,
) -> dict:
    """
    Run semgrep static analysis on a codebase via Kali remote worker.

    Args:
        path:         Path to codebase directory or single file.
        rulesets:     List of semgrep ruleset strings. Defaults to RULESETS.
        timeout:      Max seconds to run (default 300).
        max_findings: Cap findings returned (default 200).

    Returns:
        Normalized findings dict.
    """
    if not Path(path).exists():
        return {"status": "error", "message": f"Path not found: {path}", "findings": []}

    kali_path = _to_kali_shared_path(path)
    normalized_rulesets = _normalize_rulesets(rulesets)

    logger.info(f"Semgrep remote execution → Kali {KALI_WORKER_URL}")
    logger.info(f"Windows path → Kali path | {path} -> {kali_path}")

    
    primary_args = [
        "scan",
        "--json",
        "--quiet",
        "--timeout",
        str(timeout),
        "--max-memory",
        "2048",
        "--config",
        "auto",
        kali_path,
    ]

    primary_worker_result, primary_error = _remote_execute_semgrep(
        primary_args, timeout
    )
    if primary_error:
        return primary_error

    primary_data, primary_parse_error = _parse_semgrep_json(primary_worker_result)
    if primary_parse_error:
        return primary_parse_error

    combined_results = list(primary_data.get("results", []))

    
    if _is_python_target(path):
        should_run_python_pack = (
            not normalized_rulesets
            or "p/python" in normalized_rulesets
            or "auto" in normalized_rulesets
        )

        if should_run_python_pack:
            secondary_args = [
                "scan",
                "--json",
                "--quiet",
                "--timeout",
                str(timeout),
                "--max-memory",
                "2048",
                "--config",
                "p/python",
                kali_path,
            ]
            secondary_worker_result, secondary_error = _remote_execute_semgrep(
                secondary_args, timeout
            )
            if secondary_error:
                logger.warning(
                    f"Optional secondary semgrep scan (p/python) failed: {secondary_error.get('message')}"
                )
            else:
                secondary_data, secondary_parse_error = _parse_semgrep_json(
                    secondary_worker_result
                )
                if secondary_parse_error:
                    logger.warning(
                        f"Optional secondary semgrep JSON parse failed: {secondary_parse_error.get('message')}"
                    )
                else:
                    combined_results.extend(secondary_data.get("results", []))

    
    dedup = {}
    for r in combined_results:
        fp = r.get("extra", {}).get("fingerprint")
        if fp:
            key = f"fp:{fp}"
        else:
            key = (
                r.get("check_id", ""),
                r.get("path", ""),
                r.get("start", {}).get("line", 0),
                r.get("end", {}).get("line", 0),
                r.get("extra", {}).get("message", ""),
            )
        dedup[key] = r

    results = list(dedup.values())
    findings = []

    for r in results[:max_findings]:
        meta = r.get("extra", {})
        finding = {
            "type": _classify_finding(r.get("check_id", "")),
            "rule_id": r.get("check_id", ""),
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "end_line": r.get("end", {}).get("line", 0),
            "severity": SEVERITY_MAP.get(meta.get("severity", "INFO"), "medium"),
            "message": meta.get("message", ""),
            "code": meta.get("lines", ""),
            "cwe": _extract_cwe(meta),
            "owasp": _extract_owasp(meta),
            "fix": meta.get("fix", ""),
            "fingerprint": r.get("extra", {}).get("fingerprint", ""),
        }
        findings.append(finding)

    by_severity = _count_by_severity(findings)

    logger.info(f"Remote Semgrep completed | Findings parsed: {len(findings)}")

    return {
        "status": "success",
        "tool": "semgrep",
        "path": path,
        "rulesets": rulesets or RULESETS,
        "findings": findings,
        "total": len(findings),
        "by_severity": by_severity,
        "summary": (
            f"semgrep found {len(findings)} issues in {path} | "
            f"critical:{by_severity.get('critical', 0)} "
            f"high:{by_severity.get('high', 0)} "
            f"medium:{by_severity.get('medium', 0)}"
        ),
    }


def _classify_finding(rule_id: str) -> str:
    rule = rule_id.lower()
    if any(x in rule for x in ["sqli", "sql-injection", "injection"]):
        return "SQL Injection"
    if any(x in rule for x in ["xss", "cross-site"]):
        return "XSS"
    if any(x in rule for x in ["secret", "hardcoded", "password", "token", "key"]):
        return "Hardcoded Secret"
    if any(x in rule for x in ["path-traversal", "traversal", "lfi"]):
        return "Path Traversal"
    if any(x in rule for x in ["command", "exec", "shell", "injection"]):
        return "Command Injection"
    if any(x in rule for x in ["ssrf", "request-forgery"]):
        return "SSRF"
    if any(x in rule for x in ["xxe", "xml"]):
        return "XXE"
    if any(x in rule for x in ["deserial", "pickle", "marshal"]):
        return "Insecure Deserialization"
    if any(x in rule for x in ["crypto", "weak-cipher", "md5", "sha1"]):
        return "Weak Cryptography"
    if any(x in rule for x in ["auth", "authn", "authz"]):
        return "Authentication Issue"
    return "Security Misconfiguration"


def _extract_cwe(meta: dict) -> str:
    metadata = meta.get("metadata", {})
    cwe = metadata.get("cwe", "")
    if isinstance(cwe, list):
        return cwe[0] if cwe else ""
    return str(cwe)


def _extract_owasp(meta: dict) -> str:
    metadata = meta.get("metadata", {})
    owasp = metadata.get("owasp", "")
    if isinstance(owasp, list):
        return owasp[0] if owasp else ""
    return str(owasp)


def _count_by_severity(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts

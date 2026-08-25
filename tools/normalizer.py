"""
AI_KAVACH — Tool Output Normalizer ()
=======================================
Converts raw output from every tool into a standard schema before
the agent sees it or it gets logged.

Without normalization, each tool returns a different structure:
    - nuclei returns a list of JSON findings
    - nikto returns plain text with OSVDB references
    - ffuf returns a list of matched paths
    - check_headers returns its own dict format
    - read_log_file returns a plain text string

With normalization, every tool returns the same schema:
    {
        "tool":        tool name string
        "status":      "success" | "error" | "timeout" | "not_installed"
        "data":        tool-specific structured dict (see per-tool sections)
        "summary":     one-line plain English for the agent to read
        "raw":         raw output truncated to MAX_RAW_CHARS
        "duration_ms": how long the call took
    }

local LLM reads the normalized output. The raw field is for audit logging.
The data field is what the agent uses to reason about findings.

Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json
import logging
import re
from typing import Any

logger = logging.getLogger("ai_kavach.normalizer")



MAX_RAW_CHARS = 4000



MAX_LIST_ITEMS = 50






def normalize_output(tool_name: str, raw_output: Any, duration_ms: int = 0) -> dict:
    """
    Normalize raw tool output into the standard AI_KAVACH schema.

    Dispatches to a tool-specific normalizer function.
    Falls back to _normalize_generic() for any tool not explicitly handled.

    Args:
        tool_name:   Tool name from TOOL_REGISTRY.
        raw_output:  Whatever the tool function returned.
        duration_ms: How long the tool call took.

    Returns:
        Normalized dict with keys: tool, status, data, summary, raw, duration_ms
    """
    normalizers = {
        "read_log_file":          _normalize_log_reader,
        "check_sqli_patterns":    _normalize_pattern_scanner,
        "lookup_cve":             _normalize_cve_lookup,
        "run_nuclei":             _normalize_nuclei,
        "run_nikto":              _normalize_nikto,
        "run_ffuf":               _normalize_ffuf,
        "check_headers":          _normalize_header_checker,
        "check_ssl":              _normalize_ssl_checker,
        "scan_endpoint":          _normalize_endpoint_scanner,
        "generate_defense_rules": _normalize_defense_rules,
        "generate_ids_signatures":_normalize_ids_signatures,
        "generate_waf_policy":    _normalize_waf_policy,
        "validate_defenses":      _normalize_defense_validator,
    }

    fn = normalizers.get(tool_name, _normalize_generic)

    try:
        result = fn(raw_output)
    except Exception as e:
        logger.error(f"normalizer: failed for '{tool_name}': {e}")
        result = {
            "status": "error",
            "data": {},
            "summary": f"Normalization failed: {e}",
        }

    
    result["tool"] = tool_name
    result["duration_ms"] = duration_ms

    
    if "raw" not in result:
        result["raw"] = _to_raw_string(raw_output)

    return result






def _normalize_log_reader(raw: Any) -> dict:
    """
    Normalize read_log_file output.

    read_log_file returns a string: metadata header + log content.
    We split them and structure the result.
    """
    if isinstance(raw, dict):
        
        status = "error" if raw.get("error") else "success"
        return {
            "status": status,
            "data": raw,
            "summary": raw.get("error") or raw.get("summary", "Log file read"),
            "raw": _to_raw_string(raw),
        }

    if not isinstance(raw, str):
        return _error_result(f"Expected string from read_log_file, got {type(raw).__name__}")

    if not raw.strip():
        return _error_result("read_log_file returned empty content")

    
    lower = raw.lower()
    if "not found" in lower or "no such file" in lower or "does not exist" in lower:
        return {
            "status": "error",
            "data": {"error": raw.strip()},
            "summary": raw.strip()[:200],
            "raw": raw[:MAX_RAW_CHARS],
        }

    
    lines = raw.split("\n")
    line_count = len(lines)

    return {
        "status": "success",
        "data": {
            "content": raw,
            "line_count": line_count,
            "preview": "\n".join(lines[:5]),
        },
        "summary": f"Read {line_count} lines from log file",
        "raw": raw[:MAX_RAW_CHARS],
    }


def _normalize_pattern_scanner(raw: Any) -> dict:
    """
    Normalize check_sqli_patterns output.

    pattern_scanner returns a structured dict with categories,
    matched_lines, attacker_ips, and analyst_guidance.
    """
    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from check_sqli_patterns, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {
            "status": "error",
            "data": raw,
            "summary": str(error)[:200],
            "raw": _to_raw_string(raw),
        }

    total = raw.get("total_matches", 0)
    categories = raw.get("categories", {})
    attacker_ips = raw.get("attacker_ips", {})
    matched_lines = raw.get("matched_lines", [])[:MAX_LIST_ITEMS]
    guidance = raw.get("analyst_guidance", "")

    
    if total == 0:
        summary = "No attack patterns detected in log content"
    else:
        top_cats = sorted(categories.items(), key=lambda x: x[1].get("count", 0), reverse=True)
        cat_str = ", ".join(f"{k}({v.get('count',0)})" for k, v in top_cats[:3])
        summary = (
            f"{total} pattern matches found | "
            f"Top categories: {cat_str} | "
            f"Attacker IPs: {list(attacker_ips.keys())[:5]}"
        )

    return {
        "status": "success",
        "data": {
            "total_matches": total,
            "categories": categories,
            "attacker_ips": attacker_ips,
            "matched_lines": matched_lines,
            "analyst_guidance": guidance,
        },
        "summary": summary,
        "raw": _to_raw_string(raw),
    }


def _normalize_cve_lookup(raw: Any) -> dict:
    """
    Normalize lookup_cve output.

    cve_lookup returns a structured dict with CVE details.
    Handles both exact lookup and keyword search results.
    """
    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from lookup_cve, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {
            "status": "error",
            "data": raw,
            "summary": str(error)[:200],
            "raw": _to_raw_string(raw),
        }

    cve_id = raw.get("cve_id", "")
    severity = raw.get("cvss_severity", "UNKNOWN")
    score = raw.get("cvss_score", 0.0)
    description = raw.get("description", "")[:300]
    exploit = raw.get("exploit_available", False)

    if not cve_id:
        summary = "CVE lookup returned no results"
    else:
        summary = (
            f"{cve_id} | Severity: {severity} | CVSS: {score} | "
            f"Exploit available: {exploit}"
        )

    return {
        "status": "success",
        "data": raw,
        "summary": summary,
        "raw": _to_raw_string(raw),
    }






def _normalize_nuclei(raw: Any) -> dict:
    """
    Normalize run_nuclei output.

    nuclei_runner returns a dict with a "findings" list.
    Each finding has: template-id, severity, matched-at, cve, description.
    """
    if isinstance(raw, dict) and raw.get("status") == "not_installed":
        return {
            "status": "not_installed",
            "data": {},
            "summary": raw.get("message", "nuclei is not installed on "),
            "raw": _to_raw_string(raw),
        }

    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from run_nuclei, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {
            "status": "error",
            "data": raw,
            "summary": str(error)[:200],
            "raw": _to_raw_string(raw),
        }

    findings = raw.get("findings", [])[:MAX_LIST_ITEMS]

    
    by_severity: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

    if not findings:
        summary = f"Nuclei found no vulnerabilities on {raw.get('target', 'target')}"
    else:
        sev_str = ", ".join(f"{k}:{v}" for k, v in sorted(by_severity.items()))
        summary = (
            f"Nuclei found {len(findings)} issues on {raw.get('target', 'target')} | "
            f"Severity breakdown: {sev_str}"
        )

    return {
        "status": "success",
        "data": {
            "target": raw.get("target", ""),
            "templates": raw.get("templates", ""),
            "findings": findings,
            "finding_count": len(findings),
            "by_severity": by_severity,
        },
        "summary": summary,
        "raw": _to_raw_string(raw),
    }


def _normalize_nikto(raw: Any) -> dict:
    """
    Normalize run_nikto output.

    nikto_runner returns a dict with a "findings" list.
    Each finding has: description, osvdb, uri, severity.
    """
    if isinstance(raw, dict) and raw.get("status") == "not_installed":
        return {
            "status": "not_installed",
            "data": {},
            "summary": raw.get("message", "nikto is not installed on "),
            "raw": _to_raw_string(raw),
        }

    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from run_nikto, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {
            "status": "error",
            "data": raw,
            "summary": str(error)[:200],
            "raw": _to_raw_string(raw),
        }

    findings = raw.get("findings", [])[:MAX_LIST_ITEMS]

    if not findings:
        summary = f"Nikto found no issues on {raw.get('target', 'target')}"
    else:
        summary = (
            f"Nikto found {len(findings)} issues on "
            f"{raw.get('target', 'target')}:{raw.get('port', 80)}"
        )

    return {
        "status": "success",
        "data": {
            "target": raw.get("target", ""),
            "port": raw.get("port", 80),
            "findings": findings,
            "finding_count": len(findings),
        },
        "summary": summary,
        "raw": _to_raw_string(raw),
    }


def _normalize_ffuf(raw: Any) -> dict:
    """
    Normalize run_ffuf output.

    ffuf_runner returns a dict with a "hits" list.
    Each hit has: path, status_code, content_length.
    404s are already filtered by the tool.
    """
    if isinstance(raw, dict) and raw.get("status") == "not_installed":
        return {
            "status": "not_installed",
            "data": {},
            "summary": raw.get("message", "ffuf is not installed on "),
            "raw": _to_raw_string(raw),
        }

    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from run_ffuf, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {
            "status": "error",
            "data": raw,
            "summary": str(error)[:200],
            "raw": _to_raw_string(raw),
        }

    hits = raw.get("hits", [])[:MAX_LIST_ITEMS]

    
    by_status: dict[str, int] = {}
    for h in hits:
        code = str(h.get("status_code", "unknown"))
        by_status[code] = by_status.get(code, 0) + 1

    if not hits:
        summary = f"ffuf found no accessible paths on {raw.get('target', 'target')}"
    else:
        interesting = [h["path"] for h in hits if h.get("status_code") in (200, 403, 500)][:5]
        summary = (
            f"ffuf discovered {len(hits)} paths | "
            f"Status breakdown: {by_status} | "
            f"Notable: {interesting}"
        )

    return {
        "status": "success",
        "data": {
            "target": raw.get("target", ""),
            "hits": hits,
            "hit_count": len(hits),
            "by_status_code": by_status,
        },
        "summary": summary,
        "raw": _to_raw_string(raw),
    }


def _normalize_header_checker(raw: Any) -> dict:
    """
    Normalize check_headers output.

    header_checker returns a structured dict.
    Always available — no binary needed.
    """
    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from check_headers, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {
            "status": "error",
            "data": raw,
            "summary": str(error)[:200],
            "raw": _to_raw_string(raw),
        }

    missing = raw.get("missing_security_headers", [])
    disclosure = raw.get("information_disclosure", [])
    score = raw.get("security_score", 0)
    max_score = raw.get("max_score", 10)
    cors = raw.get("cors_misconfiguration", False)

    issues = []
    if missing:
        issues.append(f"{len(missing)} missing headers")
    if disclosure:
        issues.append(f"{len(disclosure)} info disclosure headers")
    if cors:
        issues.append("CORS misconfiguration")

    summary = (
        f"Security score {score}/{max_score} | "
        f"{', '.join(issues) if issues else 'No issues found'}"
    )

    return {
        "status": "success",
        "data": raw,
        "summary": summary,
        "raw": _to_raw_string(raw),
    }


def _normalize_ssl_checker(raw: Any) -> dict:
    """
    Normalize check_ssl output.

    ssl_checker returns a structured dict.
    Always available — uses Python stdlib only.
    """
    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from check_ssl, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {
            "status": "error",
            "data": raw,
            "summary": str(error)[:200],
            "raw": _to_raw_string(raw),
        }

    issues = raw.get("issues", [])
    cert_valid = raw.get("certificate_valid", True)
    days_remaining = raw.get("days_until_expiry", None)
    tls_versions = raw.get("tls_versions_supported", [])

    weak_tls = [v for v in tls_versions if v in ("TLSv1.0", "TLSv1.1", "SSLv3")]

    parts = []
    if issues:
        parts.append(f"{len(issues)} issues found")
    if not cert_valid:
        parts.append("invalid certificate")
    if weak_tls:
        parts.append(f"weak TLS: {weak_tls}")
    if days_remaining is not None and days_remaining < 30:
        parts.append(f"certificate expires in {days_remaining} days")

    summary = (
        f"SSL check: {', '.join(parts) if parts else 'No issues found'}"
    )

    return {
        "status": "success",
        "data": raw,
        "summary": summary,
        "raw": _to_raw_string(raw),
    }


def _normalize_endpoint_scanner(raw: Any) -> dict:
    """
    Normalize scan_endpoint output.

    endpoint_scanner returns a structured dict with vulnerability findings.
    """
    if isinstance(raw, dict) and raw.get("status") == "not_installed":
        return {
            "status": "not_installed",
            "data": {},
            "summary": raw.get("message", "endpoint scanner dependency not available"),
            "raw": _to_raw_string(raw),
        }

    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from scan_endpoint, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {
            "status": "error",
            "data": raw,
            "summary": str(error)[:200],
            "raw": _to_raw_string(raw),
        }

    findings = raw.get("findings", [])[:MAX_LIST_ITEMS]
    target = raw.get("target", "target")

    if not findings:
        summary = f"No vulnerabilities found at {target}"
    else:
        vuln_types = list({f.get("type", "unknown") for f in findings})
        summary = (
            f"Found {len(findings)} vulnerabilities at {target} | "
            f"Types: {vuln_types[:5]}"
        )

    return {
        "status": "success",
        "data": {
            "target": target,
            "method": raw.get("method", "GET"),
            "findings": findings,
            "finding_count": len(findings),
        },
        "summary": summary,
        "raw": _to_raw_string(raw),
    }






def _normalize_defense_rules(raw: Any) -> dict:
    """Normalize generate_defense_rules output."""
    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from generate_defense_rules, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {"status": "error", "data": raw, "summary": str(error)[:200], "raw": _to_raw_string(raw)}

    rules = raw.get("rules", [])
    summary = f"Generated {len(rules)} firewall rules for {raw.get('target_os', 'unknown OS')}"

    return {
        "status": "success",
        "data": raw,
        "summary": summary,
        "raw": _to_raw_string(raw),
    }


def _normalize_ids_signatures(raw: Any) -> dict:
    """Normalize generate_ids_signatures output."""
    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from generate_ids_signatures, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {"status": "error", "data": raw, "summary": str(error)[:200], "raw": _to_raw_string(raw)}

    signatures = raw.get("signatures", [])
    summary = f"Generated {len(signatures)} Suricata IDS signatures"

    return {
        "status": "success",
        "data": raw,
        "summary": summary,
        "raw": _to_raw_string(raw),
    }


def _normalize_waf_policy(raw: Any) -> dict:
    """Normalize generate_waf_policy output."""
    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from generate_waf_policy, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {"status": "error", "data": raw, "summary": str(error)[:200], "raw": _to_raw_string(raw)}

    waf_rules = raw.get("waf_rules", [])
    nginx = raw.get("nginx_config", "")
    apache = raw.get("apache_config", "")

    parts = [f"{len(waf_rules)} WAF rules"]
    if nginx:
        parts.append("Nginx config")
    if apache:
        parts.append("Apache config")

    summary = f"Generated: {', '.join(parts)}"

    return {
        "status": "success",
        "data": raw,
        "summary": summary,
        "raw": _to_raw_string(raw),
    }






def _normalize_defense_validator(raw: Any) -> dict:
    """Normalize validate_defenses output."""
    if not isinstance(raw, dict):
        return _error_result(
            f"Expected dict from validate_defenses, got {type(raw).__name__}"
        )

    error = raw.get("error")
    if error:
        return {"status": "error", "data": raw, "summary": str(error)[:200], "raw": _to_raw_string(raw)}

    results = raw.get("validation_results", [])
    blocked = [r for r in results if r.get("attack_blocked")]
    failed = [r for r in results if not r.get("attack_blocked")]
    coverage = raw.get("overall_coverage", 0.0)

    summary = (
        f"Defense validation: {len(blocked)}/{len(results)} attacks blocked | "
        f"Coverage: {int(coverage * 100)}%"
    )

    return {
        "status": "success",
        "data": raw,
        "summary": summary,
        "raw": _to_raw_string(raw),
    }






def _normalize_generic(raw: Any) -> dict:
    """
    Fallback normalizer for any tool not explicitly handled above.
    Wraps whatever the tool returned in the standard schema.
    """
    if isinstance(raw, dict):
        error = raw.get("error")
        status = "error" if error else raw.get("status", "success")
        summary = error or raw.get("summary", "Tool completed")
        return {
            "status": status,
            "data": raw,
            "summary": str(summary)[:200],
            "raw": _to_raw_string(raw),
        }

    if isinstance(raw, str):
        status = "error" if "error" in raw.lower()[:50] else "success"
        return {
            "status": status,
            "data": {"output": raw},
            "summary": raw[:200],
            "raw": raw[:MAX_RAW_CHARS],
        }

    return {
        "status": "success",
        "data": {"output": str(raw)},
        "summary": f"Tool returned {type(raw).__name__}",
        "raw": str(raw)[:MAX_RAW_CHARS],
    }






def _error_result(message: str) -> dict:
    """Build a standard error normalized result."""
    return {
        "status": "error",
        "data": {},
        "summary": message,
        "raw": "",
    }


def _to_raw_string(value: Any) -> str:
    """Convert any value to a raw string, capped at MAX_RAW_CHARS."""
    if isinstance(value, str):
        raw = value
    else:
        try:
            raw = json.dumps(value, ensure_ascii=False, indent=2)
        except Exception:
            raw = str(value)

    if len(raw) > MAX_RAW_CHARS:
        return raw[:MAX_RAW_CHARS] + f"\n... [{len(raw) - MAX_RAW_CHARS} chars truncated]"
    return raw
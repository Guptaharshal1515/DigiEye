"""
AI_KAVACH — Tool Executor ()
=============================
Single entry point for all tool calls from any agent.

Every tool call in AI_KAVACH flows through execute_tool() — never directly.
This guarantees:
    - Registry validation before every call
    - Agent permission check (can this agent use the tool?)
    - Type coercions for known local LLM output quirks
    - Output normalization via normalizer.py
    - Audit logging via audit_log.py
    - Clean error handling — no tool exception ever crashes an agent

Call signature used by base_agent.py:
    result = execute_tool(
        tool_name="read_log_file",
        params={"path": "C:/logs/access.log", "lines": 100},
        task_id="code_analysis_001",
        agent_type="code",
    )

Returns a normalized dict always containing at minimum:
    status:  "success" | "error" | "timeout" | "not_installed" | "permission_denied"
    summary: one-line plain English summary
    data:    tool-specific structured output (empty dict on failure)
    error:   error message string or None

Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import logging
import time
from typing import Any, Optional

from tools.registry import TOOL_REGISTRY, get_tool_function, get_tool_info
from tools.normalizer import normalize_output
from tools.audit_log import log_tool_call
from tools.execution_models import normalize_tool_status

logger = logging.getLogger("ai_kavach.executor")





_CONFIRMED_LOG_PATHS: dict[str, str] = {}  






def _coerce_params(tool_name: str, params: dict, task_id: str = "") -> dict:
    """
    Apply type coercions to tool params before calling the function.

    local LLM sometimes sends wrong types despite clear parameter descriptions.
    These coercions are applied silently — the tool never sees bad types.

    Known quirks:
        read_log_file:  lines sent as [121, 144] instead of 121
        lookup_cve:     cve_id sent as "CVE 2021 44228" instead of "CVE-2021-44228"
        check_ssl:      port sent as "443" (string) instead of 443 (int)
        run_ffuf:       wordlist sent as None — substitute auto-detected default
        run_nuclei:     target sent without http:// scheme
        scan_endpoint:  method sent as lowercase "get" instead of "GET"
    """
    p = dict(params)  

    if tool_name == "read_log_file":
        
        if isinstance(p.get("lines"), list):
            raw = p["lines"]
            p["lines"] = int(raw[0]) if raw else 100
            logger.debug(f"executor: coerced lines {raw} → {p['lines']}")

        
        elif isinstance(p.get("lines"), str):
            try:
                p["lines"] = int(p["lines"])
            except ValueError:
                p["lines"] = 100

        
        if not p.get("lines"):
            p["lines"] = 100

        
        if not p.get("path"):
            logger.warning("executor: read_log_file called with no path")

        
        
        
        if task_id and task_id in _CONFIRMED_LOG_PATHS:
            confirmed = _CONFIRMED_LOG_PATHS[task_id]

            if p.get("path") != confirmed:
                logger.warning(
                    f"[{task_id}] Path lock: model sent '{p.get('path')}' "
                    f"but substituting confirmed path '{confirmed}'"
                )
                p["path"] = confirmed

    elif tool_name == "lookup_cve":
        
        cve_id = p.get("cve_id", "")
        if isinstance(cve_id, str):
            cve_id = cve_id.strip().upper()
            cve_id = cve_id.replace(" ", "-").replace("_", "-")
            p["cve_id"] = cve_id

    elif tool_name == "check_ssl":
        
        if isinstance(p.get("port"), str):
            try:
                p["port"] = int(p["port"])
            except ValueError:
                p["port"] = 443
        if not p.get("port"):
            p["port"] = 443

    elif tool_name == "run_ffuf":
        
        if not p.get("wordlist"):
            p["wordlist"] = ""

    elif tool_name == "run_nuclei":
        
        target = p.get("target", "")
        if target and not target.startswith(("http://", "https://")):
            p["target"] = f"http://{target}"

    elif tool_name == "scan_endpoint":
        
        if isinstance(p.get("method"), str):
            p["method"] = p["method"].upper()
        if not p.get("method"):
            p["method"] = "GET"

        
        if isinstance(p.get("params"), list):
            p["params"] = ",".join(str(x) for x in p["params"])

    elif tool_name in (
        "generate_defense_rules",
        "generate_ids_signatures",
        "generate_waf_policy",
        "validate_defenses",
    ):
        
        for list_field in (
            "attack_types",
            "attacker_ips",
            "evidence",
            "waf_rules",
            "ids_rules",
        ):
            if isinstance(p.get(list_field), str):
                p[list_field] = [p[list_field]] if p[list_field] else []

        
        for list_field in ("entry_points", "vulnerabilities"):
            if isinstance(p.get(list_field), str):
                p[list_field] = []

    elif tool_name in ("check_headers",):
        
        target = p.get("target", "")
        if target and not target.startswith(("http://", "https://")):
            p["target"] = f"http://{target}"

    return p


def _register_confirmed_path(task_id: str, path: str) -> None:
    """
    Store a successfully confirmed read_log_file path.

    Once a path succeeds, all subsequent read_log_file calls for the same
    task use that confirmed path.
    """
    if task_id and path:
        _CONFIRMED_LOG_PATHS[task_id] = path
        logger.info(
            f"[{task_id}] Path lock: confirmed working log path '{path}'"
        )


def clear_path_lock(task_id: str) -> None:
    """Clear the confirmed log path when a task completes."""
    if task_id in _CONFIRMED_LOG_PATHS:
        _CONFIRMED_LOG_PATHS.pop(task_id, None)
        logger.debug(f"[{task_id}] Path lock cleared")







def _agent_has_permission(agent_type: str, tool_name: str) -> bool:
    """
    Check whether an agent type is allowed to call a specific tool.

    This is a safety check on top of the registry — prevents a code_defense
    agent from accidentally calling a code_dast active scanner.

    Args:
        agent_type: Agent type string.
        tool_name:  Tool name string.

    Returns:
        True if permitted, False otherwise.
    """
    tool = get_tool_info(tool_name)
    if tool is None:
        return False
    return agent_type in tool.get("agents", [])






def execute_tool(
    tool_name: str,
    params: dict,
    task_id: str,
    agent_type: str,
) -> dict:
    """
    Execute a tool by name with given params.

    This is the only function agents call to run tools.
    Never call tool functions directly from agents.

    Flow:
        1. Validate tool exists in registry and is enabled
        2. Check agent has permission to use this tool
        3. Apply type coercions for known local LLM output quirks
        4. Dynamically import and call the tool function
        5. Normalize the raw output to standard schema
        6. Log the call to audit_log.py
        7. Return normalized result

    Args:
        tool_name:  Name of tool from TOOL_REGISTRY.
        params:     Parameters dict from local LLM action_input.
        task_id:    Current run ID for audit logging.
        agent_type: Which agent is calling (for permission check).

    Returns:
        Normalized result dict with keys:
            tool, status, data, summary, raw, duration_ms
        Never raises — all exceptions return a structured error dict.
    """
    call_start = time.time()

    
    
    
    if tool_name not in TOOL_REGISTRY:
        error_msg = (
            f"Tool '{tool_name}' does not exist in the registry. "
            f"Available tools: {sorted(TOOL_REGISTRY.keys())}"
        )
        logger.warning(f"[{task_id}] executor: {error_msg}")
        return _error_result(tool_name, error_msg, call_start)

    
    
    
    if not TOOL_REGISTRY[tool_name].get("enabled", False):
        error_msg = f"Tool '{tool_name}' is currently disabled."
        logger.info(f"[{task_id}] executor: {error_msg}")
        return _error_result(
            tool_name,
            error_msg,
            call_start,
            status="disabled",
        )

    
    
    
    if not _agent_has_permission(agent_type, tool_name):
        error_msg = (
            f"Tool '{tool_name}' not permitted for agent '{agent_type}'. "
            f"Permitted agents: {TOOL_REGISTRY[tool_name].get('agents', [])}"
        )
        logger.warning(f"[{task_id}] executor: {error_msg}")
        return {
            "tool": tool_name,
            "status": "tool_not_allowed",
            "data": {},
            "summary": (
                f"TOOL NOT AVAILABLE: '{tool_name}' cannot be used by {agent_type}. "
                f"You must only use tools from your available tools list. "
                f"Call final_answer with current findings."
            ),
            "error": f"Tool '{tool_name}' not permitted for agent '{agent_type}'",
            "raw": "",
            "duration_ms": round((time.time() - call_start) * 1000),
        }

    
    
    
    coerced_params = _coerce_params(tool_name, params, task_id)

    logger.info(
        f"[{task_id}] executor: calling '{tool_name}' | "
        f"agent={agent_type} | params={_safe_log_params(coerced_params)}"
    )

    
    
    
    try:
        fn = get_tool_function(tool_name)

    except (KeyError, ModuleNotFoundError, AttributeError) as e:
        error_msg = f"Tool '{tool_name}' could not be loaded: {e}"
        logger.error(f"[{task_id}] executor: {error_msg}")

        result = _error_result(
            tool_name,
            error_msg,
            call_start,
            status="not_installed",
        )

        log_tool_call(
            task_id,
            agent_type,
            tool_name,
            coerced_params,
            result,
            round((time.time() - call_start) * 1000),
        )

        return result

    try:
        raw_output = fn(**coerced_params)

    except FileNotFoundError as e:
        
        error_msg = (
            f"Tool binary not found: {e}. "
            f"Install the required tool first."
        )
        logger.warning(f"[{task_id}] executor: {error_msg}")

        result = _error_result(
            tool_name,
            error_msg,
            call_start,
            status="not_installed",
        )

        log_tool_call(
            task_id,
            agent_type,
            tool_name,
            coerced_params,
            result,
            round((time.time() - call_start) * 1000),
        )

        return result

    except TimeoutError as e:
        error_msg = f"Tool '{tool_name}' timed out: {e}"
        logger.warning(f"[{task_id}] executor: {error_msg}")

        result = _error_result(
            tool_name,
            error_msg,
            call_start,
            status="timeout",
        )

        log_tool_call(
            task_id,
            agent_type,
            tool_name,
            coerced_params,
            result,
            round((time.time() - call_start) * 1000),
        )

        return result

    except PermissionError as e:
        error_msg = f"Permission denied running '{tool_name}': {e}"
        logger.warning(f"[{task_id}] executor: {error_msg}")

        result = _error_result(
            tool_name,
            error_msg,
            call_start,
            status="permission_denied",
        )

        log_tool_call(
            task_id,
            agent_type,
            tool_name,
            coerced_params,
            result,
            round((time.time() - call_start) * 1000),
        )

        return result

    except Exception as e:
        error_msg = f"Tool '{tool_name}' failed: {e}"
        logger.exception(f"[{task_id}] executor: {error_msg}")

        result = _error_result(
            tool_name,
            error_msg,
            call_start,
            status="error",
        )

        log_tool_call(
            task_id,
            agent_type,
            tool_name,
            coerced_params,
            result,
            round((time.time() - call_start) * 1000),
        )

        return result

    
    
    
    duration_ms = round((time.time() - call_start) * 1000)

    try:
        normalized = normalize_output(
            tool_name,
            raw_output,
            duration_ms,
        )

    except Exception as e:
        logger.error(
            f"[{task_id}] executor: normalizer failed for "
            f"'{tool_name}': {e}. "
            f"Returning raw output wrapped in standard schema."
        )

        normalized = {
            "tool": tool_name,
            "status": "success",
            "data": raw_output if isinstance(raw_output, dict) else {},
            "summary": (
                f"Tool completed but output normalization failed: {e}"
            ),
            "raw": str(raw_output)[:4000],
            "duration_ms": duration_ms,
        }

    
    
    
    if (
        tool_name == "read_log_file"
        and normalized.get("status") == "success"
    ):
        _register_confirmed_path(
            task_id,
            coerced_params.get("path", ""),
        )

    
    
    
    log_tool_call(
        task_id,
        agent_type,
        tool_name,
        coerced_params,
        normalized,
        duration_ms,
    )

    logger.info(
        f"[{task_id}] executor: '{tool_name}' completed | "
        f"status={normalized.get('status')} | {duration_ms}ms"
    )

    normalized["status"] = normalize_tool_status(normalized.get("status", "error"))
    return normalized






def _error_result(
    tool_name: str,
    error_msg: str,
    call_start: float,
    status: str = "error",
) -> dict:
    """Build a standard error result dict."""
    return {
        "tool": tool_name,
        "status": normalize_tool_status(status),
        "data": {},
        "summary": error_msg,
        "raw": "",
        "duration_ms": round((time.time() - call_start) * 1000),
        "error": error_msg,
    }


def _safe_log_params(params: dict) -> dict:
    """
    Truncate large param values for clean log output.
    Prevents log_content strings from flooding the log file.
    """
    safe = {}

    for k, v in params.items():
        if isinstance(v, str) and len(v) > 200:
            safe[k] = f"[{len(v)} chars]"

        elif isinstance(v, list) and len(v) > 10:
            safe[k] = f"[list of {len(v)} items]"

        else:
            safe[k] = v

    return safe
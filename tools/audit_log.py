"""
AI_KAVACH — Tool Audit Logger ()
==================================
Append-only audit log of every tool call made during any agent run.

Every call to execute_tool() produces one JSONL line in logs/tool_audit.jsonl.
This log is:
    - The source of truth for which tools ran during an investigation
    - Used by agent_server.py GET /v1/runs to show run history
    - Included in Report B as tool usage summary
    - Readable by for fine-tuning signal (which tools helped most)

Log format: one JSON object per line (JSONL), never overwritten, append-only.
Log rotation: when file exceeds MAX_LOG_SIZE_MB it is renamed with a timestamp
and a new file is started — old logs are never deleted automatically.

Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.config import LOG_DIR

logger = logging.getLogger("ai_kavach.audit_log")





AUDIT_LOG_FILENAME = "tool_audit.jsonl"
MAX_LOG_SIZE_MB = 50
_LOCK = threading.Lock()  






def log_tool_call(
    task_id: str,
    agent_type: str,
    tool_name: str,
    params: dict,
    result: dict,
    duration_ms: int,
) -> None:
    """
    Append one tool call record to the audit log.

    Called by executor.py after every tool execution — success or failure.
    Never raises — audit logging failure must never crash an agent run.

    Args:
        task_id:    Current run identifier.
        agent_type: Which agent made this call (e.g. "code").
        tool_name:  Name of the tool called.
        params:     Coerced params passed to the tool (after executor coercions).
        result:     Normalized result dict from normalizer.py.
        duration_ms: How long the tool call took in milliseconds.
    """
    try:
        entry = _build_entry(task_id, agent_type, tool_name, params, result, duration_ms)
        _write_entry(entry)
    except Exception as e:
        
        logger.error(f"audit_log: failed to write entry for '{tool_name}': {e}")


def get_recent_calls(task_id: str, limit: int = 100) -> list[dict]:
    """
    Return all tool call records for a specific task_id.

    Called by agent_server.py and Report B builder to get tool history
    for a specific run.

    Args:
        task_id: The run identifier to filter by.
        limit:   Maximum number of records to return (most recent first).

    Returns:
        List of audit log entry dicts, newest first.
    """
    path = _get_log_path()
    if not path.exists():
        return []

    matches = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("task_id") == task_id:
                        matches.append(entry)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.error(f"audit_log: failed to read log for task {task_id}: {e}")
        return []

    
    return list(reversed(matches))[-limit:]


def get_tool_stats(since_task_id: Optional[str] = None) -> dict:
    """
    Return aggregate statistics across all tool calls in the audit log.

    Used by agent_server.py GET /v1/runs and Report B generation.
    Gives a picture of which tools are called most, which fail most,
    and average durations — useful for fine-tuning signal.

    Args:
        since_task_id: If provided, only count calls from runs after this
                       task_id alphabetically (approximate recency filter).

    Returns:
        dict with per-tool stats:
            call_count, success_count, error_count, timeout_count,
            not_installed_count, avg_duration_ms, total_duration_ms
    """
    path = _get_log_path()
    if not path.exists():
        return {}

    stats: dict[str, dict] = {}
    counting = since_task_id is None

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                
                if since_task_id and entry.get("task_id") == since_task_id:
                    counting = True

                if not counting:
                    continue

                tool = entry.get("tool", "unknown")
                status = entry.get("status", "unknown")
                duration = entry.get("duration_ms", 0)

                if tool not in stats:
                    stats[tool] = {
                        "call_count": 0,
                        "success_count": 0,
                        "error_count": 0,
                        "timeout_count": 0,
                        "not_installed_count": 0,
                        "total_duration_ms": 0,
                    }

                stats[tool]["call_count"] += 1
                stats[tool]["total_duration_ms"] += duration

                if status == "success":
                    stats[tool]["success_count"] += 1
                elif status == "timeout":
                    stats[tool]["timeout_count"] += 1
                elif status == "not_installed":
                    stats[tool]["not_installed_count"] += 1
                else:
                    stats[tool]["error_count"] += 1

    except Exception as e:
        logger.error(f"audit_log: failed to compute stats: {e}")
        return {}

    
    for tool_stats in stats.values():
        count = tool_stats["call_count"]
        total = tool_stats["total_duration_ms"]
        tool_stats["avg_duration_ms"] = round(total / count) if count > 0 else 0

    return stats


def get_run_list(limit: int = 50) -> list[dict]:
    """
    Return a summary list of recent runs from the audit log.

    Called by agent_server.py GET /v1/runs endpoint.
    Groups entries by task_id and returns one summary per run.

    Args:
        limit: Maximum number of unique runs to return (most recent first).

    Returns:
        List of run summary dicts:
            task_id, agent_type, first_tool, last_tool,
            tool_count, success_count, error_count,
            started_at, last_activity, total_duration_ms
    """
    path = _get_log_path()
    if not path.exists():
        return []

    runs: dict[str, dict] = {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                tid = entry.get("task_id", "unknown")
                status = entry.get("status", "unknown")
                ts = entry.get("timestamp", "")
                duration = entry.get("duration_ms", 0)
                tool = entry.get("tool", "unknown")

                if tid not in runs:
                    runs[tid] = {
                        "task_id": tid,
                        "agent_type": entry.get("agent_type", "unknown"),
                        "first_tool": tool,
                        "last_tool": tool,
                        "tool_count": 0,
                        "success_count": 0,
                        "error_count": 0,
                        "started_at": ts,
                        "last_activity": ts,
                        "total_duration_ms": 0,
                    }

                run = runs[tid]
                run["tool_count"] += 1
                run["last_tool"] = tool
                run["last_activity"] = ts
                run["total_duration_ms"] += duration

                if status == "success":
                    run["success_count"] += 1
                else:
                    run["error_count"] += 1

    except Exception as e:
        logger.error(f"audit_log: failed to build run list: {e}")
        return []

    
    sorted_runs = sorted(
        runs.values(),
        key=lambda r: r.get("started_at", ""),
        reverse=True,
    )
    return sorted_runs[:limit]






def _build_entry(
    task_id: str,
    agent_type: str,
    tool_name: str,
    params: dict,
    result: dict,
    duration_ms: int,
) -> dict:
    """Build the audit log entry dict for one tool call."""
    raw_output = result.get("raw", "")
    output_hash = hashlib.sha256(
        raw_output.encode("utf-8", errors="replace")
    ).hexdigest()[:16]  

    return {
        "timestamp": _now(),
        "task_id": task_id,
        "agent_type": agent_type,
        "tool": tool_name,
        "params": _sanitize_params(params),
        "status": result.get("status", "unknown"),
        "summary": result.get("summary", ""),
        "duration_ms": duration_ms,
        "output_hash": f"sha256:{output_hash}",
        "error": result.get("error"),
    }


def _write_entry(entry: dict) -> None:
    """
    Write one entry to the audit log file.
    Thread-safe via module-level lock.
    Rotates log file if it exceeds MAX_LOG_SIZE_MB.
    """
    path = _get_log_path()

    with _LOCK:
        
        if path.exists() and path.stat().st_size > MAX_LOG_SIZE_MB * 1024 * 1024:
            _rotate_log(path)

        
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _rotate_log(path: Path) -> None:
    """
    Rename current log file with timestamp suffix and start fresh.
    Old log files are kept — never deleted automatically.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    rotated_path = path.parent / f"tool_audit_{timestamp}.jsonl"
    try:
        path.rename(rotated_path)
        logger.info(f"audit_log: rotated to {rotated_path}")
    except Exception as e:
        logger.error(f"audit_log: rotation failed: {e}")


def _get_log_path() -> Path:
    """Return the Path object for the active audit log file."""
    return Path(LOG_DIR) / AUDIT_LOG_FILENAME


def _now() -> str:
    """Returns current UTC time as ISO8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _sanitize_params(params: dict) -> dict:
    """
    Truncate large param values before logging.
    Prevents log_content strings from making the JSONL file unreadable.
    """
    sanitized = {}
    for k, v in params.items():
        if k in ("log_content", "content", "raw", "waf_rules", "ids_rules"):
            sanitized[k] = f"[{len(str(v))} chars — omitted from audit log]"
        elif isinstance(v, str) and len(v) > 300:
            sanitized[k] = v[:300] + f"... [{len(v)} chars total]"
        elif isinstance(v, list) and len(v) > 20:
            sanitized[k] = v[:5] + [f"... {len(v) - 5} more items"]
        else:
            sanitized[k] = v
    return sanitized
"""Execution models and shared helpers for tool state handling."""

from __future__ import annotations

from urllib.parse import urlparse

TOOL_STATUSES = {
    "not_requested",
    "not_applicable",
    "unavailable",
    "not_configured",
    "queued",
    "running",
    "success",
    "success_no_findings",
    "error",
    "timeout",
    "tool_not_allowed",
    "tool_missing",
    "skipped",
}


def normalize_tool_status(status: str) -> str:
    s = str(status or "").strip().lower()
    aliases = {
        "ok": "success",
        "non_zero_exit": "error",
        "permission_denied": "tool_not_allowed",
        "not_installed": "tool_missing",
        "disabled": "unavailable",
    }
    s = aliases.get(s, s)
    return s if s in TOOL_STATUSES else "error"


def split_host_port_from_url(url: str) -> tuple[str, int | None]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    if port is None and parsed.scheme == "https":
        port = 443
    elif port is None and parsed.scheme == "http":
        port = 80
    return host, port

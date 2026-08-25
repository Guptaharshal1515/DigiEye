"""Target parsing and path translation helpers."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse

_URL_RE = re.compile(r"https?://[^\s\]\[\"'<>]+", re.IGNORECASE)


def extract_http_targets(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in _URL_RE.findall(text):
        clean = raw.rstrip('.,;:)"]}')
        normalized = normalize_http_url(clean)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def normalize_http_url(url: str) -> str:
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def to_kali_shared_path(path: str, project_root_name: str = "AI_KAVACH") -> str:
    if not path:
        return path
    if str(path).startswith(f"/mnt/hgfs/{project_root_name}"):
        return str(path)

    input_abs = os.path.abspath(str(path))
    root_abs = os.path.abspath(str(Path(__file__).resolve().parents[1]))

    try:
        common = os.path.commonpath([os.path.normcase(root_abs), os.path.normcase(input_abs)])
    except ValueError:
        return str(path).replace("\\", "/")

    if common == os.path.normcase(root_abs):
        rel = os.path.relpath(input_abs, root_abs)
        rel_posix = Path(rel).as_posix()
        return f"/mnt/hgfs/{project_root_name}" if rel_posix == "." else f"/mnt/hgfs/{project_root_name}/{rel_posix}"

    return str(path).replace("\\", "/")

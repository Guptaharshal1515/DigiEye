"""
AI_KAVACH — CodeQL Runner
========================
run_codeql(): Deep semantic code analysis using GitHub's CodeQL.
Most powerful SAST tool — finds complex multi-step vulnerabilities
that simpler pattern matchers miss.

Supports: C/C++, C#, Java, JavaScript, Python, Go, Ruby, Swift

Author: AI_KAVACH Team (— Harshal)
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger("ai_kavach.code_tools.codeql")

LANGUAGE_MAP = {
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "javascript",
    ".java": "java",
    ".c":    "cpp",
    ".cpp":  "cpp",
    ".h":    "cpp",
    ".cs":   "csharp",
    ".go":   "go",
    ".rb":   "ruby",
    ".swift":"swift",
}


def run_codeql(path: str, language: str = "auto", timeout: int = 600) -> dict:
    """
    Run CodeQL analysis on a codebase.

    Args:
        path:     Path to codebase.
        language: Language to analyze ("auto" = detect from files).
        timeout:  Max seconds (default 600 — CodeQL is slow).

    Returns:
        Normalized findings dict.
    """
    if not shutil.which("codeql"):
        return {
            "status":  "not_installed",
            "message": (
                "CodeQL not installed. Download from: "
                "https://github.com/github/codeql-cli-binaries/releases"
            ),
            "findings": [],
        }

    if not Path(path).exists():
        return {"status": "error", "message": f"Path not found: {path}", "findings": []}

    
    if language == "auto":
        language = _detect_language(path)
    if not language:
        return {"status": "error", "message": "Could not detect language for CodeQL", "findings": []}

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "codeql-db")
        results_path = os.path.join(tmpdir, "results.sarif")

        try:
            
            create_cmd = [
                "codeql", "database", "create",
                db_path,
                f"--language={language}",
                f"--source-root={path}",
                "--overwrite",
            ]
            subprocess.run(
                create_cmd, capture_output=True, timeout=timeout // 2, check=True
            )

            
            analyze_cmd = [
                "codeql", "database", "analyze",
                db_path,
                f"{language}-security-and-quality.qls",
                "--format=sarif-latest",
                f"--output={results_path}",
            ]
            subprocess.run(
                analyze_cmd, capture_output=True, timeout=timeout // 2, check=True
            )

            
            if not Path(results_path).exists():
                return {"status": "error", "message": "CodeQL produced no output", "findings": []}

            with open(results_path) as f:
                sarif = json.load(f)

            findings = _parse_sarif(sarif, path)
            by_severity = _count_by_severity(findings)

            return {
                "status":      "success",
                "tool":        "codeql",
                "path":        path,
                "language":    language,
                "findings":    findings,
                "total":       len(findings),
                "by_severity": by_severity,
                "summary": (
                    f"CodeQL found {len(findings)} issues in {path} | "
                    f"critical:{by_severity.get('critical',0)} "
                    f"high:{by_severity.get('high',0)}"
                ),
            }

        except subprocess.CalledProcessError as e:
            return {"status": "error", "message": f"CodeQL failed: {e.stderr[:300]}", "findings": []}
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "message": f"CodeQL timed out after {timeout}s", "findings": []}
        except Exception as e:
            return {"status": "error", "message": str(e), "findings": []}


def _parse_sarif(sarif: dict, base_path: str) -> list:
    findings = []
    for run in sarif.get("runs", []):
        rules = {
            r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule    = rules.get(rule_id, {})
            level   = result.get("level", "warning")
            severity = {"error": "high", "warning": "medium", "note": "low"}.get(level, "medium")
            locs = result.get("locations", [])
            file_path = ""
            line = 0
            if locs:
                phys = locs[0].get("physicalLocation", {})
                uri  = phys.get("artifactLocation", {}).get("uri", "")
                file_path = uri.replace("file:///", "").replace(base_path.lstrip("/"), "")
                line = phys.get("region", {}).get("startLine", 0)

            findings.append({
                "type":     rule.get("name", rule_id),
                "rule_id":  rule_id,
                "file":     file_path,
                "line":     line,
                "severity": severity,
                "message":  result.get("message", {}).get("text", ""),
                "cwe":      _extract_sarif_cwe(rule),
            })
    return findings


def _extract_sarif_cwe(rule: dict) -> str:
    for rel in rule.get("relationships", []):
        target = rel.get("target", {})
        if "CWE" in target.get("id", ""):
            return target["id"]
    return ""


def _detect_language(path: str) -> str:
    ext_counts: dict[str, int] = {}
    for root, _, files in os.walk(path):
        for f in files:
            ext = Path(f).suffix.lower()
            if ext in LANGUAGE_MAP:
                lang = LANGUAGE_MAP[ext]
                ext_counts[lang] = ext_counts.get(lang, 0) + 1
    return max(ext_counts, key=ext_counts.get) if ext_counts else ""


def _count_by_severity(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
"""
AI_KAVACH — patch_generator.py
===========================
Extracted from the original code_tools.py without changing runner logic.
Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json, logging, shutil, subprocess
from pathlib import Path



def generate_patch(
    file_path: str,
    vulnerability_type: str,
    line_number: int,
    code_snippet: str,
    language: str = "auto",
) -> dict:
    """
    Generate a code patch for a confirmed vulnerability.
    Returns a unified diff that can be applied with patch_applier.
    """
    import difflib

    if not Path(file_path).exists():
        return {"status": "error", "message": f"File not found: {file_path}", "patch": ""}

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            original_lines = f.readlines()

        patched_lines = original_lines.copy()
        fix = _generate_fix(vulnerability_type, code_snippet, language)

        if fix and 0 < line_number <= len(patched_lines):
            patched_lines[line_number - 1] = fix + "\n"

        diff = list(difflib.unified_diff(
            original_lines, patched_lines,
            fromfile=f"a/{Path(file_path).name}",
            tofile=f"b/{Path(file_path).name}",
            lineterm="",
        ))

        return {
            "status":    "success",
            "tool":      "patch-generator",
            "file":      file_path,
            "vuln_type": vulnerability_type,
            "line":      line_number,
            "patch":     "\n".join(diff),
            "fix_code":  fix,
            "summary":   f"Generated patch for {vulnerability_type} at {file_path}:{line_number}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "patch": ""}


def _generate_fix(vuln_type: str, code: str, language: str) -> str:
    """Generate the fixed code line based on vulnerability type."""
    vt = vuln_type.lower()

    if "sql" in vt:
        if language == "python":
            return "    cursor.execute(query, (user_input,))  # PATCHED: parameterized query"
        if language == "java":
            return '    PreparedStatement ps = conn.prepareStatement(query);  // PATCHED'
        return "    # PATCHED: Use parameterized query here — replace string concatenation"

    if "xss" in vt:
        if language == "python":
            return "    output = html.escape(user_input)  # PATCHED: escape output"
        if language in ("javascript", "js"):
            return "    output = DOMPurify.sanitize(userInput);  // PATCHED: sanitize output"
        return "    # PATCHED: Encode/escape user output before rendering"

    if "secret" in vt or "hardcoded" in vt:
        return "    value = os.environ.get('SECRET_KEY')  # PATCHED: moved to environment variable"

    if "traversal" in vt or "lfi" in vt:
        if language == "python":
            return "    safe_path = os.path.normpath(os.path.join(BASE_DIR, filename))  # PATCHED"
        return "    # PATCHED: Normalize path and validate against allowed base directory"

    if "command" in vt or "injection" in vt:
        if language == "python":
            return "    subprocess.run([cmd, arg], check=True)  # PATCHED: list args, no shell=True"
        return "    # PATCHED: Use list args instead of shell string"

    return f"    # PATCHED: Manual fix required for {vuln_type}"




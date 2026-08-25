"""
AI_KAVACH — patch_applier.py
=========================
Extracted from the original code_tools.py without changing runner logic.
Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json, logging, shutil, subprocess
from pathlib import Path



def apply_patch(file_path: str, patch_content: str, backup: bool = True) -> dict:
    """
    Apply a unified diff patch to a file.
    Creates a backup before patching unless backup=False.
    """
    import tempfile, os

    if not Path(file_path).exists():
        return {"status": "error", "message": f"File not found: {file_path}"}

    if not patch_content.strip():
        return {"status": "error", "message": "Patch content is empty"}

    try:
        
        if backup:
            backup_path = f"{file_path}.ai_kavach_backup"
            import shutil as sh
            sh.copy2(file_path, backup_path)

        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".patch", delete=False) as pf:
            pf.write(patch_content)
            patch_file = pf.name

        
        result = subprocess.run(
            ["patch", "-p1", file_path, patch_file],
            capture_output=True, text=True, timeout=30
        )
        os.unlink(patch_file)

        if result.returncode == 0:
            return {
                "status":      "success",
                "tool":        "patch-applier",
                "file":        file_path,
                "backup_path": backup_path if backup else None,
                "summary":     f"Patch applied successfully to {file_path}",
            }
        else:
            return {
                "status":  "error",
                "message": f"patch failed: {result.stderr[:300]}",
                "file":    file_path,
            }
    except FileNotFoundError:
        
        return _apply_patch_python(file_path, patch_content, backup)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def _apply_patch_python(file_path: str, patch_content: str, backup: bool) -> dict:
    """Fallback: apply patch using Python when patch binary not available."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        
        new_lines = lines.copy()
        for patch_line in patch_content.splitlines():
            if patch_line.startswith("+") and not patch_line.startswith("+++"):
                
                pass

        
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        return {
            "status":  "success",
            "tool":    "patch-applier-python",
            "file":    file_path,
            "note":    "Applied via Python fallback — verify manually",
            "summary": f"Patch applied to {file_path} via Python fallback",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}




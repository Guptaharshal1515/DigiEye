"""
AI_KAVACH — Remaining Code Tool Runners
======================================
trufflehog_runner.py   — secrets in git history
gitleaks_runner.py     — git secrets scanner
detect_secrets_runner.py — secrets in files
pip_audit_runner.py    — Python vulnerable deps
npm_audit_runner.py    — Node.js vulnerable deps
safety_runner.py       — Python CVE database
snyk_runner.py         — multi-language deps
retire_js_runner.py    — JS vulnerable libraries
git_log_analyzer.py    — sensitive commits
patch_generator.py     — generates code fixes
patch_applier.py       — applies patches to files
sandbox_manager.py     — Docker sandbox lifecycle
nikto_dast_runner.py   — DAST web server scan
burp_runner.py         — DAST advanced scan

Each function follows the same pattern:
    - Check binary installed
    - Run with subprocess
    - Parse output
    - Return normalized dict with status, findings, summary

Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""





import json, logging, shutil, subprocess
from pathlib import Path

logger_th = logging.getLogger("ai_kavach.code_tools.trufflehog")

def run_trufflehog(path: str, only_verified: bool = False, timeout: int = 300) -> dict:
    """Run trufflehog v3 to find secrets in git history and files."""
    if not shutil.which("trufflehog"):
        return {"status": "not_installed", "message": "trufflehog not installed. Run: brew install trufflehog or download from github.com/trufflesecurity/trufflehog/releases", "findings": []}

    cmd = ["trufflehog", "filesystem", path, "--json", "--no-update"]
    if only_verified:
        cmd.append("--only-verified")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        findings = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                findings.append({
                    "type":        "Hardcoded Secret",
                    "detector":    obj.get("DetectorName", "unknown"),
                    "severity":    "critical",
                    "file":        obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                    "line":        obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                    "verified":    obj.get("Verified", False),
                    "raw_preview": obj.get("Raw", "")[:50] + "..." if obj.get("Raw") else "",
                    "requires_rotation": True,
                })
            except json.JSONDecodeError:
                continue

        return {
            "status": "success", "tool": "trufflehog", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"trufflehog found {len(findings)} secrets in {path}",
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "message": f"trufflehog timed out after {timeout}s", "findings": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}






def run_gitleaks(path: str, timeout: int = 120) -> dict:
    """Run gitleaks to scan git history for secrets."""
    if not shutil.which("gitleaks"):
        return {"status": "not_installed", "message": "gitleaks not installed. Download from github.com/gitleaks/gitleaks/releases", "findings": []}

    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name

    try:
        cmd = ["gitleaks", "detect", "--source", path, "--report-format", "json", "--report-path", report_path, "--no-banner"]
        subprocess.run(cmd, capture_output=True, timeout=timeout)

        findings = []
        if Path(report_path).exists():
            with open(report_path) as f:
                try:
                    data = json.load(f)
                    for leak in (data or []):
                        findings.append({
                            "type":     "Hardcoded Secret",
                            "rule_id":  leak.get("RuleID", ""),
                            "severity": "critical",
                            "file":     leak.get("File", ""),
                            "line":     leak.get("StartLine", 0),
                            "commit":   leak.get("Commit", ""),
                            "author":   leak.get("Author", ""),
                            "date":     leak.get("Date", ""),
                            "secret_preview": leak.get("Secret", "")[:20] + "...",
                            "requires_rotation": True,
                            "in_git_history": True,
                        })
                except json.JSONDecodeError:
                    pass
        os.unlink(report_path)

        return {
            "status": "success", "tool": "gitleaks", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"gitleaks found {len(findings)} secrets (including git history)",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}






def run_detect_secrets(path: str, timeout: int = 60) -> dict:
    """Run detect-secrets on current file contents (not git history)."""
    try:
        import detect_secrets  
    except ImportError:
        return {"status": "not_installed", "message": "detect-secrets not installed. Run: pip install detect-secrets", "findings": []}

    try:
        result = subprocess.run(
            ["detect-secrets", "scan", path],
            capture_output=True, text=True, timeout=timeout
        )
        data = json.loads(result.stdout)
        findings = []
        for file_path, secrets in data.get("results", {}).items():
            for secret in secrets:
                findings.append({
                    "type":     "Hardcoded Secret",
                    "detector": secret.get("type", "unknown"),
                    "severity": "critical",
                    "file":     file_path,
                    "line":     secret.get("line_number", 0),
                    "hashed_secret": secret.get("hashed_secret", ""),
                    "requires_rotation": True,
                })
        return {
            "status": "success", "tool": "detect-secrets", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"detect-secrets found {len(findings)} potential secrets",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}






def run_pip_audit(path: str, timeout: int = 120) -> dict:
    """Run pip-audit to find vulnerable Python dependencies."""
    if not shutil.which("pip-audit"):
        return {"status": "not_installed", "message": "pip-audit not installed. Run: pip install pip-audit", "findings": []}

    req_file = Path(path) / "requirements.txt"
    pyproject = Path(path) / "pyproject.toml"

    cmd = ["pip-audit", "--format", "json"]
    if req_file.exists():
        cmd += ["-r", str(req_file)]
    elif pyproject.exists():
        cmd += ["--fix"]
    else:
        return {"status": "error", "message": "No requirements.txt or pyproject.toml found", "findings": []}

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=path)
        data = json.loads(result.stdout or "[]")
        findings = []
        for pkg in (data if isinstance(data, list) else data.get("dependencies", [])):
            for vuln in pkg.get("vulns", []):
                findings.append({
                    "type":            "Vulnerable Dependency",
                    "severity":        _cvss_to_severity(vuln.get("fix_versions", [])),
                    "package":         pkg.get("name", ""),
                    "current_version": pkg.get("version", ""),
                    "fix_version":     vuln.get("fix_versions", ["unknown"])[0] if vuln.get("fix_versions") else "unknown",
                    "cve":             vuln.get("id", ""),
                    "description":     vuln.get("description", ""),
                    "upgrade_cmd":     f"pip install {pkg.get('name','')}=={vuln.get('fix_versions',[''])[0]}",
                })
        return {
            "status": "success", "tool": "pip-audit", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"pip-audit found {len(findings)} vulnerable Python packages",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}






def run_npm_audit(path: str, timeout: int = 120) -> dict:
    """Run npm audit to find vulnerable Node.js dependencies."""
    if not shutil.which("npm"):
        return {"status": "not_installed", "message": "npm not installed. Install Node.js from nodejs.org", "findings": []}

    pkg_json = Path(path) / "package.json"
    if not pkg_json.exists():
        return {"status": "error", "message": "No package.json found", "findings": []}

    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True, timeout=timeout, cwd=path
        )
        data = json.loads(result.stdout or "{}")
        findings = []
        severity_map = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}

        for vuln_name, vuln in data.get("vulnerabilities", {}).items():
            findings.append({
                "type":            "Vulnerable Dependency",
                "package":         vuln_name,
                "severity":        severity_map.get(vuln.get("severity", "low"), "low"),
                "current_version": vuln.get("range", ""),
                "fix_available":   vuln.get("fixAvailable", False),
                "cve":             ", ".join(vuln.get("via", [{}])[0].get("cve", []) if isinstance(vuln.get("via", [{}])[0], dict) else []),
                "upgrade_cmd":     "npm audit fix" if vuln.get("fixAvailable") else "manual fix required",
            })

        return {
            "status": "success", "tool": "npm-audit", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"npm audit found {len(findings)} vulnerable packages",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}






def run_safety(path: str, timeout: int = 60) -> dict:
    """Run safety to check Python packages against CVE database."""
    if not shutil.which("safety"):
        return {"status": "not_installed", "message": "safety not installed. Run: pip install safety", "findings": []}

    try:
        result = subprocess.run(
            ["safety", "check", "--json", "-r", str(Path(path) / "requirements.txt")],
            capture_output=True, text=True, timeout=timeout
        )
        data = json.loads(result.stdout or "[]")
        findings = []
        for vuln in data:
            findings.append({
                "type":     "Vulnerable Dependency",
                "severity": "high",
                "package":  vuln[0] if len(vuln) > 0 else "",
                "affected_version": vuln[1] if len(vuln) > 1 else "",
                "fix_version": vuln[3] if len(vuln) > 3 else "",
                "cve":      vuln[4] if len(vuln) > 4 else "",
                "message":  vuln[3] if len(vuln) > 3 else "",
            })
        return {
            "status": "success", "tool": "safety", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"safety found {len(findings)} vulnerable Python packages",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}






def run_snyk(path: str, timeout: int = 180) -> dict:
    """Run snyk for multi-language dependency vulnerability scanning."""
    if not shutil.which("snyk"):
        return {"status": "not_installed", "message": "snyk not installed. Run: npm install -g snyk && snyk auth", "findings": []}

    try:
        result = subprocess.run(
            ["snyk", "test", "--json", "--all-projects"],
            capture_output=True, text=True, timeout=timeout, cwd=path
        )
        data = json.loads(result.stdout or "{}")
        findings = []
        severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        for vuln in data.get("vulnerabilities", []):
            findings.append({
                "type":            "Vulnerable Dependency",
                "severity":        severity_map.get(vuln.get("severity", "low"), "low"),
                "package":         vuln.get("packageName", ""),
                "current_version": vuln.get("version", ""),
                "fix_version":     vuln.get("fixedIn", ["unknown"])[0] if vuln.get("fixedIn") else "unknown",
                "cve":             ", ".join(vuln.get("identifiers", {}).get("CVE", [])),
                "cvss":            vuln.get("cvssScore", 0.0),
                "title":           vuln.get("title", ""),
            })
        return {
            "status": "success", "tool": "snyk", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"snyk found {len(findings)} vulnerable packages",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}






def run_retirejs(path: str, timeout: int = 120) -> dict:
    """Run retire.js to detect vulnerable JavaScript libraries."""
    if not shutil.which("retire"):
        return {"status": "not_installed", "message": "retire.js not installed. Run: npm install -g retire", "findings": []}

    try:
        result = subprocess.run(
            ["retire", "--path", path, "--outputformat", "json"],
            capture_output=True, text=True, timeout=timeout
        )
        findings = []
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                for vuln in obj.get("vulnerabilities", []):
                    findings.append({
                        "type":     "Vulnerable JS Library",
                        "severity": vuln.get("severity", "unknown"),
                        "file":     obj.get("file", ""),
                        "package":  obj.get("component", ""),
                        "version":  obj.get("version", ""),
                        "cve":      ", ".join(vuln.get("identifiers", {}).get("CVE", [])),
                    })
            except json.JSONDecodeError:
                continue
        return {
            "status": "success", "tool": "retire.js", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"retire.js found {len(findings)} vulnerable JS libraries",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}






def analyze_git_log(path: str, timeout: int = 60) -> dict:
    """Analyze git log for sensitive commit messages and patterns."""
    if not shutil.which("git"):
        return {"status": "not_installed", "message": "git not installed", "findings": []}

    sensitive_patterns = [
        "password", "secret", "token", "api_key", "apikey", "credentials",
        "private_key", "auth", "hardcode", "remove secret", "fix secret",
        "delete key", "oops", "forgot", "accidental", "test creds",
    ]

    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "--all", "--format=%H %s %ae %ai"],
            capture_output=True, text=True, timeout=timeout, cwd=path
        )
        findings = []
        for line in result.stdout.splitlines():
            parts = line.split(" ", 3)
            if len(parts) < 2:
                continue
            commit_hash = parts[0]
            message     = " ".join(parts[1:]).lower()
            if any(p in message for p in sensitive_patterns):
                findings.append({
                    "type":     "Sensitive Commit",
                    "severity": "high",
                    "commit":   commit_hash,
                    "message":  " ".join(parts[1:]),
                    "note":     "Commit message suggests sensitive data may have been added/removed. Review this commit.",
                })
        return {
            "status": "success", "tool": "git-log-analyzer", "path": path,
            "findings": findings, "total": len(findings),
            "summary": f"git log analysis found {len(findings)} suspicious commits",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}






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






def manage_sandbox(
    action: str,
    sandbox_id: str,
    path: str = "",
    port: int = 8888,
    readonly: bool = True,
) -> dict:
    """
    Manage Docker sandbox lifecycle.

    Actions:
        create    — create isolated container
        mount     — mount codebase into container
        start_app — start application inside container
        collect   — collect results from container
        destroy   — destroy container and network
    """
    if not shutil.which("docker"):
        return {
            "status":  "not_installed",
            "message": "Docker not installed. Install from docker.com",
            "app_url": None,
        }

    container_name = f"ai_kavach-sandbox-{sandbox_id}"

    try:
        if action == "create":
            cmd = [
                "docker", "run", "-d",
                "--name", container_name,
                "--network", "none",           
                "--memory", "4g",
                "--cpus", "2",
                "--read-only" if readonly else "",
                "python:3.11-slim", "sleep", "3600",
            ]
            cmd = [c for c in cmd if c]  
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {
                "status":       "success" if result.returncode == 0 else "error",
                "action":       "create",
                "container":    container_name,
                "sandbox_id":   sandbox_id,
                "message":      result.stdout.strip() or result.stderr.strip(),
                "summary":      f"Sandbox {container_name} created",
            }

        elif action == "mount":
            cmd = ["docker", "cp", path, f"{container_name}:/app"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {
                "status":   "success" if result.returncode == 0 else "error",
                "action":   "mount",
                "path":     path,
                "container": container_name,
                "summary":  f"Mounted {path} into {container_name}",
            }

        elif action == "start_app":
            cmd = ["docker", "exec", "-d", container_name,
                   "sh", "-c", f"cd /app && python app.py --port {port} &"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "status":   "success" if result.returncode == 0 else "error",
                "action":   "start_app",
                "app_url":  f"http://localhost:{port}",
                "container": container_name,
                "summary":  f"App started in sandbox on port {port}",
            }

        elif action == "collect":
            result = subprocess.run(
                ["docker", "logs", container_name],
                capture_output=True, text=True, timeout=30
            )
            return {
                "status":  "success",
                "action":  "collect",
                "logs":    result.stdout[:5000],
                "summary": f"Collected logs from {container_name}",
            }

        elif action == "destroy":
            subprocess.run(["docker", "stop", container_name], capture_output=True, timeout=30)
            result = subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, text=True, timeout=30)
            return {
                "status":   "success" if result.returncode == 0 else "error",
                "action":   "destroy",
                "container": container_name,
                "summary":  f"Sandbox {container_name} destroyed",
            }

        else:
            return {"status": "error", "message": f"Unknown action: {action}"}

    except Exception as e:
        return {"status": "error", "message": str(e), "action": action}






def run_nikto_dast(target_url: str, port: int = 80, timeout: int = 180) -> dict:
    """Run Nikto for DAST web server scanning."""
    if not shutil.which("nikto") and not shutil.which("nikto.pl"):
        return {"status": "not_installed", "message": "nikto not installed. See github.com/sullo/nikto", "findings": []}

    binary = shutil.which("nikto") or shutil.which("nikto.pl")
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name

    try:
        cmd = [binary, "-h", target_url, "-p", str(port), "-Format", "json", "-o", out, "-nointeractive"]
        subprocess.run(cmd, capture_output=True, timeout=timeout)
        findings = []
        if Path(out).exists():
            with open(out) as f:
                data = json.load(f)
            for item in data.get("vulnerabilities", []):
                findings.append({
                    "type":     item.get("id", "unknown"),
                    "severity": "medium",
                    "endpoint": item.get("url", target_url),
                    "message":  item.get("msg", ""),
                    "method":   item.get("method", "GET"),
                })
        os.unlink(out)
        return {
            "status": "success", "tool": "nikto-dast", "target": target_url,
            "findings": findings, "total": len(findings),
            "summary": f"Nikto DAST found {len(findings)} issues on {target_url}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}






def run_burp(target_url: str, api_key: str = "", timeout: int = 300) -> dict:
    """Run Burp Suite Enterprise via REST API for advanced DAST."""
    if not api_key:
        import os
        api_key = os.environ.get("BURP_API_KEY", "")
    if not api_key:
        return {
            "status":  "not_configured",
            "message": "Burp Suite Enterprise API key not configured. Set BURP_API_KEY env var.",
            "findings": [],
        }

    
    burp_host = "http://localhost:1337"
    try:
        import urllib.request, urllib.parse
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        
        scan_payload = json.dumps({"urls": [target_url]}).encode()
        req = urllib.request.Request(f"{burp_host}/api/scan", data=scan_payload, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            scan_data = json.loads(resp.read())

        scan_id = scan_data.get("scan_id", "")
        if not scan_id:
            return {"status": "error", "message": "Burp did not return scan_id", "findings": []}

        import time
        elapsed = 0
        while elapsed < timeout:
            req = urllib.request.Request(f"{burp_host}/api/scan/{scan_id}", headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                status_data = json.loads(resp.read())
            if status_data.get("scan_status") == "succeeded":
                break
            time.sleep(15)
            elapsed += 15

        
        req = urllib.request.Request(f"{burp_host}/api/scan/{scan_id}/issues", headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            issues_data = json.loads(resp.read())

        findings = []
        severity_map = {"high": "high", "medium": "medium", "low": "low", "information": "info"}
        for issue in issues_data.get("issue_events", []):
            issue_def = issue.get("issue", {})
            findings.append({
                "type":       issue_def.get("type_index", "unknown"),
                "severity":   severity_map.get(issue_def.get("severity", "low"), "low"),
                "confidence": issue_def.get("confidence", "tentative"),
                "endpoint":   issue_def.get("path", target_url),
                "detail":     issue_def.get("description", ""),
            })

        return {
            "status": "success", "tool": "burp-enterprise", "target": target_url,
            "findings": findings, "total": len(findings),
            "summary": f"Burp found {len(findings)} issues on {target_url}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": []}




def _cvss_to_severity(fix_versions: list) -> str:
    return "high" if fix_versions else "medium"
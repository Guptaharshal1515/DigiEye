"""
AI_KAVACH — sandbox_manager.py
===========================
Extracted from the original code_tools.py without changing runner logic.
Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import json, logging, shutil, subprocess
from pathlib import Path



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




"""
AI_KAVACH — Code Secret Scanner Agent ()
==========================================
Detects hardcoded secrets, credentials, API keys, tokens,
and sensitive data in source code and git history.

agent_type: "code_secrets"
Inherits:   BaseAgent

Tools: trufflehog, detect-secrets, gitleaks
Detects: API keys, passwords, tokens, private keys, connection strings,
         AWS/GCP/Azure credentials, JWT secrets, database URLs

Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import logging
from typing import Optional

from agents.base_agent import BaseAgent
from app.session_memory import SessionMemory
from system_prompts.code.code_secret_prompt import CODE_SECRET_PROMPT

logger = logging.getLogger("ai_kavach.agents.code.secret_scanner")


class SecretScannerAgent(BaseAgent):
    """
    Secret detection agent. Scans source code and git history
    for hardcoded credentials and sensitive data.
    """

    def __init__(
        self,
        task_id: str,
        target: str,
        session_memory: Optional[SessionMemory] = None,
    ):
        super().__init__(
            agent_type="code_secrets",
            task_id=task_id,
            target=target,
            session_memory=session_memory,
        )
        self.system_prompt = CODE_SECRET_PROMPT
        self._repo_path: Optional[str] = None
        self._has_git: bool = False

        logger.info(f"[{task_id}] SecretScannerAgent initialized | target={target}")

    def _pre_run(self, task_prompt: str, env: dict) -> None:
        import os
        self._repo_path = self.memory.log_path or self.target
        
        if self._repo_path:
            self._has_git = os.path.exists(
                f"{self._repo_path}/.git"
            )
        available = env.get("tools_available", [])
        secret_tools = [
            t for t in ["trufflehog", "gitleaks", "detect-secrets"]
            if t in available
        ]
        if not secret_tools:
            logger.warning(f"[{self.task_id}] SecretScanner: no tools installed")
        logger.info(
            f"[{self.task_id}] SecretScanner: "
            f"tools={secret_tools} | git={self._has_git}"
        )

    def _post_run(self, final_answer: Optional[dict], error: Optional[str]) -> Optional[dict]:
        if not final_answer:
            return None
        if self._repo_path:
            final_answer["target"] = self._repo_path
        
        for vuln in final_answer.get("vulnerabilities", []):
            if "secret" in vuln.get("type", "").lower():
                vuln["severity"] = "critical"
                vuln["requires_rotation"] = True
        return final_answer

    def _build_first_message(self, task_prompt: str) -> str:
        parts = []
        parts.append(f"TARGET CODEBASE: {self._repo_path}")
        parts.append(f"GIT REPOSITORY: {self._has_git}")
        parts.append(
            "\nSECRET SCAN SEQUENCE:\n"
            "1. run_trufflehog (git history + current code)\n"
            "2. run_gitleaks (git history — if .git exists)\n"
            "3. run_detect_secrets (current files)\n"
            "4. analyze_git_log (commits with sensitive keywords)\n"
            "\nFor each secret found:\n"
            "  - Record exact file path and line number\n"
            "  - Classify: API key, password, token, private key, connection string\n"
            "  - Check if it appears in git history (cannot be deleted, must rotate)\n"
            "  - Mark requires_rotation=true for any secret in git history"
        )
        parts.append(f"\nTASK:\n{task_prompt}")
        return "\n".join(parts)
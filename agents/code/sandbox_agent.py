"""
AI_KAVACH — Code Sandbox Agent ()
===================================
Manages the isolated sandbox environment for code security testing.
Creates, configures, and destroys Docker-based sandboxes.

agent_type: "code_sandbox"
Inherits:   BaseAgent

Responsibilities:
    - Spin up isolated Docker container for the target application
    - Mount target codebase read-only (analysis) or read-write (patching)
    - Start the application inside the container
    - Expose port for DAST testing
    - Collect output after testing
    - Destroy container completely — no persistent state

Sandbox isolation:
    - Separate Docker network (no internet access during fuzzing)
    - Resource limits: 2 CPU, 4GB RAM, 10GB disk
    - Read-only filesystem except /tmp and /app/patched/
    - All traffic logged via tshark on the sandbox interface

Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import logging
from typing import Optional

from agents.base_agent import BaseAgent
from app.session_memory import SessionMemory
from system_prompts.code.code_sandbox_prompt import CODE_SANDBOX_PROMPT

logger = logging.getLogger("ai_kavach.agents.code.sandbox_agent")


class SandboxAgent(BaseAgent):
    """
    Sandbox lifecycle management agent.
    Creates isolated environment, runs application, manages cleanup.
    """

    def __init__(
        self,
        task_id: str,
        target: str,
        session_memory: Optional[SessionMemory] = None,
    ):
        super().__init__(
            agent_type="code_sandbox",
            task_id=task_id,
            target=target,
            session_memory=session_memory,
        )
        self.system_prompt = CODE_SANDBOX_PROMPT
        self._repo_path: Optional[str] = None
        self._sandbox_id: Optional[str] = None
        self._app_url: Optional[str] = None
        self._container_port: int = 8888
        self._docker_available: bool = False

        logger.info(f"[{task_id}] SandboxAgent initialized | target={target}")

    def _pre_run(self, task_prompt: str, env: dict) -> None:
        """Check Docker availability."""
        import shutil
        self._docker_available = shutil.which("docker") is not None
        self._repo_path = self.memory.log_path or self.target
        self._sandbox_id = self.task_id

        if not self._docker_available:
            logger.warning(
                f"[{self.task_id}] SandboxAgent: Docker not installed — "
                f"sandbox isolation not available. "
                f"Analysis will run on host filesystem."
            )
            self._tools_not_available.append(
                "docker — sandbox isolation requires Docker"
            )
        else:
            logger.info(f"[{self.task_id}] SandboxAgent: Docker available")

    def _post_run(self, final_answer: Optional[dict], error: Optional[str]) -> Optional[dict]:
        if not final_answer:
            return None
        
        if self._app_url:
            if not hasattr(self.memory, "sandbox_state"):
                self.memory.sandbox_state = {}
            self.memory.sandbox_state["app_url"] = self._app_url
            self.memory.sandbox_state["sandbox_id"] = self._sandbox_id
            self.memory.sandbox_state["container_port"] = self._container_port
        final_answer["target"] = self._repo_path or self.target
        return final_answer

    def _build_first_message(self, task_prompt: str) -> str:
        parts = []
        parts.append(f"TARGET CODEBASE: {self._repo_path}")
        parts.append(f"SANDBOX ID: {self._sandbox_id}")
        parts.append(f"DOCKER AVAILABLE: {self._docker_available}")
        parts.append(f"APP PORT: {self._container_port}")
        parts.append(
            "\nSANDBOX SEQUENCE:\n"
            "1. manage_sandbox(action='create', sandbox_id=task_id)\n"
            "2. manage_sandbox(action='mount', path=repo_path)\n"
            "3. manage_sandbox(action='start_app', port=discovered_or_requested_port)\n"
            "4. Verify app is running on the URL returned by sandbox output (no hardcoded localhost).\n"
            "5. Return app_url for DAST agent from actual runtime output\n"
            "\nAfter all testing is complete:\n"
            "6. manage_sandbox(action='collect_results')\n"
            "7. manage_sandbox(action='destroy', sandbox_id=task_id)\n"
            "\nISOLATION RULES:\n"
            "- No internet access during fuzzing\n"
            "- Resource limits: 2 CPU, 4GB RAM\n"
            "- Codebase mounted read-only for analysis stages\n"
            "- Mounted read-write only during patching stage"
        )
        parts.append(f"\nTASK:\n{task_prompt}")
        return "\n".join(parts)
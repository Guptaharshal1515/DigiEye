"""
AI_KAVACH — Code Agent Orchestrator ()
========================================
Orchestrates the complete autonomous code security pipeline:
    SAST → DAST → Fuzzing → Secrets → Dependencies → Patch → Verify

agent_type: "code_orchestrator"
Inherits:   BaseAgent

This agent can:
    - Enter a sandbox environment autonomously
    - Run static and dynamic analysis across all major languages
    - Fuzz the target with AFL++, libFuzzer, Atheris, Jazzer
    - Detect hardcoded secrets and vulnerable dependencies
    - Generate and apply patches autonomously
    - Verify patches did not break functionality
    - Exit and clean up the sandbox

Supported languages:
    Python, JavaScript/TypeScript, Java, C/C++, Go, Rust,
    Ruby, PHP, C#, Swift, Kotlin, Scala

Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import logging
from typing import Optional

from agents.base_agent import BaseAgent
from app.session_memory import SessionMemory
from system_prompts.code.code_orchestrator_prompt import CODE_ORCHESTRATOR_PROMPT

logger = logging.getLogger("ai_kavach.agents.code.code_agent")


class CodeAgent(BaseAgent):
    """
    Code security orchestrator. Runs the full autonomous vulnerability
    discovery and patching pipeline against a target codebase.
    """

    def __init__(
        self,
        task_id: str,
        target: str,
        session_memory: Optional[SessionMemory] = None,
    ):
        super().__init__(
            agent_type="code_orchestrator",
            task_id=task_id,
            target=target,
            session_memory=session_memory,
        )
        self.system_prompt = CODE_ORCHESTRATOR_PROMPT
        self._repo_path: Optional[str] = None
        self._language: Optional[str] = None
        self._sandbox_active: bool = False

        logger.info(f"[{task_id}] CodeAgent initialized | target={target}")

    def _pre_run(self, task_prompt: str, env: dict) -> None:
        """Detect language, enter sandbox, set repo path."""
        import re
        
        path_match = re.search(
            r'[A-Za-z]:[/\\][\w/\\\-\.]+|/[\w/\-\.]{5,}',
            task_prompt
        )
        if path_match:
            self._repo_path = path_match.group(0)
            self.memory.set_log_path(self._repo_path)

        if self.target:
            self.memory.set_target(self.target)
            self.memory.add_to_scope(self.target)

        logger.info(
            f"[{self.task_id}] CodeAgent pre-run | "
            f"repo={self._repo_path} | target={self.target}"
        )

    def _post_run(self, final_answer: Optional[dict], error: Optional[str]) -> Optional[dict]:
        """Ensure sandbox is cleaned up even on failure."""
        if self._sandbox_active:
            logger.warning(
                f"[{self.task_id}] CodeAgent: sandbox still active after run — "
                f"attempting cleanup"
            )
            try:
                from runners.code.sandbox_manager import manage_sandbox
                manage_sandbox(action="destroy", sandbox_id=self.task_id)
                self._sandbox_active = False
            except Exception as e:
                logger.error(f"[{self.task_id}] Sandbox cleanup failed: {e}")

        if not final_answer:
            return None

        
        if self._repo_path and final_answer.get("target") != self._repo_path:
            final_answer["target"] = self._repo_path

        
        if self.memory.all_evidence:
            existing = set(final_answer.get("evidence", []))
            for e in self.memory.all_evidence:
                if e not in existing:
                    final_answer.setdefault("evidence", []).append(e)

        return final_answer

    def _build_first_message(self, task_prompt: str) -> str:
        parts = []
        if self._repo_path:
            parts.append(
                f"TARGET CODEBASE: {self._repo_path}\n"
                f"Use this exact path in your final_answer target field."
            )
        parts.append(
            "\nPIPELINE: sandbox_enter → sast → dast → fuzz → "
            "secrets → dependency_audit → patch → verify → sandbox_destroy"
        )
        parts.append(f"\nTASK:\n{task_prompt}")
        return "\n".join(parts)
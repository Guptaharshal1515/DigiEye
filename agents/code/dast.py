"""AI_KAVACH code DAST agent."""

import logging
from typing import Optional

from agents.base_agent import BaseAgent
from app.session_memory import SessionMemory
from system_prompts.code.code_dast_prompt import CODE_DAST_PROMPT
from tools.execution_models import split_host_port_from_url
from tools.target_utils import extract_http_targets, normalize_http_url

logger = logging.getLogger("ai_kavach.agents.code.dast")


class DASTAgent(BaseAgent):
    def __init__(self, task_id: str, target: str, session_memory: Optional[SessionMemory] = None):
        super().__init__(agent_type="code_dast", task_id=task_id, target=target, session_memory=session_memory)
        self.system_prompt = CODE_DAST_PROMPT
        self._app_url: Optional[str] = None
        self._target_urls: list[str] = []

    def _pre_run(self, task_prompt: str, env: dict) -> None:
        sandbox_state = getattr(self.memory, "sandbox_state", {}) or {}
        discovered: list[str] = []

        for u in extract_http_targets(task_prompt):
            if u not in discovered:
                discovered.append(u)

        app_url = normalize_http_url(str(sandbox_state.get("app_url", "")))
        if app_url and app_url not in discovered:
            discovered.append(app_url)

        target_url = normalize_http_url(str(self.target or ""))
        if target_url and target_url not in discovered:
            discovered.append(target_url)

        self._target_urls = discovered
        self._app_url = discovered[0] if discovered else None
        if self._app_url:
            self.memory.set_target(self._app_url)

        if not discovered:
            logger.warning(f"[{self.task_id}] DAST: no HTTP target discovered from task/sandbox")

    def _post_run(self, final_answer: Optional[dict], error: Optional[str]) -> Optional[dict]:
        if not final_answer:
            return None
        if self._app_url:
            final_answer["target"] = self._app_url
        if self._target_urls:
            final_answer["targets_tested"] = self._target_urls
        return final_answer

    def _build_first_message(self, task_prompt: str) -> str:
        parts = []
        if self._target_urls:
            parts.append("TARGET APPLICATION URLS:\n" + "\n".join(f"- {u}" for u in self._target_urls))
            host_ports = []
            for url in self._target_urls:
                host, port = split_host_port_from_url(url)
                host_ports.append(f"- {url} -> host={host} port={port}")
            parts.append("\nDAST TARGET DERIVATION:\n" + "\n".join(host_ports))
        else:
            parts.append("TARGET APPLICATION URLS: none discovered. Use provided task input URLs only; do not substitute localhost.")

        parts.append(
            "\nDAST SEQUENCE:\n"
            "1. check_headers on each target URL\n"
            "2. check_ssl for HTTPS targets\n"
            "3. run_zap on target URL(s)\n"
            "4. run_nikto_dast on target URL(s)\n"
            "5. run_burp only if configured\n"
            "If target unreachable, record real connection error; do not substitute another URL."
        )
        parts.append(f"\nTASK:\n{task_prompt}")
        return "\n".join(parts)

"""
AI_KAVACH — Code Dependency Audit Agent ()
============================================
Detects vulnerable third-party dependencies across all package managers.

agent_type: "code_dependency"
Inherits:   BaseAgent

Tools: pip-audit, npm audit, safety, snyk, retire.js
Covers: Python (pip), Node.js (npm/yarn), Java (maven/gradle),
        Ruby (bundler), PHP (composer), Go (go mod), Rust (cargo)

Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import logging
import os
from typing import Optional

from agents.base_agent import BaseAgent
from app.session_memory import SessionMemory
from system_prompts.code.code_dependency_prompt import CODE_DEPENDENCY_PROMPT

logger = logging.getLogger("ai_kavach.agents.code.dependency_audit")


class DependencyAuditAgent(BaseAgent):
    """
    Dependency audit agent. Detects known vulnerable packages
    across all major package managers.
    """

    def __init__(
        self,
        task_id: str,
        target: str,
        session_memory: Optional[SessionMemory] = None,
    ):
        super().__init__(
            agent_type="code_dependency",
            task_id=task_id,
            target=target,
            session_memory=session_memory,
        )
        self.system_prompt = CODE_DEPENDENCY_PROMPT
        self._repo_path: Optional[str] = None
        self._detected_package_files: list = []

        logger.info(f"[{task_id}] DependencyAuditAgent initialized | target={target}")

    def _pre_run(self, task_prompt: str, env: dict) -> None:
        """Detect package manager files in repo."""
        self._repo_path = self.memory.log_path or self.target
        if self._repo_path and os.path.exists(self._repo_path):
            manifest_files = [
                "requirements.txt", "Pipfile", "pyproject.toml",  
                "package.json", "yarn.lock",                        
                "pom.xml", "build.gradle",                          
                "Gemfile",                                           
                "composer.json",                                     
                "go.mod",                                            
                "Cargo.toml",                                        
            ]
            for f in manifest_files:
                full_path = os.path.join(self._repo_path, f)
                if os.path.exists(full_path):
                    self._detected_package_files.append(f)

        logger.info(
            f"[{self.task_id}] DependencyAudit: "
            f"manifests={self._detected_package_files}"
        )

    def _post_run(self, final_answer: Optional[dict], error: Optional[str]) -> Optional[dict]:
        if not final_answer:
            return None
        if self._repo_path:
            final_answer["target"] = self._repo_path
        
        vulns = final_answer.get("vulnerabilities", [])
        vulns.sort(key=lambda v: v.get("cvss", 0), reverse=True)
        final_answer["vulnerabilities"] = vulns
        return final_answer

    def _build_first_message(self, task_prompt: str) -> str:
        parts = []
        parts.append(f"CODEBASE: {self._repo_path}")
        if self._detected_package_files:
            parts.append(
                f"DETECTED PACKAGE FILES: {', '.join(self._detected_package_files)}"
            )
        parts.append(
            "\nDEPENDENCY AUDIT SEQUENCE:\n"
            "1. run_pip_audit (requirements.txt / pyproject.toml)\n"
            "2. run_npm_audit (package.json)\n"
            "3. run_safety (Python — additional CVE database)\n"
            "4. run_snyk (multi-language — if available)\n"
            "5. run_retirejs (JavaScript — client-side vulnerable libs)\n"
            "6. lookup_cve for every CVE ID found\n"
            "\nFor each vulnerable package:\n"
            "  - Current version vs patched version\n"
            "  - CVE ID and CVSS score\n"
            "  - Direct vs transitive dependency\n"
            "  - Upgrade command to fix"
        )
        parts.append(f"\nTASK:\n{task_prompt}")
        return "\n".join(parts)
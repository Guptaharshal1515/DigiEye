"""
AI_KAVACH — Code Patch Agent ()
=================================
Autonomous patch generation and application agent.
Reads findings from SAST, DAST, Fuzzer, and Secret Scanner,
generates fixes, applies them, and verifies they work.

agent_type: "code_patch"
Inherits:   BaseAgent

Patch strategies by vulnerability type:
    SQL Injection     → parameterized queries
    XSS               → output encoding, CSP headers
    Command Injection → allowlist validation, subprocess with list args
    Path Traversal    → path normalization, allowlist
    Hardcoded Secret  → move to environment variable
    Vulnerable Dep    → upgrade to patched version
    Buffer Overflow   → bounds checking, safe string functions
    Use-After-Free    → memory management fixes

IMPORTANT: Patch agent only modifies files inside the sandbox.
Never applies patches to production code without human review.

Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import logging
from typing import Optional

from agents.base_agent import BaseAgent
from app.session_memory import SessionMemory
from system_prompts.code.code_patch_prompt import CODE_PATCH_PROMPT

logger = logging.getLogger("ai_kavach.agents.code.patch_agent")


class PatchAgent(BaseAgent):
    """
    Autonomous patch generation and application agent.
    Generates, applies, and verifies fixes for all confirmed vulnerabilities.
    """

    def __init__(
        self,
        task_id: str,
        target: str,
        session_memory: Optional[SessionMemory] = None,
    ):
        super().__init__(
            agent_type="code_patch",
            task_id=task_id,
            target=target,
            session_memory=session_memory,
        )
        self.system_prompt = CODE_PATCH_PROMPT
        self._repo_path: Optional[str] = None
        self._vulnerabilities_to_patch: list = []
        self._patches_applied: list = []
        self._patches_failed: list = []
        self._sandbox_only: bool = True  

        logger.info(f"[{task_id}] PatchAgent initialized | target={target}")

    def _pre_run(self, task_prompt: str, env: dict) -> None:
        """Collect all vulnerabilities from prior stages."""
        self._repo_path = self.memory.log_path or self.target

        
        all_vulns = []
        for findings_attr in [
            "code_sast_findings",      
            "code_dast_findings",  
        ]:
            findings = getattr(self.memory, findings_attr, None)
            if findings:
                vulns = findings.get("vulnerabilities", [])
                all_vulns.extend(vulns)

        
        seen = set()
        for v in all_vulns:
            key = f"{v.get('file', '')}:{v.get('line', '')}:{v.get('type', '')}"
            if key not in seen:
                seen.add(key)
                self._vulnerabilities_to_patch.append(v)

        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self._vulnerabilities_to_patch.sort(
            key=lambda v: severity_order.get(v.get("severity", "low"), 3)
        )

        logger.info(
            f"[{self.task_id}] PatchAgent: "
            f"{len(self._vulnerabilities_to_patch)} vulnerabilities to patch | "
            f"sandbox_only={self._sandbox_only}"
        )

        
        if not self._sandbox_only:
            logger.warning(
                f"[{self.task_id}] PatchAgent: sandbox_only=False — "
                f"patches will be applied to live code!"
            )

    def _post_run(self, final_answer: Optional[dict], error: Optional[str]) -> Optional[dict]:
        if not final_answer:
            return None
        if self._repo_path:
            final_answer["target"] = self._repo_path
        
        final_answer["patch_summary"] = {
            "total_vulnerabilities":  len(self._vulnerabilities_to_patch),
            "patches_applied":        len(self._patches_applied),
            "patches_failed":         len(self._patches_failed),
            "patch_coverage":         (
                round(
                    len(self._patches_applied) /
                    len(self._vulnerabilities_to_patch), 2
                )
                if self._vulnerabilities_to_patch else 0.0
            ),
            "sandbox_only":           self._sandbox_only,
        }
        return final_answer

    def _build_first_message(self, task_prompt: str) -> str:
        parts = []
        parts.append(f"TARGET CODEBASE: {self._repo_path}")
        parts.append(f"SANDBOX ONLY: {self._sandbox_only}")
        parts.append(
            f"VULNERABILITIES TO PATCH: "
            f"{len(self._vulnerabilities_to_patch)}"
        )
        if self._vulnerabilities_to_patch:
            parts.append("\nVULNERABILITY LIST (patch in this order):")
            for i, v in enumerate(self._vulnerabilities_to_patch[:20], 1):
                parts.append(
                    f"  {i}. [{v.get('severity','?').upper()}] "
                    f"{v.get('type','unknown')} at "
                    f"{v.get('file','?')}:{v.get('line','?')}"
                )
        parts.append(
            "\nPATCHING SEQUENCE PER VULNERABILITY:\n"
            "1. generate_patch (read file, generate fix, produce unified diff)\n"
            "2. apply_patch (apply the diff to the file in sandbox)\n"
            "3. Verify: re-run SAST on patched file\n"
            "4. If SAST still flags it → generate_patch again (max 3 attempts)\n"
            "5. Record: patched / failed / requires_manual_review\n"
            "\nCRITICAL RULES:\n"
            "- Never delete functionality, only fix the vulnerability\n"
            "- Parameterized queries replace string concatenation\n"
            "- Secrets move to os.environ / config files, never deleted\n"
            "- Dependency upgrades: update version in manifest only\n"
            "- If unsure about a fix, mark requires_manual_review=true"
        )
        parts.append(f"\nTASK:\n{task_prompt}")
        return "\n".join(parts)
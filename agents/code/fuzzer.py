"""
AI_KAVACH — Code Fuzzer Agent ()
==================================
Autonomous fuzzing agent. Selects the correct fuzzer per language
and runs it against the target, collecting crashes and hangs.

agent_type: "code_fuzzer"
Inherits:   BaseAgent

Fuzzer selection by language:
    C/C++     → AFL++ (afl-fuzz)
    Python    → Atheris (libFuzzer-based)
    Java/JVM  → Jazzer
    Any       → Radamsa (mutation-based, language-agnostic)
    Binary    → AFL++ with QEMU mode (no source needed)

Pipeline:
    1. Detect language and entry points
    2. Build fuzzing harness (if needed)
    3. Run fuzzer with corpus
    4. Collect crashes
    5. Triage crashes (unique vs duplicate)
    6. Generate PoC for each unique crash
    7. Feed crash info to patch_agent

Author: AI_KAVACH Team (— Harshal)
Schema: 1.0.0
"""

import logging
from typing import Optional

from agents.base_agent import BaseAgent
from app.session_memory import SessionMemory
from system_prompts.code.code_fuzzer_prompt import CODE_FUZZER_PROMPT

logger = logging.getLogger("ai_kavach.agents.code.fuzzer")


class FuzzerAgent(BaseAgent):
    """
    Fuzzing agent. Selects and runs the appropriate fuzzer for the
    target language. Triages crashes and generates PoCs.
    """

    def __init__(
        self,
        task_id: str,
        target: str,
        session_memory: Optional[SessionMemory] = None,
    ):
        super().__init__(
            agent_type="code_fuzzer",
            task_id=task_id,
            target=target,
            session_memory=session_memory,
        )
        self.system_prompt = CODE_FUZZER_PROMPT
        self._repo_path: Optional[str] = None
        self._language: Optional[str] = None
        self._selected_fuzzer: Optional[str] = None
        self._fuzz_timeout: int = 300  

        logger.info(f"[{task_id}] FuzzerAgent initialized | target={target}")

    def _pre_run(self, task_prompt: str, env: dict) -> None:
        """Select fuzzer based on language and availability."""
        self._repo_path = self.memory.log_path or self.target

        
        sast = self.memory.code_sast_findings
        if sast:
            self._language = sast.get("language")

        available = env.get("tools_available", [])

        
        fuzzer_map = {
            "c/c++":      ["afl", "radamsa"],
            "python":     ["atheris", "radamsa"],
            "java":       ["jazzer", "radamsa"],
            "javascript": ["radamsa"],
            "go":         ["go-fuzz", "radamsa"],
            "rust":       ["cargo-fuzz", "radamsa"],
        }

        candidates = fuzzer_map.get(self._language or "", ["radamsa"])
        for fuzzer in candidates:
            if fuzzer in available:
                self._selected_fuzzer = fuzzer
                break

        if not self._selected_fuzzer:
            logger.warning(
                f"[{self.task_id}] Fuzzer: no fuzzer installed for "
                f"language={self._language}. Install AFL++ or radamsa."
            )
            self._tools_not_available.append(
                f"No fuzzer for {self._language} — install AFL++ or radamsa"
            )
        else:
            logger.info(
                f"[{self.task_id}] Fuzzer: selected={self._selected_fuzzer} | "
                f"language={self._language} | timeout={self._fuzz_timeout}s"
            )

    def _post_run(self, final_answer: Optional[dict], error: Optional[str]) -> Optional[dict]:
        if not final_answer:
            return None
        if self._repo_path:
            final_answer["target"] = self._repo_path
        
        for vuln in final_answer.get("vulnerabilities", []):
            vuln["discovered_by"] = f"fuzzer:{self._selected_fuzzer}"
        return final_answer

    def _build_first_message(self, task_prompt: str) -> str:
        parts = []
        parts.append(f"TARGET CODEBASE: {self._repo_path}")
        parts.append(f"LANGUAGE: {self._language or 'auto-detect'}")
        parts.append(f"SELECTED FUZZER: {self._selected_fuzzer or 'none — select from available'}")
        parts.append(f"FUZZ TIMEOUT: {self._fuzz_timeout} seconds")
        parts.append(
            "\nFUZZING SEQUENCE:\n"
            "1. Identify entry points (main(), API handlers, parsers)\n"
            "2. Build fuzzing harness if needed\n"
            "3. run_afl / run_atheris / run_jazzer / run_radamsa\n"
            "4. Collect crashes from output directory\n"
            "5. Triage: deduplicate by stack trace\n"
            "6. Generate PoC input for each unique crash\n"
            "7. Classify crash type: heap overflow, null deref, use-after-free, etc."
        )
        
        sast = self.memory.code_sast_findings
        if sast:
            entry_points = sast.get("entry_points", [])
            if entry_points:
                parts.append(
                    "\nSAST-IDENTIFIED ENTRY POINTS TO FUZZ:\n"
                    + "\n".join(f"  - {ep}" for ep in entry_points[:10])
                )
        parts.append(f"\nTASK:\n{task_prompt}")
        return "\n".join(parts)
"""Shared ReAct loop for Code Agent modules."""

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from app.config import (
    LOCAL_LLM_URL,
    LOCAL_LLM_MODEL,
    LOCAL_LLM_TIMEOUT,
    LOCAL_LLM_MAX_TOKENS,
    LOCAL_LLM_TEMPERATURE,
    MAX_STEPS,
    RETRY_ON_PARSE_FAIL,
    RETRY_DELAY_SECONDS,
    SCHEMA_VERSION,
)
from app.session_memory import SessionMemory
from tools.executor import execute_tool
from tools.registry import get_tools_for_agent
from app.environment_probe import get_available_tools_for_agent, probe_environment

logger = logging.getLogger("ai_kavach.base_agent")





REPAIR_PROMPT = (
    "Your last response was not valid JSON. "
    "You must respond with ONLY a JSON object — no markdown, no explanation, "
    "no text before or after the JSON. "
    "The object must have exactly these three keys:\n"
    '  "thought": your reasoning as a string\n'
    '  "action": the tool name to call, or "final_answer"\n'
    '  "action_input": a dict of parameters for the action\n'
    "Example of correct format:\n"
    '{"thought": "I need to read the log file first.", '
    '"action": "read_log_file", '
    '"action_input": {"path": "C:/logs/access.log", "lines": 100}}\n'
    "Respond now with only the corrected JSON object."
)





VALIDATION_RULES = [
    
    (
        lambda fa: not (fa.get("attack_confirmed") and not fa.get("evidence")),
        "attack_confirmed=true requires at least one evidence item"
    ),
    (
        lambda fa: not (fa.get("attack_confirmed") and not fa.get("attacker", {}).get("ip_addresses")),
        "attack_confirmed=true requires at least one attacker IP address"
    ),
    (
        lambda fa: not (not fa.get("attack_confirmed") and fa.get("attack_types")),
        "attack_confirmed=false requires attack_types to be an empty list"
    ),
    (
        lambda fa: not (fa.get("confidence", 0) >= 0.7 and len(fa.get("evidence", [])) < 2),
        "confidence >= 0.7 requires at least 2 evidence items with line numbers"
    ),
    (
        lambda fa: not (fa.get("confidence", 0) >= 0.9 and len(fa.get("timeline", [])) < 2),
        "confidence >= 0.9 requires at least 2 timeline events"
    ),
]






class BaseAgent:
    """
    Shared ReAct loop for all AI_KAVACH agent modules.

    Subclasses must set:
        self.agent_type     — string identifier (e.g. "code")
        self.system_prompt  — full system prompt string for this agent

    Subclasses may override:
        _pre_run()          — setup before ReAct loop starts
        _post_run()         — cleanup / enrichment after loop ends
        _build_first_message() — how the initial user message is built

    Standard constructor signature (all subclasses follow this):
        def __init__(self, task_id: str, target: str,
                     session_memory: Optional[SessionMemory] = None)
    """

    def __init__(
        self,
        agent_type: str,
        task_id: str,
        target: str,
        session_memory: Optional[SessionMemory] = None,
    ):
        """
        Args:
            agent_type:     Identifier string — must match registry agent lists.
            task_id:        Unique run ID from .
            target:         URL, IP, or file path being investigated.
            session_memory: Shared state from agent_router. Created fresh if None.
        """
        self.agent_type = agent_type
        self.task_id = task_id
        self.target = target

        
        self.memory = session_memory or SessionMemory(
            task_id=task_id,
            task=f"Standalone {agent_type} run on {target}",
            target=target,
        )

        
        self.system_prompt: str = ""

        
        self._step_history: list[dict] = []
        self._parse_failures: int = 0
        self._tools_used: set[str] = set()
        self._tools_not_available: list[str] = []
        self._rag_gaps: list[str] = []
        self._model_struggles: list[str] = []
        self._run_start: float = 0.0
        self._unavailable_tool_attempts: int = 0

        
        self._available_tools: list[dict] = []

        logger.info(
            f"[{task_id}] {self.__class__.__name__} initialized | "
            f"agent_type={agent_type} | target={target}"
        )

    
    
    

    def run(self, task_prompt: str, max_steps: int = MAX_STEPS) -> dict:
        """
        Execute the ReAct loop for this agent.

        Called by agent_router._run_stage() for every stage in the pipeline.
        Returns a structured result dict that agent_router stores in
        session_memory and uses to build Report A and Report B.

        Args:
            task_prompt: The task string to reason about. Built by
                         agent_router's prompt builders with prior
                         stage context already injected.
            max_steps:   Maximum ReAct iterations before forced stop.

        Returns:
            dict with keys:
                success, final_answer, confidence, steps_taken,
                tools_used, tools_not_available, parse_failures,
                clarifications_requested, rag_gaps, model_struggles,
                duration_seconds, error
        """
        self._run_start = time.time()
        self._step_history = []
        self._parse_failures = 0
        self._tools_used = set()
        self._tools_not_available = []
        self._rag_gaps = []
        self._model_struggles = []
        self._unavailable_tool_attempts = 0

        logger.info(
            f"[{self.task_id}] {self.agent_type} run started | max_steps={max_steps}"
        )

        
        env = probe_environment()
        available_tool_names = get_available_tools_for_agent(self.agent_type, env)
        self._available_tools = get_tools_for_agent(self.agent_type, available_tool_names)

        logger.info(
            f"[{self.task_id}] Tools available for {self.agent_type}: "
            f"{[t['name'] for t in self._available_tools]}"
        )

        
        all_registered = get_tools_for_agent(self.agent_type)
        registered_names = {t["name"] for t in all_registered}
        available_names = {t["name"] for t in self._available_tools}
        for missing in registered_names - available_names:
            msg = f"{missing} — tool not installed on "
            self._tools_not_available.append(msg)

        
        try:
            self._pre_run(task_prompt, env)
        except Exception as e:
            logger.warning(f"[{self.task_id}] _pre_run error (non-fatal): {e}")

        
        messages = self._build_initial_messages(task_prompt)

        
        final_answer = None
        error = None

        for step in range(1, max_steps + 1):
            logger.info(f"[{self.task_id}] [{self.agent_type}] Step {step}/{max_steps}")

            
            model_response = self._call_model(messages)

            if model_response is None:
                error = "local LLM did not respond — Ollama may be down"
                self.memory.record_model_struggle(f"Step {step}: Ollama did not respond")
                break

            
            parsed, parse_error = self._parse_response(model_response)

            if parsed is None:
                
                logger.warning(
                    f"[{self.task_id}] Step {step}: parse failure #{self._parse_failures + 1}"
                )
                self._parse_failures += 1
                self.memory.record_parse_failure(model_response, self.agent_type, step)

                if self._parse_failures <= RETRY_ON_PARSE_FAIL:
                    
                    messages.append({"role": "assistant", "content": model_response})
                    messages.append({"role": "user", "content": REPAIR_PROMPT})
                    time.sleep(RETRY_DELAY_SECONDS)
                    continue
                else:
                    error = f"Parse retries exhausted after {self._parse_failures} failures"
                    break

            
            thought = parsed.get("thought", "")
            action = parsed.get("action", "")
            action_input = parsed.get("action_input", {})

            logger.info(
                f"[{self.task_id}] Step {step} | action={action} | "
                f"thought={thought[:80]}..."
            )

            
            self.memory.record_step(
                thought=thought,
                action=action,
                action_input=action_input,
                stage=self.agent_type,
            )

            
            self._step_history.append(
                {
                    "step": step,
                    "thought": thought,
                    "action": action,
                    "action_input": action_input,
                    "observation": None,
                }
            )

            
            messages.append({"role": "assistant", "content": model_response})

            
            if action == "final_answer":
                validation_errors = self._validate_final_answer(action_input)

                if validation_errors:
                    logger.warning(
                        f"[{self.task_id}] Final answer validation failed: {validation_errors}"
                    )
                    self._model_struggles.append(
                        f"Step {step}: Final answer failed validation — {validation_errors}"
                    )
                    self.memory.record_model_struggle(
                        f"Step {step}: Final answer validation errors: {validation_errors}"
                    )
                    
                    fix_prompt = (
                        f"Your final_answer has validation errors that must be fixed:\n"
                        f"{chr(10).join(f'  - {e}' for e in validation_errors)}\n"
                        f"Fix these issues and return the corrected final_answer JSON. "
                        f"Return ONLY the corrected JSON object with action='final_answer'."
                    )
                    messages.append({"role": "user", "content": fix_prompt})
                    continue

                
                final_answer = action_input
                final_answer["agent"] = self.agent_type
                final_answer["task_id"] = self.task_id
                final_answer["timestamp"] = _now()
                final_answer.setdefault("schema_version", SCHEMA_VERSION)
                final_answer.setdefault("target", self.target)

                logger.info(
                    f"[{self.task_id}] {self.agent_type} final answer accepted | "
                    f"confidence={final_answer.get('confidence', 0):.2f} | "
                    f"attack_confirmed={final_answer.get('attack_confirmed')}"
                )
                break

            
            if action not in {t["name"] for t in self._available_tools}:
                
                observation = (
                    f"ERROR: Tool '{action}' is not available. "
                    f"Available tools: {[t['name'] for t in self._available_tools]}. "
                    f"Choose one of those tools or return final_answer."
                )
                self._unavailable_tool_attempts += 1
                self._model_struggles.append(
                    f"Step {step}: Called unavailable tool '{action}'"
                )
                self.memory.record_model_struggle(
                    f"Step {step}: Called unavailable tool '{action}'"
                )
                if self._unavailable_tool_attempts >= 3:
                    messages.append({
                        "role": "user",
                        "content": (
                            "You have attempted to use unavailable tools 3 times. "
                            "You must now call final_answer with whatever findings you have. "
                            "Do not call any more tools."
                        )
                    })
            else:
                
                self._tools_used.add(action)
                tool_start = time.time()

                action_input = self._sanitize_tool_action_input(action, action_input)

                observation_dict = execute_tool(
                    tool_name=action,
                    params=action_input,
                    task_id=self.task_id,
                    agent_type=self.agent_type,
                )

                duration_ms = round((time.time() - tool_start) * 1000)
                observation = json.dumps(observation_dict, indent=2)

                
                self.memory.record_tool_call(
                    tool_name=action,
                    params=action_input,
                    status=observation_dict.get("status", "success"),
                    duration_ms=duration_ms,
                    summary=observation_dict.get("summary", ""),
                    stage=self.agent_type,
                )

                if observation_dict.get("status") in {"tool_not_allowed", "permission_denied"}:
                    self._unavailable_tool_attempts += 1
                    if self._unavailable_tool_attempts >= 3:
                        messages.append({
                            "role": "user",
                            "content": (
                                "You have attempted to use unavailable tools 3 times. "
                                "You must now call final_answer with whatever findings you have. "
                                "Do not call any more tools."
                            )
                        })
                else:
                    self._unavailable_tool_attempts = 0

                
                self._collect_evidence(action, observation_dict)

                
                self._detect_rag_gaps(action, observation_dict)

                logger.info(
                    f"[{self.task_id}] Tool '{action}' completed | "
                    f"status={observation_dict.get('status')} | {duration_ms}ms"
                )

            
            self.memory.update_last_observation(observation)
            if self._step_history:
                self._step_history[-1]["observation"] = observation
            messages.append({
                "role": "user",
                "content": (
                    f"Tool result for '{action}':\n{observation}\n\n"
                    f"Continue your analysis. What do you do next? "
                    f"Steps remaining: {max_steps - step}."
                )
            })

        else:
            
            logger.warning(
                f"[{self.task_id}] {self.agent_type} reached max_steps={max_steps} "
                f"without final_answer"
            )
            self._model_struggles.append(
                f"Reached max_steps={max_steps} without producing final_answer"
            )
            error = f"Max steps ({max_steps}) reached without final answer"

        
        try:
            final_answer = self._post_run(final_answer, error) or final_answer
        except Exception as e:
            logger.warning(f"[{self.task_id}] _post_run error (non-fatal): {e}")

        duration = round(time.time() - self._run_start, 2)
        confidence = final_answer.get("confidence", 0.0) if final_answer else 0.0

        
        for struggle in self._model_struggles:
            self.memory.record_model_struggle(struggle)
        for gap in self._rag_gaps:
            self.memory.record_rag_gap(gap)

        return {
            "success": final_answer is not None,
            "final_answer": final_answer or {},
            "confidence": confidence,
            "steps_taken": len(self._step_history),
            "tools_used": sorted(self._tools_used),
            "tools_not_available": self._tools_not_available,
            "parse_failures": self._parse_failures,
            "clarifications_requested": len(self.memory.clarifications),
            "rag_gaps": self._rag_gaps,
            "model_struggles": self._model_struggles,
            "duration_seconds": duration,
            "error": error,
        }

    
    
    

    def _pre_run(self, task_prompt: str, env: dict) -> None:
        """
        Called once before the ReAct loop starts.
        Override in subclass for stage-specific setup.

        Examples:
            CodeAgent: runs log_preprocessor and injects stats
            CodeAgent: checks scope, confirms target is reachable
        """
        pass

    def _post_run(self, final_answer: Optional[dict], error: Optional[str]) -> Optional[dict]:
        """
        Called once after the ReAct loop ends.
        Override in subclass for stage-specific enrichment.

        Examples:
            CodeAgent: ensures target path in final_answer matches task
            CodeAgent: formats defense rules into deployable configs

        Args:
            final_answer: The validated final_answer dict, or None if failed.
            error:        Error message if run failed, or None.

        Returns:
            Optionally return a modified final_answer dict.
            Return None to keep the original unchanged.
        """
        return None

    def _build_first_message(self, task_prompt: str) -> str:
        """
        Build the first user message in the conversation.
        Override in subclass to prepend preprocessor output, scope, etc.

        Args:
            task_prompt: The task string from agent_router.

        Returns:
            Complete first user message string.
        """
        return task_prompt

    
    
    

    def _build_initial_messages(self, task_prompt: str) -> list[dict]:
        """
        Build the initial message list for the Ollama API call.

        Structure:
            [system prompt, first user message with task + tool list + context]

        The tool list and prior stage context are always injected here
        so the model knows what it can use and what prior stages found.
        """
        
        tool_block = self._build_tool_block()

        
        stage_context = self.memory.get_context_for_stage(self.agent_type)

        
        first_message = self._build_first_message(task_prompt)

        
        full_first = ""
        if stage_context:
            full_first += f"{stage_context}\n\n"
        full_first += f"TARGET: {self.target}\n\n"
        full_first += f"TASK:\n{first_message}\n\n"
        full_first += tool_block
        full_first += (
            "\nRespond with a JSON object containing: "
            '"thought", "action", "action_input". '
            "No markdown. No explanation outside the JSON."
        )

        return [
            {"role": "system", "content": self._get_full_system_prompt()},
            {"role": "user", "content": full_first},
        ]

    def _get_full_system_prompt(self) -> str:
        """
        Returns the full system prompt for this agent.
        Subclasses set self.system_prompt in their __init__.
        Base rules are appended here so they are never overridden.
        """
        base_rules = (
            "\n\n=== AI_KAVACH BASE RULES (MANDATORY) ===\n"
            "1. Every claim must cite a specific line number or tool output.\n"
            "2. The 'target' field in final_answer must exactly match the target you were given.\n"
            "   Do not substitute or hallucinate a different path or URL.\n"
            "3. Never invent CVEs. Only reference CVEs returned by the lookup_cve tool.\n"
            "4. Respond with ONLY a JSON object per step. No markdown. No extra text.\n"
            "5. If a tool returns an error, reason about it and try a different approach.\n"
            "6. Call final_answer only when you have sufficient evidence to be definitive.\n"
            "7. confidence >= 0.7 requires at least 2 evidence items with line numbers.\n"
            "8. confidence >= 0.9 requires at least 2 timeline events.\n"
        )
        return self.system_prompt + base_rules

    def _build_tool_block(self) -> str:
        """
        Builds the tool list block injected into the first user message.
        local LLM reads this to know which tools exist and how to call them.
        """
        if not self._available_tools:
            return "AVAILABLE TOOLS: None. Proceed directly to final_answer.\n"

        lines = ["AVAILABLE TOOLS:", ""]
        for tool in self._available_tools:
            lines.append(f"Tool: {tool['name']}")
            lines.append(f"  Description: {tool['description']}")
            lines.append(f"  Parameters:")
            for param_name, param_desc in tool.get("parameters", {}).items():
                lines.append(f"    {param_name}: {param_desc}")
            lines.append("")

        lines.append(
            'To call a tool, respond with: '
            '{"thought": "...", "action": "tool_name", "action_input": {params}}'
        )
        lines.append(
            'To finish, respond with: '
            '{"thought": "...", "action": "final_answer", "action_input": {findings}}'
        )
        lines.append(
            "\nCRITICAL: You may ONLY call tools from the list above."
            "\nIf you call any tool not listed above, the system will return an error."
            "\nIf no tools are available, call final_answer immediately."
            "\nDo NOT invent tool names. Do NOT call read_log_file for code analysis."
            "\nDo NOT call web tools from a code agent stage."
        )

        return "\n".join(lines)

    
    
    

    def _call_model(self, messages: list[dict]) -> Optional[str]:
        """
        Call local LLM via Ollama HTTP API.

        Uses /api/chat endpoint with the full message history.
        Returns raw response content string, or None on failure.

        Args:
            messages: Full conversation history in OpenAI format.

        Returns:
            Raw model response string, or None if call failed.
        """
        try:
            with httpx.Client(timeout=LOCAL_LLM_TIMEOUT) as client:
                response = client.post(
                    f"{LOCAL_LLM_URL}/api/chat",
                    json={
                        "model": LOCAL_LLM_MODEL,
                        "messages": messages,
                        "stream": False,
                        "options": {
                            "temperature": LOCAL_LLM_TEMPERATURE,
                            "num_predict": LOCAL_LLM_MAX_TOKENS,
                        },
                    },
                )

            if response.status_code != 200:
                logger.error(
                    f"[{self.task_id}] Ollama returned HTTP {response.status_code}: "
                    f"{response.text[:200]}"
                )
                return None

            data = response.json()
            content = data.get("message", {}).get("content", "")

            if not content:
                logger.warning(f"[{self.task_id}] Ollama returned empty content")
                return None

            return content

        except httpx.TimeoutException:
            logger.error(
                f"[{self.task_id}] Ollama timeout after {LOCAL_LLM_TIMEOUT}s"
            )
            return None
        except Exception as e:
            logger.error(f"[{self.task_id}] Ollama call failed: {e}")
            return None

    
    
    

    def _parse_response(self, raw: str) -> tuple[Optional[dict], Optional[str]]:
        """
        Parse local LLM's raw response into a structured dict.

        Handles common model output issues:
        - JSON wrapped in markdown code fences (```json ... ```)
        - Leading/trailing whitespace
        - Thinking tags from local LLM style models (<think>...</think>)
        - JSON embedded in prose

        Args:
            raw: Raw string from local LLM.

        Returns:
            (parsed_dict, None) on success
            (None, error_string) on failure
        """
        if not raw or not raw.strip():
            return None, "Empty response"

        text = raw.strip()

        
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

        
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        text = text.strip()

        
        try:
            parsed = json.loads(text)
            return self._validate_parsed_structure(parsed)
        except json.JSONDecodeError:
            pass

        
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(0))
                return self._validate_parsed_structure(parsed)
            except json.JSONDecodeError:
                pass

        return None, f"Could not parse JSON from response: {text[:200]}"

    def _validate_parsed_structure(self, parsed: dict) -> tuple[Optional[dict], Optional[str]]:
        """
        Validate that a parsed dict has the required ReAct keys.

        Args:
            parsed: Dict from JSON parse.

        Returns:
            (parsed, None) if valid
            (None, error_string) if missing required keys
        """
        if not isinstance(parsed, dict):
            return None, "Response is not a JSON object"

        if "action" not in parsed:
            return None, "Response missing required key 'action'"

        if "action_input" not in parsed:
            return None, "Response missing required key 'action_input'"

        
        parsed.setdefault("thought", "")

        return parsed, None

    
    
    

    def _validate_final_answer(self, final_answer: dict) -> list[str]:
        """
        Validate final_answer against Schema 1.0.0 consistency rules.

        Args:
            final_answer: The action_input dict when action == "final_answer"

        Returns:
            List of error strings. Empty list means validation passed.
        """
        errors = []
        for rule_fn, error_msg in VALIDATION_RULES:
            try:
                if not rule_fn(final_answer):
                    errors.append(error_msg)
            except Exception:
                pass  

        
        expected_target = self.target
        actual_target = final_answer.get("target", "")
        if (
            expected_target
            and actual_target
            and actual_target != expected_target
            and expected_target not in actual_target
            and actual_target not in expected_target
        ):
            errors.append(
                f"target field '{actual_target}' does not match "
                f"the given target '{expected_target}'. "
                f"Set target to exactly: {expected_target}"
            )

        return errors

    
    
    

    def _collect_evidence(self, tool_name: str, result: dict) -> None:
        """
        Extract evidence strings from tool results and add to session memory.

        Args:
            tool_name: Which tool produced this result.
            result:    Normalized tool output dict.
        """
        if result.get("status") not in {"success", "success_no_findings"}:
            return

        data = result.get("data", {})

        
        if tool_name == "check_sqli_patterns":
            for match in data.get("matched_lines", []):
                line_num = match.get("line", "?")
                content = match.get("content", "")
                category = match.get("category", "")
                evidence = f"Line {line_num}: [{category.upper()}] {content[:200]}"
                self.memory.add_evidence(evidence)

        
        elif tool_name == "read_log_file":
            summary = result.get("summary", "")
            if summary:
                self.memory.add_evidence(f"[log_reader] {summary}")

        
        elif tool_name == "lookup_cve":
            cve_id = data.get("cve_id", "")
            severity = data.get("cvss_severity", "")
            if cve_id:
                self.memory.add_evidence(
                    f"CVE lookup: {cve_id} ({severity}) — "
                    f"{data.get('description', '')[:100]}"
                )

        
        elif tool_name == "run_nuclei":
            for finding in data.get("findings", []):
                self.memory.add_evidence(
                    f"[nuclei] {finding.get('template-id', 'unknown')} "
                    f"at {finding.get('matched-at', '')} "
                    f"(severity: {finding.get('severity', 'unknown')})"
                )

        
        elif tool_name == "check_headers":
            missing = data.get("missing_security_headers", [])
            disclosure = data.get("information_disclosure", [])
            if missing:
                self.memory.add_evidence(
                    f"[header_checker] Missing security headers: {', '.join(missing)}"
                )
            for d in disclosure:
                self.memory.add_evidence(f"[header_checker] Information disclosure: {d}")

        
        elif tool_name == "check_ssl":
            issues = data.get("issues", [])
            for issue in issues:
                self.memory.add_evidence(f"[ssl_checker] {issue}")

        
        elif tool_name in {"run_semgrep", "run_bandit"}:
            findings = data.get("findings", []) if isinstance(data, dict) else []
            for finding in findings[:100]:
                if not isinstance(finding, dict):
                    continue
                file_path = finding.get("file") or finding.get("path") or "unknown"
                line = finding.get("line") or finding.get("line_number") or "?"
                sev = finding.get("severity", "unknown")
                ftype = finding.get("type") or finding.get("test_id") or finding.get("rule_id") or "finding"
                msg = finding.get("message") or finding.get("issue_text") or ""
                self.memory.add_evidence(
                    f"[{tool_name}] {file_path}:{line} [{sev}] {ftype} {msg[:180]}"
                )

    def _sanitize_tool_action_input(self, action: str, action_input: dict) -> dict:
        """Repair common LLM tool-call drift without hardcoding targets."""
        if not isinstance(action_input, dict):
            return {}

        fixed = dict(action_input)
        default_path = self.memory.log_path or self.target or ""

        if action in {"run_semgrep", "run_bandit"}:
            raw_path = str(fixed.get("path", "")).strip()
            if not raw_path or raw_path in {".", "./", "path/to/source/code"}:
                if default_path:
                    fixed["path"] = default_path

        if action == "run_semgrep":
            if "rulesets" not in fixed:
                drift_value = fixed.get("ruleset") or fixed.get("rules")
                if drift_value:
                    if isinstance(drift_value, list):
                        rulesets = [str(x) for x in drift_value if str(x).strip()]
                    else:
                        rulesets = [str(drift_value)]

                    alias = {
                        "owasp-top10": "owasp-top-ten",
                        "owasp-top-ten": "owasp-top-ten",
                        "security-audit": "security-audit",
                        "secrets": "secrets",
                        "python": "python",
                    }
                    normalized = []
                    for rs in rulesets:
                        key = rs.strip().lower()
                        normalized.append(alias.get(key, rs.strip()))
                    fixed["rulesets"] = normalized

            fixed.pop("ruleset", None)
            fixed.pop("rules", None)

        return fixed

    
    
    

    def _detect_rag_gaps(self, tool_name: str, result: dict) -> None:
        """
        Detect knowledge gaps from tool results and record them for Report B.
        uses these to update PC3 ChromaDB.

        Args:
            tool_name: Which tool ran.
            result:    Normalized tool output.
        """
        data = result.get("data", {})

        
        if tool_name in ("check_sqli_patterns", "read_log_file"):
            unknown_agents = data.get("unknown_user_agents", [])
            for agent in unknown_agents:
                self._rag_gaps.append(
                    f"Unknown user agent in logs — not in scanner signatures: {agent}"
                )

        
        if tool_name == "lookup_cve" and result.get("status") == "success":
            if not data.get("cve_id"):
                query = data.get("query", "")
                self._rag_gaps.append(
                    f"CVE lookup returned no results for: {query}. "
                    f"ChromaDB may need updated CVE knowledge."
                )

        
        if tool_name == "run_nuclei":
            for finding in data.get("findings", []):
                if not finding.get("cve") and finding.get("severity") in ("critical", "high"):
                    self._rag_gaps.append(
                        f"Nuclei finding '{finding.get('template-id')}' "
                        f"has no CVE mapping — consider adding to knowledge base"
                    )

    
    
    

def _now() -> str:
    """Returns current UTC time as ISO8601 string."""
    return datetime.now(timezone.utc).isoformat()

"""Session state for the Code Agent pipeline."""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SessionMemory:
    def __init__(
        self,
        task_id: str,
        task: str,
        target: Optional[str] = None,
        log_path: Optional[str] = None,
        mode: Optional[str] = None,
    ):
        self.task_id = task_id
        self.task = task
        self.mode = mode
        self.created_at = _now()
        self.target = target
        self.log_path = log_path
        self.scope: list[str] = []
        self.out_of_scope: list[str] = []
        self.http_targets: list[str] = []

        self.code_sandbox_state: Optional[dict] = None
        self.code_sast_findings: Optional[dict] = None
        self.code_dast_findings: Optional[dict] = None
        self.code_fuzzer_findings: Optional[dict] = None
        self.code_secrets_findings: Optional[dict] = None
        self.code_dependency_findings: Optional[dict] = None
        self.code_patch_output: Optional[dict] = None

        self._evidence_set: set[str] = set()
        self.all_evidence: list[str] = []
        self.step_history: list[dict] = []
        self.tools_used: set[str] = set()
        self.tool_call_log: list[dict] = []
        self.tools_not_available: list[str] = []
        self.clarifications: list[dict] = []
        self.parse_failures = 0
        self.parse_failure_details: list[dict] = []
        self.rag_gaps: list[str] = []
        self.model_struggles: list[str] = []
        self.retries_used = 0
        self._current_stage: Optional[str] = None
        self._current_step = 0
        self._stage_timings: dict[str, dict] = {}
        self._run_start = time.time()

    def begin_stage(self, stage: str) -> None:
        self._current_stage = stage
        self._current_step = 0
        self._stage_timings[stage] = {
            "started_at": _now(),
            "start_ts": time.time(),
            "completed_at": None,
            "duration_seconds": None,
            "steps": 0,
        }

    def end_stage(self, stage: str) -> None:
        if stage not in self._stage_timings:
            return
        duration = round(time.time() - self._stage_timings[stage]["start_ts"], 2)
        self._stage_timings[stage]["completed_at"] = _now()
        self._stage_timings[stage]["duration_seconds"] = duration
        self._stage_timings[stage]["steps"] = self._current_step

    def record_step(self, thought: str, action: str, action_input: dict, observation: str, step_number: int) -> None:
        self._current_step = step_number
        entry = {
            "step": step_number,
            "stage": self._current_stage,
            "thought": thought,
            "action": action,
            "action_input": self._sanitize_params(action_input),
            "observation": observation,
            "timestamp": _now(),
        }
        self.step_history.append(entry)

    def update_last_observation(self, observation: str) -> None:
        if self.step_history:
            self.step_history[-1]["observation"] = observation

    def add_evidence(self, evidence: str) -> None:
        if not evidence:
            return
        digest = hashlib.sha256(evidence.encode("utf-8", errors="ignore")).hexdigest()
        if digest not in self._evidence_set:
            self._evidence_set.add(digest)
            self.all_evidence.append(evidence)

    def add_evidence_batch(self, evidence_items: list[str]) -> None:
        for item in evidence_items:
            self.add_evidence(item)

    def record_tool_call(self, tool_name: str, params: dict, result: dict, duration_ms: float = 0, **kwargs) -> None:
        self.tools_used.add(tool_name)
        self.tool_call_log.append({
            "tool": tool_name,
            "params": self._sanitize_params(params),
            "status": result.get("status") if isinstance(result, dict) else None,
            "result": result,
            "duration_ms": duration_ms,
            "timestamp": _now(),
            **{k: v for k, v in kwargs.items() if k not in {"tool", "params", "result"}},
        })

    def record_clarification(self, question: str, reason: str, answer: str, action: str = "continue") -> None:
        self.clarifications.append({
            "question": question,
            "reason": reason,
            "answer": answer,
            "action": action,
            "timestamp": _now(),
        })

    def record_parse_failure(self, raw: str, agent_type: str, step: int) -> None:
        self.parse_failures += 1
        self.parse_failure_details.append({
            "agent_type": agent_type,
            "step": step,
            "raw_prefix": (raw or "")[:1000],
            "timestamp": _now(),
        })

    def record_rag_gap(self, gap: str) -> None:
        if gap:
            self.rag_gaps.append(gap)

    def record_model_struggle(self, detail: str) -> None:
        if detail:
            self.model_struggles.append(detail)

    def set_target(self, target: str) -> None:
        self.target = target

    def set_log_path(self, path: str) -> None:
        self.log_path = path

    def add_to_scope(self, item: str) -> None:
        if item and item not in self.scope:
            self.scope.append(item)

    def add_out_of_scope(self, item: str) -> None:
        if item and item not in self.out_of_scope:
            self.out_of_scope.append(item)

    def is_in_scope(self, item: str) -> bool:
        if item in self.out_of_scope:
            return False
        if not self.scope:
            return True
        return any(item.startswith(s) or s in item for s in self.scope)

    @property
    def total_steps(self) -> int:
        return len(self.step_history)

    @property
    def stages_completed(self) -> list[str]:
        fields = {
            "code_sandbox": self.code_sandbox_state,
            "code_sast": self.code_sast_findings,
            "code_dast": self.code_dast_findings,
            "code_fuzzer": self.code_fuzzer_findings,
            "code_secrets": self.code_secrets_findings,
            "code_dependency": self.code_dependency_findings,
            "code_patch": self.code_patch_output,
        }
        return [stage for stage, value in fields.items() if value is not None]

    @property
    def highest_confidence(self) -> float:
        values = []
        for value in (
            self.code_sandbox_state,
            self.code_sast_findings,
            self.code_dast_findings,
            self.code_fuzzer_findings,
            self.code_secrets_findings,
            self.code_dependency_findings,
            self.code_patch_output,
        ):
            if isinstance(value, dict) and isinstance(value.get("confidence"), (int, float)):
                values.append(float(value["confidence"]))
        return max(values, default=0.0)

    @property
    def run_duration_seconds(self) -> float:
        return round(time.time() - self._run_start, 2)

    def get_summary(self) -> dict:
        return {
            "task_id": self.task_id,
            "task": self.task,
            "mode": self.mode,
            "target": self.target,
            "log_path": self.log_path,
            "created_at": self.created_at,
            "run_duration_seconds": self.run_duration_seconds,
            "stages_completed": self.stages_completed,
            "stage_timings": self._stage_timings,
            "total_steps": self.total_steps,
            "evidence_count": len(self.all_evidence),
            "highest_confidence": self.highest_confidence,
            "tools_used": sorted(self.tools_used),
            "tools_not_available": self.tools_not_available,
            "tool_call_count": len(self.tool_call_log),
            "parse_failures": self.parse_failures,
            "retries_used": self.retries_used,
            "rag_gaps": self.rag_gaps,
            "model_struggles": self.model_struggles,
            "clarifications_requested": len(self.clarifications),
            "scope": self.scope,
            "out_of_scope": self.out_of_scope,
        }

    def get_context_for_stage(self, stage: str) -> str:
        fields = [
            ("code_sandbox", self.code_sandbox_state),
            ("code_sast", self.code_sast_findings),
            ("code_dast", self.code_dast_findings),
            ("code_fuzzer", self.code_fuzzer_findings),
            ("code_secrets", self.code_secrets_findings),
            ("code_dependency", self.code_dependency_findings),
            ("code_patch", self.code_patch_output),
        ]
        lines = []
        for name, findings in fields:
            if findings is None or name == stage:
                continue
            lines.append(f"=== {name.upper()} ===")
            lines.append(json.dumps(findings, ensure_ascii=False, default=str)[:6000])
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"SessionMemory(task_id={self.task_id!r}, mode={self.mode!r}, "
            f"stages={self.stages_completed}, steps={self.total_steps}, "
            f"confidence={self.highest_confidence:.2f})"
        )

    @staticmethod
    def _sanitize_params(params: object) -> object:
        try:
            json.dumps(params)
            return params
        except TypeError:
            return str(params)

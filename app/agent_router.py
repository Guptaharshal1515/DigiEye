"""Routes Code Agent modes to their execution stages."""

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from agents.code.code_agent import CodeAgent
from agents.code.dast import DASTAgent
from agents.code.dependency_audit import DependencyAuditAgent
from agents.code.fuzzer import FuzzerAgent
from agents.code.patch_agent import PatchAgent
from agents.code.sandbox_agent import SandboxAgent
from agents.code.sast import SASTAgent
from agents.code.secret_scanner import SecretScannerAgent


from app.config import MAX_STEPS
from app.environment_probe import probe_environment
from app.report_generator import generate_report
from app.session_memory import SessionMemory
from tools.cve_lookup import lookup_cve
from tools.execution_models import normalize_tool_status
from tools.target_utils import extract_http_targets

logger = logging.getLogger("ai_kavach.router")





VALID_MODES = {
    "code_analysis",
    "code_dast",
    "code_defense",
    "code_pipeline",
    "code_analysis_red",
    "code_analysis_blue",
    "code_analysis_red_blue",
    "full",
    "auto",
    "code_sast",
    "code_dast",
    "code_fuzzer",
    "code_secrets",
    "code_dependency",
    "code_patch",
    "code_sandbox",
    "code_full",
}



MODE_PIPELINES = {
    "code_analysis": ["code_analysis"],
    "code_dast": ["code_dast"],
    "code_defense": ["code_defense"],
    "code_pipeline": ["code_pipeline"],
    "code_analysis_red": ["code_analysis", "code_dast"],
    "code_analysis_blue": ["code_analysis", "code_defense"],
    "code_analysis_red_blue": ["code_analysis", "code_dast", "code_defense"],
    "full": ["code_analysis", "code_dast", "code_defense", "code_pipeline"],
    "code_sast": ["code_sast"],
    "code_dast": ["code_sandbox", "code_dast"],
    "code_fuzzer": ["code_sandbox", "code_fuzzer"],
    "code_secrets": ["code_secrets"],
    "code_dependency": ["code_dependency"],
    "code_patch": ["code_sandbox", "code_patch"],
    "code_sandbox": ["code_sandbox"],
    "code_full": [
        "code_sandbox",
        "code_sast",
        "code_dast",
        "code_fuzzer",
        "code_secrets",
        "code_dependency",
        "code_patch",
    ],
    
}






def route(
    task: str,
    task_id: str,
    mode: str,
    target: Optional[str] = None,
    log_path: Optional[str] = None,
    max_steps: int = MAX_STEPS,
) -> dict:
    """
    Main routing function called by agent_server.py.

    Selects the correct agent pipeline based on mode, runs each stage
    in order, passes findings between stages via SessionMemory, and
    returns a unified result dict.

    Args:
        task:       Natural language task description from .
        task_id:    Unique run identifier injected by .
        mode:       One of VALID_MODES.
        target:     Optional explicit target URL or IP override.
        log_path:   Optional explicit log file path override.
        max_steps:  Maximum ReAct steps per agent stage.

    Returns:
        Unified result dict with keys:
            success, task_id, mode, pipeline_run,
            final_answer, report_A, report_B,
            stages, steps_taken, duration_seconds,
            tools_used, error
    """
    router_start = time.time()

    logger.info(f"[{task_id}] CHECKPOINT 1 | Request received | mode={mode}")

    
    if mode not in VALID_MODES:
        return _error_result(
            task_id, mode, f"Unknown mode '{mode}'. Valid modes: {sorted(VALID_MODES)}"
        )

    
    if mode == "auto":
        mode = _resolve_auto_mode(task, task_id)
        logger.info(f"[{task_id}] Auto mode resolved to: {mode}")

    logger.info(f"[{task_id}] CHECKPOINT 2 | Mode resolved | mode={mode}")

    
    memory = SessionMemory(
        task_id=task_id,
        task=task,
        target=target,
        log_path=log_path,
        mode=mode,
    )

    if mode.startswith("code_") and not memory.target:
        extracted_target = _extract_target(task, include_paths=True)
        if extracted_target:
            memory.set_target(extracted_target)
            memory.set_log_path(extracted_target)
            memory.add_to_scope(extracted_target)
            logger.info(f"[{task_id}] {mode} target resolved from task: {extracted_target}")

    memory.http_targets = extract_http_targets(task)
    logger.info(f"[{task_id}] CHECKPOINT 3 | Target resolved | target={memory.target} | http_targets={memory.http_targets}")

    
    pipeline = MODE_PIPELINES[mode]
    stage_results = {}
    all_steps = 0
    all_tools = set()

    logger.info(f"[{task_id}] Pipeline: {' → '.join(pipeline)}")

    for stage in pipeline:
        logger.info(f"[{task_id}] CHECKPOINT 4 | Stage initialized | stage={stage}")
        memory.begin_stage(stage)

        stage_result = _run_stage(
            stage=stage,
            task=task,
            task_id=task_id,
            memory=memory,
            max_steps=max_steps,
        )

        stage_results[stage] = stage_result
        all_steps += stage_result.get("steps_taken", 0)
        all_tools.update(stage_result.get("tools_used", []))

        memory.end_stage(stage)

        
        _store_stage_findings(stage, stage_result, memory)

        logger.info(f"[{task_id}] CHECKPOINT 10 | Findings aggregated | stage={stage}")

        
        if stage_result.get("success"):
            confidence = stage_result.get("confidence", 0.0)
            logger.info(
                f"[{task_id}] CHECKPOINT 11 | Stage completed | stage={stage} | confidence={confidence:.2f}"
            )
        else:
            logger.warning(
                f"[{task_id}] Stage '{stage}' failed: {stage_result.get('error')}"
            )

    
    duration = round(time.time() - router_start, 2)
    final_answer = _merge_findings(stage_results, task_id, mode, memory)
    final_answer = _enrich_findings_with_cve(final_answer)
    report_A = _build_report_A(final_answer, task_id, mode)
    report_B = _build_report_B(
        stage_results, task_id, mode, all_steps, all_tools, duration
    )

    tool_exec_summary = _summarize_tool_execution(memory)

    report_artifacts = None
    if mode.startswith("code_"):
        report_artifacts = _generate_code_sast_reports(
            final_answer=final_answer,
            task_id=task_id,
            output_dir=memory.log_path,
            tool_execution_summary=tool_exec_summary,
        )

    logger.info(f"[{task_id}] CHECKPOINT 12 | Report generated")

    overall_success = any(r.get("success") for r in stage_results.values())

    result = {
        "success": overall_success,
        "task_id": task_id,
        "mode": mode,
        "pipeline_run": pipeline,
        "final_answer": final_answer,
        "report_A": report_A,
        "report_B": report_B,
        "stages": stage_results,
        "steps_taken": all_steps,
        "duration_seconds": duration,
        "tools_used": sorted(all_tools),
        "tool_execution": tool_exec_summary,
        "error": None,
        "report_artifacts": report_artifacts,
    }

    logger.info(
        f"[{task_id}] Routing complete | "
        f"stages={len(stage_results)} | "
        f"steps={all_steps} | "
        f"duration={duration}s"
    )

    return result







def _run_stage(
    stage: str,
    task: str,
    task_id: str,
    memory: SessionMemory,
    max_steps: int,
) -> dict:
    target = memory.target or _extract_target(task, include_paths=True)
    stage_target = target or memory.log_path or ""

    agents = {
        "code_sandbox": SandboxAgent,
        "code_sast": SASTAgent,
        "code_dast": DASTAgent,
        "code_fuzzer": FuzzerAgent,
        "code_secrets": SecretScannerAgent,
        "code_dependency": DependencyAuditAgent,
        "code_patch": PatchAgent,
        "code_orchestrator": CodeAgent,
    }

    agent_class = agents.get(stage)
    if agent_class is None:
        return _stage_error(stage, f"Unknown code stage: {stage}")

    try:
        agent = agent_class(
            task_id=task_id,
            target=stage_target,
            session_memory=memory,
        )
        result = agent.run(task_prompt=task, max_steps=max_steps)
        result.setdefault("stage", stage)
        result.setdefault("status", "success" if result.get("success") else "failed")
        if result.get("tools_not_available") and result.get("status") == "failed":
            result["status"] = "partial"
        if not result.get("tools_used") and not result.get("success") and not result.get("error"):
            result["status"] = "skipped"
        return result
    except Exception as e:
        logger.exception(f"[{task_id}] Stage '{stage}' failed")
        return _stage_error(stage, str(e))


def _store_stage_findings(stage: str, result: dict, memory: SessionMemory) -> None:
    findings = result.get("final_answer", {})
    if not findings:
        return

    mapping = {
        "code_sandbox": "code_sandbox_state",
        "code_sast": "code_sast_findings",
        "code_dast": "code_dast_findings",
        "code_fuzzer": "code_fuzzer_findings",
        "code_secrets": "code_secrets_findings",
        "code_dependency": "code_dependency_findings",
        "code_patch": "code_patch_output",
    }
    attr = mapping.get(stage)
    if attr:
        setattr(memory, attr, findings)



def _resolve_auto_mode(task: str, task_id: str) -> str:
    return "code_full"


def _merge_findings(
    stage_results: dict,
    task_id: str,
    mode: str,
    memory: SessionMemory,
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return _merge_code_pipeline_findings(stage_results, task_id, mode, memory, now)


def _merge_code_pipeline_findings(
    stage_results: dict,
    task_id: str,
    mode: str,
    memory: SessionMemory,
    now: str,
) -> dict:
    """Build canonical final_answer for all code_* modes."""
    canonical = []
    language = "unknown"
    patches = []
    verification_results = []
    errors = []
    warnings = []

    for stage_name, stage in stage_results.items():
        if not isinstance(stage, dict):
            continue
        fa = stage.get("final_answer", {}) or {}
        if not isinstance(fa, dict):
            continue

        stage_vulns = fa.get("vulnerabilities", []) if isinstance(fa.get("vulnerabilities"), list) else []
        stage_findings = fa.get("findings", []) if isinstance(fa.get("findings"), list) else []
        canonical.extend(stage_vulns or stage_findings)

        if language == "unknown" and fa.get("language"):
            language = fa.get("language")

        if isinstance(fa.get("patches"), list):
            patches.extend(fa.get("patches", []))
        if isinstance(fa.get("verification_results"), list):
            verification_results.extend(fa.get("verification_results", []))
        if isinstance(fa.get("errors"), list):
            errors.extend(fa.get("errors", []))
        if isinstance(fa.get("warnings"), list):
            warnings.extend(fa.get("warnings", []))

    
    
    canonical.extend(_extract_code_findings_from_memory(memory))

    
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}

    def _norm_file(value: str) -> str:
        p = str(value or "").replace("\\", "/").lower()
        idx = p.find("/ai_kavach/")
        return p[idx:] if idx >= 0 else p

    deduped = {}
    for item in canonical:
        if not isinstance(item, dict):
            continue
        key = (
            _norm_file(item.get("file", "")),
            int(item.get("line", 0) or 0),
            str(item.get("type", "")).strip().lower(),
        )
        if key not in deduped:
            deduped[key] = dict(item)
            continue

        existing = deduped[key]

        
        existing_sources = set(existing.get("tool_sources", []) or [])
        new_sources = set(item.get("tool_sources", []) or [])
        existing["tool_sources"] = sorted(existing_sources | new_sources)

        
        src_sev = dict(existing.get("source_severities", {}) or {})
        src_sev.update(item.get("source_severities", {}) or {})
        existing["source_severities"] = src_sev

        
        merged_sev = existing.get("severity", "unknown")
        for sv in src_sev.values():
            if severity_rank.get(str(sv).lower(), 0) > severity_rank.get(str(merged_sev).lower(), 0):
                merged_sev = str(sv).lower()
        existing["severity"] = merged_sev

        
        ev_old = str(existing.get("evidence", "") or "")
        ev_new = str(item.get("evidence", "") or "")
        if ev_new and ev_new not in ev_old:
            existing["evidence"] = f"{ev_old}\n---\n{ev_new}" if ev_old else ev_new

    canonical = list(deduped.values())

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    affected_files = set()
    tools_used = set()
    evidence = []

    for v in canonical:
        if not isinstance(v, dict):
            continue
        sev = str(v.get("severity", "unknown")).lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        fpath = v.get("file")
        if fpath:
            affected_files.add(fpath)

        for tool in v.get("tool_sources", []) or []:
            tools_used.add(tool)

        ev = v.get("evidence")
        if ev and ev not in evidence:
            evidence.append(ev)

    confidence = 0.0
    confidence_reasons = []
    for stage_name, stage_result in stage_results.items():
        stage_conf = float(stage_result.get("confidence", 0.0) or 0.0)
        if stage_conf > confidence:
            confidence = stage_conf
        fa_stage = stage_result.get("final_answer", {}) or {}
        if isinstance(fa_stage, dict) and fa_stage.get("confidence_reasoning"):
            confidence_reasons.append(f"[{stage_name}] {fa_stage.get('confidence_reasoning')}")

    confidence_reasoning = " | ".join(confidence_reasons) or (
        "Confidence derived from normalized code-stage findings and corroboration."
        if canonical
        else "No confirmed findings collected from executed code security stages."
    )

    return {
        "schema_version": "1.0.0",
        "agent": "code_orchestrator" if mode == "code_full" else mode,
        "task_id": task_id,
        "timestamp": now,
        "target": memory.target or "",
        "mode": mode,
        "assessment_type": mode,
        "language": language,
        "vulnerabilities": canonical,
        "findings": canonical,
        "severity_counts": severity_counts,
        "affected_files": sorted(affected_files),
        "tools_used": sorted(tools_used),
        "patches": patches,
        "verification_results": verification_results,
        "confidence": confidence,
        "confidence_reasoning": confidence_reasoning,
        "evidence": evidence,
        "errors": errors,
        "warnings": warnings,
        "scope_notes": f"Pipeline run: {' → '.join(stage_results.keys())}",
    }







def _build_report_A(final_answer: dict, task_id: str, mode: str) -> str:
    fa = final_answer
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Code Security Assessment Report",
        f"**Target:** {fa.get('target', 'Unknown')}",
        f"**Date:** {now}",
        f"**Assessment Type:** {mode.replace('_', ' ').title()}",
        f"**Confidence:** {int(float(fa.get('confidence', 0)) * 100)}%",
        "",
        "## Findings",
        "",
    ]

    vulnerabilities = fa.get("vulnerabilities", []) or fa.get("findings", [])
    if not vulnerabilities:
        lines.append("No confirmed vulnerabilities were collected from the executed stages.")
    else:
        for i, v in enumerate(vulnerabilities, 1):
            lines += [
                f"### {i}. {v.get('type', 'Unknown vulnerability')}",
                f"- **Severity:** {v.get('severity', 'unknown')}",
                f"- **File:** {v.get('file', 'N/A')}",
                f"- **Line:** {v.get('line', 'N/A')}",
                f"- **CWE:** {v.get('cwe', 'N/A')}",
                f"- **Evidence:** {v.get('evidence', 'N/A')}",
                f"- **Remediation:** {v.get('remediation', 'N/A')}",
                "",
            ]

    lines += [
        "## Tool Execution",
        "",
        f"- Tools used: {', '.join(fa.get('tools_used', [])) or 'None'}",
        f"- Affected files: {len(fa.get('affected_files', []))}",
        f"- Severity counts: {json.dumps(fa.get('severity_counts', {}))}",
        "",
    ]

    errors = fa.get("errors", [])
    warnings = fa.get("warnings", [])
    if errors:
        lines += ["## Errors", ""] + [f"- {e}" for e in errors] + [""]
    if warnings:
        lines += ["## Warnings", ""] + [f"- {w}" for w in warnings] + [""]

    return "\n".join(lines)


def _build_report_B(
    stage_results: dict,
    task_id: str,
    mode: str,
    total_steps: int,
    all_tools: set,
    duration: float,
) -> dict:
    """
    Builds the internal machine-readable report (Report B).
    reads this to update PC3 RAG and queue fine-tuning examples.
    """
    rag_gaps = []
    model_struggles = []
    tools_not_available = []
    parse_failures = 0
    clarifications = 0
    confidence_achieved = 0.0
    confidence_target = 0.9

    for stage, result in stage_results.items():
        parse_failures += result.get("parse_failures", 0)
        clarifications += result.get("clarifications_requested", 0)

        stage_conf = result.get("confidence", 0.0)
        if stage_conf > confidence_achieved:
            confidence_achieved = stage_conf

        
        for t in result.get("tools_not_available", []):
            tools_not_available.append(
                f"{t} — not installed on during {stage} stage"
            )

        
        for gap in result.get("rag_gaps", []):
            rag_gaps.append(f"[{stage}] {gap}")

        
        for struggle in result.get("model_struggles", []):
            model_struggles.append(f"[{stage}] {struggle}")

    
    suggested_rag_updates = []
    for gap in rag_gaps:
        suggested_rag_updates.append(
            f"Update ChromaDB collection with knowledge covering: {gap}"
        )

    skipped_stages = []
    stage_errors = []
    for s, r in stage_results.items():
        if r.get("error"):
            stage_errors.append(f"{s}: {r.get('error')}")
        if not r.get("tools_used") and not r.get("success"):
            skipped_stages.append({"stage": s, "reason": r.get("error") or "no tool execution"})

    return {
        "schema_version": "1.0.0",
        "task_id": task_id,
        "agent": "code_orchestrator",
        "mode": mode,
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "stages_run": list(stage_results.keys()),
        "stages_succeeded": [s for s, r in stage_results.items() if r.get("success")],
        "stages_failed": [s for s, r in stage_results.items() if not r.get("success")],
        "stages_skipped": skipped_stages,
        "stage_errors": stage_errors,
        "steps_taken": total_steps,
        "duration_seconds": duration,
        "tools_used": sorted(all_tools),
        "tools_not_available": tools_not_available,
        "parse_failures": parse_failures,
        "clarifications_requested": clarifications,
        "rag_gaps": rag_gaps,
        "model_struggles": model_struggles,
        "suggested_rag_updates": suggested_rag_updates,
        "confidence_achieved": confidence_achieved,
        "confidence_target": confidence_target,
        "why_confidence_not_higher": (
            "Insufficient evidence collected across pipeline stages."
            if confidence_achieved < confidence_target
            else "Confidence target met."
        ),
    }







def _summarize_tool_execution(memory: SessionMemory) -> dict:
    calls = memory.tool_call_log if isinstance(memory.tool_call_log, list) else []

    tools_attempted = []
    tools_succeeded = []
    tools_failed = []
    tools_unavailable = []
    tool_execution_details = []

    for entry in calls:
        tool = str(entry.get("tool", "")).strip()
        status = normalize_tool_status(str(entry.get("status", "unknown")).strip().lower())
        if not tool:
            continue

        if tool not in tools_attempted:
            tools_attempted.append(tool)

        if status in {"success", "success_no_findings"}:
            if tool not in tools_succeeded:
                tools_succeeded.append(tool)
        elif status in {"unavailable", "not_configured", "tool_not_allowed", "tool_missing", "not_applicable", "skipped"}:
            if tool not in tools_unavailable:
                tools_unavailable.append(tool)
        else:
            if tool not in tools_failed:
                tools_failed.append(tool)

        tool_execution_details.append(
            {
                "tool_name": tool,
                "stage": entry.get("stage", "unknown"),
                "applicable": "yes",
                "available": "unknown",
                "requested": "yes",
                "execution": status,
                "result": "findings_or_output" if status in {"success", "success_no_findings"} else "-",
                "reason": entry.get("summary", ""),
                "status": status,
                "duration_ms": entry.get("duration_ms"),
                "summary": entry.get("summary", ""),
                "timestamp": entry.get("timestamp"),
            }
        )

    if not tools_attempted:
        overall_status = "incomplete"
    elif tools_failed and not tools_succeeded:
        overall_status = "failed"
    elif tools_unavailable and not tools_succeeded:
        overall_status = "unavailable"
    elif tools_failed or tools_unavailable:
        overall_status = "partial"
    else:
        overall_status = "success"

    return {
        "status": overall_status,
        "tools_attempted": sorted(tools_attempted),
        "tools_executed": sorted(tools_succeeded),
        "tools_succeeded": sorted(tools_succeeded),
        "tools_failed": sorted(tools_failed),
        "tools_unavailable": sorted(tools_unavailable),
        "tool_execution_details": tool_execution_details,
    }


def _generate_code_sast_reports(
    final_answer: dict,
    task_id: str,
    output_dir: Optional[str],
    tool_execution_summary: Optional[dict] = None,
) -> dict:
    """Generate JSON+PDF reports for code_* runs."""
    try:
        findings = final_answer.get("vulnerabilities", [])
        target = final_answer.get("target", "")

        if output_dir:
            report_dir = output_dir
        else:
            report_dir = str(Path(__file__).resolve().parents[1] / "reports")

        summary = {
            "assessment_type": final_answer.get("assessment_type", "code_sast"),
            "severity_counts": final_answer.get("severity_counts", {}),
            "affected_files": final_answer.get("affected_files", []),
            "tools_used": final_answer.get("tools_used", []),
            "patches": final_answer.get("patches", []),
            "verification_results": final_answer.get("verification_results", []),
            "confidence": final_answer.get("confidence", 0.0),
            "errors": final_answer.get("errors", []),
            "warnings": final_answer.get("warnings", []),
            "tool_execution": tool_execution_summary or {},
        }

        generated = generate_report(
            findings=findings,
            target=target,
            task_id=task_id,
            output_dir=report_dir,
            summary=summary,
        )

        return {
            "status": "success",
            "output_dir": report_dir,
            "json_path": generated.get("json_path"),
            "pdf_path": generated.get("pdf_path"),
            "finding_count": generated.get("finding_count", 0),
        }
    except Exception as e:
        logger.exception(f"[{task_id}] code_sast report generation failed")
        return {
            "status": "error",
            "output_dir": output_dir,
            "error": str(e),
        }


def _extract_target(task: str, include_paths: bool = False) -> Optional[str]:
    """
    Extracts a URL/IP target from task text.
    For code_sast, optionally extracts filesystem paths as well.
    """
    import re

    
    url_pattern = r"https?://[\w\-\.]+(?::\d+)?(?:/[\w\-\./?=%&]*)?"
    url_match = re.search(url_pattern, task)
    if url_match:
        return url_match.group(0)

    
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"
    ip_match = re.search(ip_pattern, task)
    if ip_match:
        return ip_match.group(0)

    if include_paths:
        path_candidates = re.findall(r"[A-Za-z]:[\\/][^\s\"'<>]+", task)
        for raw in path_candidates:
            candidate = raw.rstrip(".,;:)\"]}")
            p = Path(candidate)
            if p.exists() and p.is_dir():
                
                tail = p.name.lower()
                if tail not in {"reports", "report", "output", "outputs"}:
                    return str(p)

        for raw in path_candidates:
            candidate = raw.rstrip(".,;:)\"]}")
            p = Path(candidate)
            if p.exists():
                return str(p)

    return None


def _extract_code_findings_from_memory(memory: SessionMemory) -> list[dict]:
    """Recover Semgrep/Bandit findings from tool observations as fallback."""
    import json

    recovered: list[dict] = []
    for step in memory.step_history:
        if not isinstance(step, dict):
            continue
        action = str(step.get("action", ""))
        if action not in {"run_semgrep", "run_bandit"}:
            continue

        obs = step.get("observation")
        if not isinstance(obs, str) or not obs.strip():
            continue

        try:
            obj = json.loads(obs)
        except Exception:
            continue

        data = obj.get("data", {}) if isinstance(obj, dict) else {}
        findings = data.get("findings", []) if isinstance(data, dict) else []
        for f in findings:
            if not isinstance(f, dict):
                continue

            tool = "semgrep" if action == "run_semgrep" else "bandit"
            recovered.append({
                "type": f.get("type") or f.get("test_id") or f.get("rule_id") or "Security Finding",
                "severity": str(f.get("severity", "medium")).lower(),
                "file": f.get("file") or f.get("path") or "",
                "line": int(f.get("line", f.get("line_number", 0)) or 0),
                "message": f.get("message") or f.get("issue_text") or "",
                "evidence": f"[{tool}] {f.get('file') or f.get('path') or ''}:{f.get('line') or f.get('line_number') or '?'} {f.get('message') or f.get('issue_text') or ''}"[:500],
                "tool_sources": [tool],
                "source_severities": {tool: str(f.get("severity", "medium")).lower()},
                "confidence": 0.75,
            })

    return recovered


def _enrich_findings_with_cve(final_answer: dict) -> dict:
    """Centralized CVE enrichment for normalized findings."""
    import re

    findings = final_answer.get("vulnerabilities", [])
    if not isinstance(findings, list) or not findings:
        return final_answer

    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        if finding.get("cve_enrichment"):
            continue

        cve_field = str(finding.get("cve", ""))
        cves = cve_pattern.findall(cve_field)

        if cves:
            cve_id = cves[0].upper()
            try:
                enriched = lookup_cve(cve_id)
                if isinstance(enriched, dict) and not enriched.get("error"):
                    finding["cve_enrichment"] = {
                        "status": "mapped",
                        "cve_id": cve_id,
                        "data": enriched,
                    }
                else:
                    finding["cve_enrichment"] = {
                        "status": "unmapped",
                        "reason": str(enriched.get("error", "lookup returned no confident mapping")) if isinstance(enriched, dict) else "lookup returned no confident mapping",
                    }
            except Exception as e:
                finding["cve_enrichment"] = {"status": "unmapped", "reason": f"lookup failed: {e}"}
            continue

        package = str(finding.get("package", "")).strip()
        version = str(finding.get("current_version", finding.get("version", ""))).strip()
        if package:
            finding["cve_enrichment"] = {
                "status": "unmapped",
                "reason": f"No explicit CVE for package '{package}' version '{version}'",
            }
        else:
            finding["cve_enrichment"] = {
                "status": "unmapped",
                "reason": "No CVE identifier in finding; cannot map confidently",
            }

    final_answer["vulnerabilities"] = findings
    return final_answer


def _confidence_to_severity(confidence: float) -> str:
    """Maps confidence float to severity label for Report A."""
    if confidence >= 0.9:
        return "CRITICAL"
    if confidence >= 0.7:
        return "HIGH"
    if confidence >= 0.5:
        return "MEDIUM"
    if confidence >= 0.3:
        return "LOW"
    return "INCONCLUSIVE"


def _error_result(task_id: str, mode: str, error: str) -> dict:
    """Returns a structured error result when routing fails before any stage runs."""
    return {
        "success": False,
        "task_id": task_id,
        "mode": mode,
        "pipeline_run": [],
        "final_answer": {},
        "report_A": f"# Assessment Failed\n\n**Error:** {error}",
        "report_B": {
            "task_id": task_id,
            "error": error,
            "stages_run": [],
        },
        "stages": {},
        "steps_taken": 0,
        "duration_seconds": 0.0,
        "tools_used": [],
        "error": error,
    }


def _stage_error(stage: str, error: str) -> dict:
    """Returns a structured error result for a single failed stage."""
    return {
        "stage": stage,
        "status": "failed",
        "success": False,
        "final_answer": {},
        "confidence": 0.0,
        "steps_taken": 0,
        "tools_used": [],
        "tools_not_available": [],
        "parse_failures": 0,
        "clarifications_requested": 0,
        "rag_gaps": [],
        "model_struggles": [f"Stage failed to start: {error}"],
        "error": error,
    }

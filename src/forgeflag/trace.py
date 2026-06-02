from __future__ import annotations

from typing import Any

from forgeflag.domain import Finding, Observation, SolverResult


def build_solve_trace_step(
    challenge_id: str,
    step_index: int,
    result: SolverResult,
    prior_observations: tuple[Observation, ...] | list[Observation] = (),
) -> Observation:
    evidence = {
        "step_index": step_index,
        "solver": result.solver,
        "status": result.status,
        "findings": [_finding_summary(finding) for finding in result.findings],
        "flag_candidates": list(result.flag_candidates),
        "made_progress": _made_progress(result),
        "rationale": _rationale_for(result, prior_observations),
        "llm_plan": _matching_llm_plan(result.solver, prior_observations),
    }
    return Observation(
        challenge_id=challenge_id,
        source=result.solver,
        kind="solve_trace_step",
        summary=f"Step {step_index}: {result.solver} completed with {result.status}",
        evidence=evidence,
    )


def trace_steps_from_observations(observations: list[Observation] | tuple[Observation, ...]) -> list[dict[str, Any]]:
    latest_run: list[dict[str, Any]] = []
    previous_index = 0
    for observation in observations:
        if observation.kind != "solve_trace_step":
            continue
        step = _trace_step(observation)
        step_index = step.get("step_index") or 0
        if latest_run and step_index > 0 and (step_index == 1 or step_index <= previous_index):
            latest_run = []
        latest_run.append(step)
        previous_index = step_index
    return sorted(latest_run, key=lambda step: step.get("step_index") or 0)


def shortest_trace_path(flag: str, trace_steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for index, step in enumerate(trace_steps):
        if flag in str(step):
            return trace_steps[: index + 1]
    progress_steps = [step for step in trace_steps if step.get("made_progress")]
    return progress_steps[:5]


def _finding_summary(finding: Finding) -> dict[str, Any]:
    return {
        "solver": finding.solver,
        "finding": finding.finding,
        "confidence": finding.confidence,
        "hypothesis": finding.hypothesis,
        "next_action": finding.next_action,
    }


def _made_progress(result: SolverResult) -> bool:
    if result.flag_candidates:
        return True
    return any(finding.confidence >= 0.7 for finding in result.findings)


def _rationale_for(result: SolverResult, prior_observations: tuple[Observation, ...] | list[Observation]) -> str:
    plan = _matching_llm_plan(result.solver, prior_observations)
    if plan:
        actions = plan.get("next_actions")
        if isinstance(actions, list) and actions:
            return str(actions[0])
        expected = plan.get("expected_evidence")
        if isinstance(expected, list) and expected:
            return f"Collect expected evidence: {expected[0]}"
    for finding in result.findings:
        if finding.next_action:
            return finding.next_action
        if finding.hypothesis:
            return finding.hypothesis
        return finding.finding
    return "Run the scoped solver and preserve any evidence it produces."


def _matching_llm_plan(
    solver_name: str,
    prior_observations: tuple[Observation, ...] | list[Observation],
) -> dict[str, Any]:
    for observation in reversed(prior_observations):
        if observation.kind != "llm_solver_plan":
            continue
        suggested = observation.evidence.get("suggested_solvers")
        if isinstance(suggested, list) and solver_name in suggested:
            return {
                "summary": observation.summary,
                "suggested_solvers": suggested,
                "next_actions": _string_list(observation.evidence.get("next_actions")),
                "tool_hints": _string_list(observation.evidence.get("tool_hints")),
                "expected_evidence": _string_list(observation.evidence.get("expected_evidence")),
                "fallback_plan": _string_list(observation.evidence.get("fallback_plan")),
            }
    return {}


def _trace_step(observation: Observation) -> dict[str, Any]:
    evidence = observation.evidence
    return {
        "step_index": _int_value(evidence.get("step_index")),
        "solver": str(evidence.get("solver") or observation.source),
        "status": str(evidence.get("status") or ""),
        "summary": observation.summary,
        "findings": evidence.get("findings") if isinstance(evidence.get("findings"), list) else [],
        "flag_candidates": _string_list(evidence.get("flag_candidates")),
        "made_progress": bool(evidence.get("made_progress")),
        "rationale": str(evidence.get("rationale") or ""),
        "llm_plan": evidence.get("llm_plan") if isinstance(evidence.get("llm_plan"), dict) else {},
    }


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)][:10]


def _int_value(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0

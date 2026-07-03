from __future__ import annotations

from forgeflag.domain import Finding, Observation


class Observer:
    def __init__(self, confidence_threshold: float = 0.7) -> None:
        self.confidence_threshold = confidence_threshold

    def observe_solver_result(
        self,
        challenge_id: str,
        solver_name: str,
        findings: list[Finding] | tuple[Finding, ...],
        flag_candidates: tuple[str, ...],
    ) -> tuple[Observation, ...]:
        observations: list[Observation] = []
        for finding in findings:
            plan = finding.evidence.get("plan")
            if isinstance(plan, dict):
                observations.append(
                    Observation(
                        challenge_id=challenge_id,
                        source=solver_name,
                        kind="llm_solver_plan",
                        summary=str(plan.get("summary") or finding.finding),
                        evidence={
                            "analysis_mode": _string(plan.get("analysis_mode")),
                            "suggested_solvers": _string_list(plan.get("suggested_solvers")),
                            "next_actions": _string_list(plan.get("next_actions")),
                            "tool_hints": _string_list(plan.get("tool_hints")),
                            "hypotheses": _string_list(plan.get("hypotheses")),
                            "expected_evidence": _string_list(plan.get("expected_evidence")),
                            "artifact_requirements": _string_list(plan.get("artifact_requirements")),
                            "blocked_by_missing_artifacts": _string_list(plan.get("blocked_by_missing_artifacts")),
                            "manual_replay_needed": _string_list(plan.get("manual_replay_needed")),
                            "fallback_plan": _string_list(plan.get("fallback_plan")),
                            "risk_notes": _string_list(plan.get("risk_notes")),
                        },
                    )
                )
            retrieved_knowledge = finding.evidence.get("retrieved_knowledge")
            if isinstance(retrieved_knowledge, list) and retrieved_knowledge:
                observations.append(
                    Observation(
                        challenge_id=challenge_id,
                        source=solver_name,
                        kind="knowledge_retrieval",
                        summary=f"Retrieved {len(retrieved_knowledge)} knowledge blocks for LLM planning",
                        evidence={"items": [item for item in retrieved_knowledge if isinstance(item, dict)][:10]},
                    )
                )
            if finding.confidence < self.confidence_threshold:
                continue
            observations.append(
                Observation(
                    challenge_id=challenge_id,
                    source=solver_name,
                    kind="solver_signal",
                    summary=finding.finding,
                    evidence={
                        "confidence": finding.confidence,
                        "hypothesis": finding.hypothesis,
                        "next_action": finding.next_action,
                    },
                )
            )

        for candidate in flag_candidates:
            observations.append(
                Observation(
                    challenge_id=challenge_id,
                    source=solver_name,
                    kind="flag_candidate",
                    summary=candidate,
                    evidence={"candidate": candidate},
                )
            )

        return tuple(observations)


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)][:10]


def _string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""

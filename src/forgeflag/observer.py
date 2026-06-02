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
                            "suggested_solvers": _string_list(plan.get("suggested_solvers")),
                            "next_actions": _string_list(plan.get("next_actions")),
                            "tool_hints": _string_list(plan.get("tool_hints")),
                            "hypotheses": _string_list(plan.get("hypotheses")),
                            "expected_evidence": _string_list(plan.get("expected_evidence")),
                            "fallback_plan": _string_list(plan.get("fallback_plan")),
                        },
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

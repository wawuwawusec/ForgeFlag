from __future__ import annotations

import json
from typing import Any

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.llm import LLMProvider
from forgeflag.solvers.base import SolverContext


class LLMSolver:
    name = "LLMSolver"
    supported_categories = set(ChallengeCategory)

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    def solve(self, context: SolverContext) -> SolverResult:
        if not self.provider.enabled:
            return SolverResult(self.name, context.challenge.challenge_id, "disabled")

        response = self.provider.generate(_instructions(), _prompt(context))
        plan = _parse_plan(response.content)
        evidence: dict[str, Any] = {
            "provider": self.provider.name,
            "model": self.provider.model,
            "strategy": response.content,
        }
        if plan:
            evidence["plan"] = plan

        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Generated LLM solve strategy",
            evidence=evidence,
            hypothesis="Use the LLM strategy as planning guidance while keeping tool execution scoped and evidence-backed.",
            confidence=0.72 if plan else 0.55,
            next_action=_next_action(plan),
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))


def _instructions() -> str:
    return (
        "You are ForgeFlag's planning model for authorized CTF/lab challenges. "
        "Suggest scoped, evidence-driven next steps only. Do not propose unauthorized access, arbitrary shell exposure, "
        "or unscoped network activity. Prefer reproducible tool workflows and explain what evidence to collect. "
        "When possible, return compact JSON with keys: summary, suggested_solvers, next_actions, tool_hints."
    )


def _prompt(context: SolverContext) -> str:
    challenge = context.challenge
    observations = "\n".join(f"- {observation.kind}: {observation.summary}" for observation in context.observations)
    return "\n".join(
        [
            f"challenge_id: {challenge.challenge_id}",
            f"category: {challenge.category.value}",
            f"title: {challenge.title or ''}",
            f"target: {challenge.target or ''}",
            f"description: {challenge.description or ''}",
            f"tags: {', '.join(challenge.tags)}",
            f"attachments: {', '.join(challenge.attachment_paths)}",
            "shared_observations:",
            observations or "- none",
        ]
    )


def _parse_plan(content: str) -> dict[str, Any]:
    try:
        raw = json.loads(content)
    except json.JSONDecodeError:
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        "summary": _string(raw.get("summary")),
        "suggested_solvers": _string_list(raw.get("suggested_solvers")),
        "next_actions": _string_list(raw.get("next_actions")),
        "tool_hints": _string_list(raw.get("tool_hints")),
    }


def _next_action(plan: dict[str, Any]) -> str:
    actions = plan.get("next_actions") if plan else None
    if isinstance(actions, list) and actions:
        return str(actions[0])
    return "Dispatch scoped specialist solvers and verify every candidate against notebook evidence."


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)][:10]

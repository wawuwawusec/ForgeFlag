from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.knowledge import format_knowledge_blocks, retrieved_knowledge_for
from forgeflag.llm import LLMProvider
from forgeflag.llm_prompts import category_playbook
from forgeflag.solvers.base import SolverContext


@dataclass(frozen=True)
class LLMPlan:
    summary: str = ""
    hypotheses: tuple[str, ...] = ()
    suggested_solvers: tuple[str, ...] = ()
    next_actions: tuple[str, ...] = ()
    tool_hints: tuple[str, ...] = ()
    expected_evidence: tuple[str, ...] = ()
    fallback_plan: tuple[str, ...] = ()

    def to_evidence(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "hypotheses": list(self.hypotheses),
            "suggested_solvers": list(self.suggested_solvers),
            "next_actions": list(self.next_actions),
            "tool_hints": list(self.tool_hints),
            "expected_evidence": list(self.expected_evidence),
            "fallback_plan": list(self.fallback_plan),
        }


class LLMSolver:
    name = "LLMSolver"
    supported_categories = set(ChallengeCategory)

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    def solve(self, context: SolverContext) -> SolverResult:
        if not self.provider.enabled:
            return SolverResult(self.name, context.challenge.challenge_id, "disabled")

        try:
            response = self.provider.generate(_instructions(), _prompt(context))
        except Exception as exc:  # noqa: BLE001 - LLM planning must not block scoped tool solvers.
            return self._unavailable_result(context, str(exc))
        if response.raw.get("status") == "unavailable":
            return self._unavailable_result(context, str(response.raw.get("error") or response.content))

        plan = _parse_plan(response.content)
        evidence: dict[str, Any] = {
            "provider": self.provider.name,
            "model": self.provider.model,
            "strategy": response.content,
        }
        if plan:
            evidence["plan"] = plan.to_evidence()

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

    def _unavailable_result(self, context: SolverContext, error: str) -> SolverResult:
        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="LLM planning unavailable",
            evidence={
                "provider": self.provider.name,
                "model": self.provider.model,
                "error": error,
            },
            hypothesis="The configured LLM could not be used, so ForgeFlag should continue with deterministic solvers.",
            confidence=0.2,
            next_action="Fix the LLM configuration or disable 大模型分析, then rerun if model guidance is needed.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "config_error", (finding,))


def _instructions() -> str:
    return (
        "You are ForgeFlag's planning model for authorized CTF/lab challenges. "
        "Suggest scoped, evidence-driven next steps only. Do not propose unauthorized access, arbitrary shell exposure, "
        "or unscoped network activity. Prefer reproducible tool workflows and explain what evidence to collect. "
        "Return compact JSON with keys: summary, hypotheses, suggested_solvers, next_actions, tool_hints, "
        "expected_evidence, fallback_plan. suggested_solvers must use exact ForgeFlag solver names such as "
        "WebSolver, CryptoSolver, ReverseSolver, PwnSolver, ForensicsSolver, TrafficSolver, MiscSolver, or InfraSolver."
    )


def _prompt(context: SolverContext) -> str:
    challenge = context.challenge
    observations = "\n".join(f"- {observation.kind}: {observation.summary}" for observation in context.observations)
    query = " ".join(
        [
            challenge.title or "",
            challenge.description or "",
            " ".join(challenge.tags),
            " ".join(challenge.attachment_paths),
            observations,
        ]
    )
    knowledge = format_knowledge_blocks(
        retrieved_knowledge_for(
            challenge.category,
            query,
            notebook=context.notebook,
            current_challenge_id=challenge.challenge_id,
        )
    )
    return "\n".join(
        [
            f"challenge_id: {challenge.challenge_id}",
            f"category: {challenge.category.value}",
            f"title: {challenge.title or ''}",
            f"target: {challenge.target or ''}",
            f"description: {challenge.description or ''}",
            f"tags: {', '.join(challenge.tags)}",
            f"attachments: {', '.join(challenge.attachment_paths)}",
            category_playbook(challenge.category),
            knowledge,
            "shared_observations:",
            observations or "- none",
        ]
    )


def _parse_plan(content: str) -> LLMPlan | None:
    try:
        raw = json.loads(_strip_markdown_json_fence(content))
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    plan = LLMPlan(
        summary=_string(raw.get("summary")),
        hypotheses=tuple(_deduped_string_list(raw.get("hypotheses"))),
        suggested_solvers=tuple(_deduped_string_list(raw.get("suggested_solvers"))),
        next_actions=tuple(_deduped_string_list(raw.get("next_actions"))),
        tool_hints=tuple(_deduped_string_list(raw.get("tool_hints"))),
        expected_evidence=tuple(_deduped_string_list(raw.get("expected_evidence"))),
        fallback_plan=tuple(_deduped_string_list(raw.get("fallback_plan"))),
    )
    if not any(plan.to_evidence().values()):
        return None
    return plan


def _strip_markdown_json_fence(content: str) -> str:
    stripped = content.strip()
    fence_start = stripped.find("```")
    if fence_start > 0:
        fence_end = stripped.find("```", fence_start + 3)
        if fence_end > fence_start:
            return _strip_markdown_json_fence(stripped[fence_start : fence_end + 3])
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if len(lines) >= 3 and lines[0].strip().startswith("```") and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()
    return stripped


def _next_action(plan: LLMPlan | None) -> str:
    if plan and plan.next_actions:
        return plan.next_actions[0]
    return "Dispatch scoped specialist solvers and verify every candidate against notebook evidence."


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _deduped_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            continue
        cleaned = item.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        items.append(cleaned)
        if len(items) >= 10:
            break
    return items

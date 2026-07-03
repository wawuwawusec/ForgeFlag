from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.knowledge import KnowledgeBlock, format_knowledge_blocks, retrieved_knowledge_for
from forgeflag.llm import LLMProvider
from forgeflag.llm_prompts import category_playbook, prior_failure_patterns
from forgeflag.solvers.base import SolverContext


@dataclass(frozen=True)
class LLMPlan:
    summary: str = ""
    analysis_mode: str = ""
    hypotheses: tuple[str, ...] = ()
    suggested_solvers: tuple[str, ...] = ()
    next_actions: tuple[str, ...] = ()
    tool_hints: tuple[str, ...] = ()
    expected_evidence: tuple[str, ...] = ()
    artifact_requirements: tuple[str, ...] = ()
    blocked_by_missing_artifacts: tuple[str, ...] = ()
    manual_replay_needed: tuple[str, ...] = ()
    fallback_plan: tuple[str, ...] = ()
    risk_notes: tuple[str, ...] = ()
    flag_candidates: tuple[str, ...] = ()

    def to_evidence(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "analysis_mode": self.analysis_mode,
            "hypotheses": list(self.hypotheses),
            "suggested_solvers": list(self.suggested_solvers),
            "next_actions": list(self.next_actions),
            "tool_hints": list(self.tool_hints),
            "expected_evidence": list(self.expected_evidence),
            "artifact_requirements": list(self.artifact_requirements),
            "blocked_by_missing_artifacts": list(self.blocked_by_missing_artifacts),
            "manual_replay_needed": list(self.manual_replay_needed),
            "fallback_plan": list(self.fallback_plan),
            "risk_notes": list(self.risk_notes),
            "flag_candidates": list(self.flag_candidates),
        }


class LLMSolver:
    name = "LLMSolver"
    supported_categories = set(ChallengeCategory)

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    def solve(self, context: SolverContext) -> SolverResult:
        if not self.provider.enabled:
            return SolverResult(self.name, context.challenge.challenge_id, "disabled")

        knowledge_blocks = _knowledge_blocks(context)
        try:
            response = self.provider.generate(_instructions(), _prompt(context, knowledge_blocks))
        except Exception as exc:  # noqa: BLE001 - LLM planning must not block scoped tool solvers.
            return self._unavailable_result(context, str(exc), knowledge_blocks)
        if response.raw.get("status") == "unavailable":
            return self._unavailable_result(context, str(response.raw.get("error") or response.content), knowledge_blocks)

        plan = _parse_plan(response.content)
        evidence: dict[str, Any] = {
            "provider": self.provider.name,
            "model": self.provider.model,
            "strategy": response.content,
        }
        retrieved = _knowledge_evidence(knowledge_blocks)
        if retrieved:
            evidence["retrieved_knowledge"] = retrieved
        if plan:
            evidence["plan"] = plan.to_evidence()
        flag_candidates = _flag_candidates_from_response(response.content, plan)
        if flag_candidates:
            evidence["flag_candidates"] = list(flag_candidates)

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
        return SolverResult(
            self.name,
            context.challenge.challenge_id,
            "flag_candidate" if flag_candidates else "ok",
            (finding,),
            flag_candidates,
        )

    def _unavailable_result(
        self,
        context: SolverContext,
        error: str,
        knowledge_blocks: list[KnowledgeBlock] | tuple[KnowledgeBlock, ...] = (),
    ) -> SolverResult:
        evidence: dict[str, Any] = {
            "provider": self.provider.name,
            "model": self.provider.model,
            "error": error,
        }
        retrieved = _knowledge_evidence(knowledge_blocks)
        if retrieved:
            evidence["retrieved_knowledge"] = retrieved
        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="LLM planning unavailable",
            evidence=evidence,
            hypothesis="The configured LLM could not be used, so ForgeFlag should continue with deterministic solvers.",
            confidence=0.2,
            next_action="Fix the LLM configuration or disable 大模型分析, then rerun if model guidance is needed.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "config_error", (finding,))


def _instructions() -> str:
    return (
        "You are ForgeFlag's planning model for local or authorized CTF/lab challenges. "
        "Treat the work as controlled challenge research, not real-world offensive activity. "
        "Suggest scoped, evidence-driven next steps only. Do not propose unauthorized access, arbitrary shell exposure, "
        "or unscoped network activity. Prefer passive artifact analysis first, then reproducible tool workflows, "
        "and explain what evidence to collect. "
        "Only include flag_candidates when derived from the provided local artifact evidence; never guess placeholders. "
        "Use prior_failure_patterns to avoid known ForgeFlag CTF pitfalls, and state missing artifacts instead of inventing them. "
        "Return compact JSON with keys: summary, analysis_mode, hypotheses, suggested_solvers, next_actions, tool_hints, "
        "expected_evidence, artifact_requirements, blocked_by_missing_artifacts, manual_replay_needed, fallback_plan, risk_notes, "
        "flag_candidates. suggested_solvers must use exact ForgeFlag solver names such as "
        "WebSolver, CryptoSolver, ReverseSolver, PwnSolver, ForensicsSolver, TrafficSolver, MiscSolver, or InfraSolver."
    )


def _prompt(context: SolverContext, knowledge_blocks: list[KnowledgeBlock] | tuple[KnowledgeBlock, ...] | None = None) -> str:
    challenge = context.challenge
    observations = "\n".join(f"- {observation.kind}: {observation.summary}" for observation in context.observations)
    if knowledge_blocks is None:
        knowledge_blocks = _knowledge_blocks(context)
    knowledge = format_knowledge_blocks(list(knowledge_blocks))
    attachment_preview = _attachment_previews(challenge.attachment_paths)
    pattern_context = "\n".join(
        [
            challenge.title or "",
            challenge.description or "",
            " ".join(challenge.tags),
            " ".join(challenge.attachment_paths),
            attachment_preview,
            observations,
        ]
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
            attachment_preview,
            category_playbook(challenge.category),
            prior_failure_patterns(challenge.category, pattern_context),
            knowledge,
            "shared_observations:",
            observations or "- none",
        ]
    )


def _knowledge_blocks(context: SolverContext) -> list[KnowledgeBlock]:
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
    return retrieved_knowledge_for(
        challenge.category,
        query,
        notebook=context.notebook,
        current_challenge_id=challenge.challenge_id,
    )


def _knowledge_evidence(blocks: list[KnowledgeBlock] | tuple[KnowledgeBlock, ...]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for block in blocks[:3]:
        content = block.content
        if len(content) > 500:
            content = content[:497].rstrip() + "..."
        items.append(
            {
                "source": block.source,
                "title": block.title,
                "category": block.category.value,
                "body": content,
            }
        )
    return items


def _parse_plan(content: str) -> LLMPlan | None:
    try:
        raw = json.loads(_strip_markdown_json_fence(content))
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    plan = LLMPlan(
        summary=_string(raw.get("summary")),
        analysis_mode=_string(raw.get("analysis_mode")),
        hypotheses=tuple(_deduped_string_list(raw.get("hypotheses"))),
        suggested_solvers=tuple(_deduped_string_list(raw.get("suggested_solvers"))),
        next_actions=tuple(_deduped_string_list(raw.get("next_actions"))),
        tool_hints=tuple(_deduped_string_list(raw.get("tool_hints"))),
        expected_evidence=tuple(_deduped_string_list(raw.get("expected_evidence"))),
        artifact_requirements=tuple(_deduped_string_list(raw.get("artifact_requirements"))),
        blocked_by_missing_artifacts=tuple(_deduped_string_list(raw.get("blocked_by_missing_artifacts"))),
        manual_replay_needed=tuple(_deduped_string_list(raw.get("manual_replay_needed"))),
        fallback_plan=tuple(_deduped_string_list(raw.get("fallback_plan"))),
        risk_notes=tuple(_deduped_string_list(raw.get("risk_notes"))),
        flag_candidates=tuple(_deduped_string_list(raw.get("flag_candidates"))),
    )
    if not any(plan.to_evidence().values()):
        return None
    return plan


def _flag_candidates_from_response(content: str, plan: LLMPlan | None) -> tuple[str, ...]:
    values: list[str] = []
    if plan:
        values.extend(plan.flag_candidates)
    values.extend(extract_flags(content))
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return tuple(deduped[:10])


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


def _attachment_previews(paths: tuple[str, ...], max_files: int = 4, max_chars_per_file: int = 1800) -> str:
    if not paths:
        return "attachment_previews:\n- none"
    rows = ["attachment_previews:"]
    for raw_path in paths[:max_files]:
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            rows.append(f"- {raw_path}: missing")
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            rows.append(f"- {raw_path}: unreadable ({exc})")
            continue
        if _looks_binary(data):
            rows.append(f"- {raw_path}: binary file, size={len(data)} bytes")
            continue
        text = data.decode("utf-8", errors="replace")
        truncated = len(text) > max_chars_per_file
        preview = _bounded_head_tail_preview(text, max_chars_per_file) if truncated else text
        suffix = " [truncated]" if truncated else ""
        rows.append(f"- {path.name} ({len(data)} bytes){suffix}:")
        rows.extend(f"  {line}" for line in _bounded_preview_lines(preview, max_lines=80))
    if len(paths) > max_files:
        rows.append(f"- {len(paths) - max_files} more attachment(s) omitted from LLM preview")
    return "\n".join(rows)


def _looks_binary(data: bytes) -> bool:
    if b"\x00" in data[:4096]:
        return True
    sample = data[:4096]
    if not sample:
        return False
    textish = sum(1 for byte in sample if byte in b"\n\r\t" or 32 <= byte <= 126)
    return textish / len(sample) < 0.85


def _bounded_head_tail_preview(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    marker = "\n[middle omitted from LLM attachment preview]\n"
    budget = max(200, max_chars - len(marker))
    head_chars = budget // 2
    tail_chars = budget - head_chars
    return text[:head_chars].rstrip() + marker + text[-tail_chars:].lstrip()


def _bounded_preview_lines(text: str, max_lines: int) -> list[str]:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return lines
    marker = f"[middle omitted from LLM attachment preview: {len(lines) - max_lines} line(s)]"
    head_count = max_lines // 2
    tail_count = max_lines - head_count - 1
    return lines[:head_count] + [marker] + lines[-tail_count:]


def _next_action(plan: LLMPlan | None) -> str:
    if plan and plan.next_actions:
        return plan.next_actions[0]
    if plan and plan.blocked_by_missing_artifacts:
        return f"Collect missing artifact or evidence: {plan.blocked_by_missing_artifacts[0]}"
    if plan and plan.manual_replay_needed:
        return plan.manual_replay_needed[0]
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

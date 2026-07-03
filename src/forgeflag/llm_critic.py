from __future__ import annotations

import json
from typing import Any

from forgeflag.domain import Challenge, Finding, Observation
from forgeflag.llm import LLMProvider
from forgeflag.llm_prompts import category_playbook, prior_failure_patterns
from forgeflag.solvers.llm import _attachment_previews, _strip_markdown_json_fence


def build_post_run_critic_observation(
    *,
    challenge: Challenge,
    provider: LLMProvider,
    run_summary: dict[str, object],
    findings: list[Finding],
    observations: list[Observation],
) -> Observation | None:
    if not provider.enabled:
        return None
    try:
        response = provider.generate(_critic_instructions(), _critic_prompt(challenge, run_summary, findings, observations))
    except Exception as exc:  # noqa: BLE001 - critic advice must not block deterministic results.
        return Observation(
            challenge_id=challenge.challenge_id,
            source="LLMCritic",
            kind="llm_post_run_critic",
            summary="Post-run critic unavailable",
            evidence={"error": str(exc), "provider": provider.name, "model": provider.model},
        )
    if response.raw.get("status") == "unavailable":
        return Observation(
            challenge_id=challenge.challenge_id,
            source="LLMCritic",
            kind="llm_post_run_critic",
            summary="Post-run critic unavailable",
            evidence={
                "error": str(response.raw.get("error") or response.content),
                "provider": provider.name,
                "model": provider.model,
            },
        )

    evidence = _parse_critic(response.content)
    if not evidence:
        evidence = {"summary": response.content.strip(), "raw_strategy": response.content}
    evidence["provider"] = provider.name
    evidence["model"] = provider.model
    return Observation(
        challenge_id=challenge.challenge_id,
        source="LLMCritic",
        kind="llm_post_run_critic",
        summary=str(evidence.get("summary") or "Post-run critic generated next-step guidance"),
        evidence=evidence,
    )


def _critic_instructions() -> str:
    return (
        "You are ForgeFlag's post-run critic for local or authorized CTF/lab challenges. "
        "Treat the work as controlled challenge research, not real-world offensive activity. "
        "Do not guess flags. Compare the run result against evidence, identify why the run stalled, "
        "and propose the next scoped solver/tool route. Return compact JSON with keys: summary, blockers, "
        "missing_evidence, suggested_solvers, tool_hints, next_actions, rerun_reason, analysis_mode, "
        "artifact_requirements, blocked_by_missing_artifacts, manual_replay_needed, risk_notes."
    )


def _critic_prompt(
    challenge: Challenge,
    run_summary: dict[str, object],
    findings: list[Finding],
    observations: list[Observation],
) -> str:
    finding_lines = [
        f"- {finding.solver}: {finding.finding}; hypothesis={finding.hypothesis or ''}; next={finding.next_action or ''}; evidence={_compact(finding.evidence)}"
        for finding in findings[-12:]
    ]
    observation_lines = [
        f"- {observation.source}/{observation.kind}: {observation.summary}; evidence={_compact(observation.evidence)}"
        for observation in observations[-16:]
    ]
    attachment_preview = _attachment_previews(challenge.attachment_paths)
    pattern_context = "\n".join(
        [
            challenge.title or "",
            challenge.description or "",
            " ".join(challenge.attachment_paths),
            attachment_preview,
            "\n".join(finding_lines),
            "\n".join(observation_lines),
        ]
    )
    return "\n".join(
        [
            f"challenge_id: {challenge.challenge_id}",
            f"category: {challenge.category.value}",
            f"title: {challenge.title or ''}",
            f"description: {challenge.description or ''}",
            f"attachments: {', '.join(challenge.attachment_paths)}",
            attachment_preview,
            category_playbook(challenge.category),
            prior_failure_patterns(challenge.category, pattern_context),
            f"run_status: {run_summary.get('status')}",
            f"accepted_flags: {run_summary.get('accepted_flags')}",
            f"rejected_flags: {run_summary.get('rejected_flags')}",
            "solver_results:",
            json.dumps(run_summary.get("solvers", []), ensure_ascii=False),
            "recent_findings:",
            "\n".join(finding_lines) or "- none",
            "recent_observations:",
            "\n".join(observation_lines) or "- none",
        ]
    )


def _parse_critic(content: str) -> dict[str, Any]:
    try:
        raw = json.loads(_strip_markdown_json_fence(content))
    except json.JSONDecodeError:
        return {}
    if not isinstance(raw, dict):
        return {}
    evidence = {
        "summary": _string(raw.get("summary")),
        "blockers": _string_list(raw.get("blockers")),
        "missing_evidence": _string_list(raw.get("missing_evidence")),
        "suggested_solvers": _string_list(raw.get("suggested_solvers")),
        "tool_hints": _string_list(raw.get("tool_hints")),
        "next_actions": _string_list(raw.get("next_actions")),
        "rerun_reason": _string(raw.get("rerun_reason")),
        "analysis_mode": _string(raw.get("analysis_mode")),
        "artifact_requirements": _string_list(raw.get("artifact_requirements")),
        "blocked_by_missing_artifacts": _string_list(raw.get("blocked_by_missing_artifacts")),
        "manual_replay_needed": _string_list(raw.get("manual_replay_needed")),
        "risk_notes": _string_list(raw.get("risk_notes")),
    }
    return {key: value for key, value in evidence.items() if value}


def _compact(value: object) -> str:
    text = json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= 700 else text[:697] + "..."


def _string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _string_list(value: object) -> list[str]:
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

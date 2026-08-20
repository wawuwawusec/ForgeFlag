"""Reviewer agent: trajectory judging, corpus gap analysis, reflection hints.

Design borrows from recent agentic-CTF research:

- LLM-as-judge over solver trajectories (CTFJudge-style, arXiv:2508.05674):
  every run's findings and execution transcripts are judged for evidence
  quality, hallucinated flags, and near-miss patterns.
- Reflection-driven retry (arXiv:2405.06682): the verdict produces a compact
  ``reflection_hint`` that is injected into later solve attempts, so retries
  start from an informed critique instead of repeating the same move.
- Reliability tracking (CTFusion's finding that static benchmarks mislead):
  variance across repeated runs is surfaced per challenge.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from forgeflag.domain import Observation
from forgeflag.flags import extract_flags_generic
from forgeflag.llm import LLMProvider

_PLACEHOLDER_MARKERS = (
    "testflag", "test_flag", "fake", "placeholder", "redacted", "example",
    "decrypted_flag", "recovered_flag", "real_flag", "decoded_flag", "todo",
)


@dataclass
class ReviewVerdict:
    challenge_id: str
    quality: str  # clean | weak_evidence | hallucination_risk | inconclusive
    issues: list[str] = field(default_factory=list)
    reflection_hint: str = ""
    llm_analysis: dict[str, Any] = field(default_factory=dict)


class ReviewerAgent:
    name = "ReviewerAgent"

    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.provider = provider

    # ------------------------------------------------------------------
    # single-challenge trajectory review
    # ------------------------------------------------------------------
    def review_challenge(self, notebook, challenge_id: str) -> ReviewVerdict:
        findings = notebook.findings_for(challenge_id)
        observations = notebook.observations_for(challenge_id)
        issues: list[str] = []

        accepted = [f for f in findings if f.confidence >= 0.8]
        for finding in findings:
            candidates = (finding.evidence or {}).get("flag_candidates") or []
            for candidate in candidates:
                lowered = str(candidate).lower()
                if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
                    issues.append(f"placeholder-shaped flag candidate accepted from {finding.solver}: {candidate[:60]}")
            if finding.solver not in ("ReconSolver",) and "ctf_scope" not in (finding.evidence or {}):
                issues.append(f"finding from {finding.solver} missing ctf_scope evidence")

        execute_transcripts = [
            o for o in observations
            if o.kind in ("tool_summary", "solve_trace", "llm_action_queue")
        ]
        if not findings:
            issues.append("no solver findings recorded")
        if not execute_transcripts:
            issues.append("no tool or execution evidence recorded")

        quality = "clean"
        if any("placeholder" in i for i in issues):
            quality = "hallucination_risk"
        elif issues:
            quality = "weak_evidence"

        llm_analysis: dict[str, Any] = {}
        reflection_hint = ""
        if self.provider is not None and self.provider.enabled and findings:
            trajectory = self._trajectory_digest(findings, observations)
            try:
                response = self.provider.generate(_judge_instructions(), trajectory)
                llm_analysis = _parse_verdict_json(response.content)
                hint = str(llm_analysis.get("reflection_hint") or "").strip()
                if hint:
                    reflection_hint = hint[:600]
                for issue in llm_analysis.get("issues") or []:
                    if isinstance(issue, str):
                        issues.append(f"judge: {issue[:160]}")
                if llm_analysis.get("quality") in {"clean", "weak_evidence", "hallucination_risk", "inconclusive"}:
                    if quality == "clean":
                        quality = llm_analysis["quality"]
            except Exception:  # noqa: BLE001 - judging must never break the run
                llm_analysis = {"error": "judge call failed"}

        return ReviewVerdict(
            challenge_id=challenge_id,
            quality=quality,
            issues=issues[:10],
            reflection_hint=reflection_hint,
            llm_analysis=llm_analysis,
        )

    @staticmethod
    def _trajectory_digest(findings, observations) -> str:
        lines = []
        for finding in findings:
            evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
            digest = {k: str(v)[:200] for k, v in list(evidence.items())[:6]}
            lines.append(f"[{finding.solver}] {finding.finding} conf={finding.confidence} evidence={json.dumps(digest, ensure_ascii=False)[:800]}")
        for observation in observations[-15:]:
            lines.append(f"({observation.kind}) {observation.summary[:200]}")
        return "\n".join(lines[:40])

    # ------------------------------------------------------------------
    # corpus-level gap analysis
    # ------------------------------------------------------------------
    def review_corpus(self, scorecard: dict[str, Any], deployable_ids: set[str] | None = None) -> dict[str, Any]:
        deployable_ids = deployable_ids or set()
        buckets: dict[str, list[str]] = {
            "retry_with_service": [],
            "near_miss_flag_found": [],
            "no_evidence_progress": [],
            "timeout_or_harness": [],
        }
        for failure in scorecard.get("failures", []):
            cid = str(failure.get("challenge_id") or "")
            status = str(failure.get("status") or "")
            if status.startswith("harness_error") or status.startswith("timeout"):
                buckets["timeout_or_harness"].append(cid)
            elif status == "flag_found" or "+replay" in status:
                buckets["near_miss_flag_found"].append(cid)
            elif cid in deployable_ids:
                buckets["retry_with_service"].append(cid)
            else:
                buckets["no_evidence_progress"].append(cid)
        prioritized = [
            *buckets["near_miss_flag_found"],
            *buckets["retry_with_service"],
            *buckets["timeout_or_harness"],
        ]
        return {
            "reviewer": self.name,
            "buckets": buckets,
            "prioritized_retry_ids": prioritized[:40],
            "recommendations": [
                "inject reflection hints from prior failures into retries",
                "deploy service harness targets for retry_with_service cases",
                "re-run variance-prone challenges before trusting single-pass results",
            ],
        }

    # ------------------------------------------------------------------
    # reliability / variance across repeated scorecards
    # ------------------------------------------------------------------
    @staticmethod
    def variance_report(scorecards: list[dict[str, Any]]) -> dict[str, Any]:
        outcomes: dict[str, list[bool]] = {}
        for scorecard in scorecards:
            solved = {cid for suite in scorecard.get("suites", []) for cid in suite.get("passed_ids", [])}
            seen: set[str] = set()
            for suite in scorecard.get("suites", []):
                for row in suite.get("rows", []):
                    cid = str(row.get("challenge_id") or "")
                    if not cid or cid in seen:
                        continue
                    seen.add(cid)
                    outcomes.setdefault(cid, []).append(cid in solved)
        flaky = {
            cid: {"solved": sum(v), "runs": len(v), "rate": round(sum(v) / len(v), 2)}
            for cid, v in outcomes.items()
            if len(v) >= 2 and 0 < sum(v) < len(v)
        }
        return {"challenges_seen": len(outcomes), "flaky_challenges": flaky}


def reviewer_observation(verdict: ReviewVerdict) -> Observation:
    return Observation(
        challenge_id=verdict.challenge_id,
        source="ReviewerAgent",
        kind="reviewer_verdict",
        summary=f"Review verdict {verdict.quality}: {len(verdict.issues)} issue(s)",
        evidence={
            "quality": verdict.quality,
            "issues": verdict.issues,
            "reflection_hint": verdict.reflection_hint,
            "llm_analysis": verdict.llm_analysis,
        },
    )


def reflection_hint_from_observations(observations) -> str:
    """Latest reviewer reflection hint to inject into retry prompts."""
    for observation in reversed(list(observations)):
        if observation.kind == "reviewer_verdict":
            hint = str((observation.evidence or {}).get("reflection_hint") or "")
            if hint:
                return hint
    return ""


def _judge_instructions() -> str:
    return (
        "You are ForgeFlag's reviewer agent judging a CTF solver trajectory "
        "(findings + tool/execution evidence) for an authorized local challenge. "
        "Assess: (1) evidence quality — are flag candidates derived from parsed data "
        "or hallucinated; (2) what the solvers got closest to and why it failed; "
        "(3) one concrete, actionable reflection_hint for the next attempt. "
        'Return compact JSON: {"quality": "clean|weak_evidence|hallucination_risk|inconclusive", '
        '"issues": ["..."], "reflection_hint": "..."} and nothing else.'
    )


def _parse_verdict_json(content: str) -> dict[str, Any]:
    match = re.search(r"\{.*\}", content, re.S)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}

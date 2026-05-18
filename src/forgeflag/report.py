from __future__ import annotations

from typing import Any

from forgeflag.domain import Finding, Observation


class ReportBuilder:
    def build(
        self,
        challenge_id: str,
        accepted_flags: tuple[str, ...],
        findings: list[Finding],
        observations: list[Observation],
    ) -> dict[str, Any]:
        return {
            "challenge_id": challenge_id,
            "flags": [
                self._flag_report(flag, findings, observations)
                for flag in accepted_flags
            ],
        }

    def _flag_report(
        self,
        flag: str,
        findings: list[Finding],
        observations: list[Observation],
    ) -> dict[str, Any]:
        path = [
            self._finding_step(finding)
            for finding in findings
            if flag in str(finding.evidence) or flag in finding.finding
        ]
        related_observations = [
            self._observation_step(observation)
            for observation in observations
            if flag in observation.summary or flag in str(observation.evidence)
        ]
        replay_steps = [
            step["next_action"]
            for step in path
            if step.get("next_action")
        ]
        return {
            "flag": flag,
            "path": path[:3],
            "observations": related_observations[:3],
            "replay_steps": replay_steps[:3],
        }

    def _finding_step(self, finding: Finding) -> dict[str, Any]:
        return {
            "solver": finding.solver,
            "finding": finding.finding,
            "confidence": finding.confidence,
            "hypothesis": finding.hypothesis,
            "next_action": finding.next_action,
            "evidence": _compact_evidence(finding.evidence),
        }

    def _observation_step(self, observation: Observation) -> dict[str, Any]:
        return {
            "source": observation.source,
            "kind": observation.kind,
            "summary": observation.summary,
            "evidence": _compact_evidence(observation.evidence),
        }


def _compact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for key, value in evidence.items():
        if isinstance(value, str):
            compact[key] = value[:500]
        elif isinstance(value, list):
            compact[key] = value[:10]
        elif isinstance(value, dict):
            compact[key] = {subkey: value[subkey] for subkey in list(value)[:10]}
        else:
            compact[key] = value
    return compact

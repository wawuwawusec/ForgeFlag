from __future__ import annotations

from typing import Any

from forgeflag.domain import Challenge, Finding, Observation


class ReportBuilder:
    def build(
        self,
        challenge_id: str,
        accepted_flags: tuple[str, ...],
        findings: list[Finding],
        observations: list[Observation],
        challenge: Challenge | None = None,
    ) -> dict[str, Any]:
        flag_reports = [
            self._flag_report(flag, findings, observations)
            for flag in accepted_flags
        ]
        writeup = self._writeup_report(challenge_id, accepted_flags, flag_reports, findings, observations, challenge)
        return {
            "challenge_id": challenge_id,
            "flags": flag_reports,
            "writeup": writeup,
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

    def _writeup_report(
        self,
        challenge_id: str,
        accepted_flags: tuple[str, ...],
        flag_reports: list[dict[str, Any]],
        findings: list[Finding],
        observations: list[Observation],
        challenge: Challenge | None,
    ) -> dict[str, Any]:
        title = challenge.title if challenge and challenge.title else challenge_id
        category = challenge.category.value if challenge else "unknown"
        tags = list(challenge.tags) if challenge else []
        attachments = list(challenge.attachment_paths) if challenge else []
        path_steps = flag_reports[0]["path"] if flag_reports else []
        observation_steps = flag_reports[0]["observations"] if flag_reports else []
        replay_steps = flag_reports[0]["replay_steps"] if flag_reports else []

        sections = [
            {
                "title": "题目信息",
                "body": challenge.description if challenge and challenge.description else "暂无题面描述，以下复盘基于 ForgeFlag 运行证据生成。",
                "items": _non_empty_items(
                    [
                        ("分类", category),
                        ("目标", challenge.target if challenge else None),
                        ("标签", ", ".join(tags) if tags else None),
                        ("附件", ", ".join(attachments) if attachments else None),
                    ]
                ),
            },
            {
                "title": "最终结论",
                "body": "Verifier 已接受以下 flag。" if accepted_flags else "本次运行尚未确认 flag。",
                "flags": list(accepted_flags),
            },
            {
                "title": "解题思路",
                "body": _approach_summary(path_steps, findings),
                "items": [
                    {
                        "label": step.get("solver") or "solver",
                        "value": step.get("hypothesis") or step.get("finding") or "记录关键分析步骤。",
                    }
                    for step in path_steps
                ],
            },
            {
                "title": "关键证据",
                "body": "这些发现或观察直接支撑最终 flag。",
                "items": _evidence_items(path_steps, observation_steps),
            },
            {
                "title": "复现步骤",
                "body": "按下面顺序可以复现最短发现路径。",
                "steps": replay_steps or _fallback_replay_steps(path_steps),
            },
            {
                "title": "工具与观察",
                "body": "保留相关 solver、观察与证据摘要，方便赛后补写完整 write-up。",
                "items": _tool_observation_items(findings, observations),
            },
        ]
        markdown = _markdown_writeup(title, challenge_id, category, list(accepted_flags), sections)
        return {
            "title": title,
            "challenge_id": challenge_id,
            "category": category,
            "tags": tags,
            "attachments": attachments,
            "final_flags": list(accepted_flags),
            "sections": sections,
            "markdown": markdown,
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


def _non_empty_items(items: list[tuple[str, str | None]]) -> list[dict[str, str]]:
    return [{"label": label, "value": value} for label, value in items if value]


def _approach_summary(path_steps: list[dict[str, Any]], findings: list[Finding]) -> str:
    if path_steps:
        solvers = " -> ".join(step.get("solver") or "solver" for step in path_steps)
        return f"从相关证据看，最短路径由 {solvers} 完成：先定位可疑线索，再提取候选 flag，并交给 verifier 确认。"
    if findings:
        solvers = " -> ".join(dict.fromkeys(finding.solver for finding in findings))
        return f"本次运行记录了 {solvers} 的分析结果，但没有找到直接关联 flag 的最短证据路径。"
    return "暂无 solver 证据。"


def _evidence_items(path_steps: list[dict[str, Any]], observation_steps: list[dict[str, Any]]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for step in path_steps:
        evidence = step.get("evidence") or {}
        items.append(
            {
                "label": f"{step.get('solver') or 'solver'}: {step.get('finding') or 'finding'}",
                "value": _short_text(evidence),
            }
        )
    for observation in observation_steps:
        items.append(
            {
                "label": f"{observation.get('source') or 'observation'}: {observation.get('kind') or 'note'}",
                "value": observation.get("summary") or _short_text(observation.get("evidence") or {}),
            }
        )
    return items[:6]


def _fallback_replay_steps(path_steps: list[dict[str, Any]]) -> list[str]:
    steps = []
    for step in path_steps:
        solver = step.get("solver") or "solver"
        finding = step.get("finding") or "finding"
        steps.append(f"复查 {solver} 的 {finding} 证据。")
    return steps[:5]


def _tool_observation_items(findings: list[Finding], observations: list[Observation]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for finding in findings[-5:]:
        items.append({"label": finding.solver, "value": finding.finding})
    for observation in observations[-5:]:
        items.append({"label": f"{observation.source} / {observation.kind}", "value": observation.summary})
    return items[:8]


def _short_text(value: Any) -> str:
    text = str(value)
    return text if len(text) <= 360 else text[:357] + "..."


def _markdown_writeup(
    title: str,
    challenge_id: str,
    category: str,
    flags: list[str],
    sections: list[dict[str, Any]],
) -> str:
    lines = [f"# {title}", "", f"- Challenge ID: `{challenge_id}`", f"- Category: `{category}`"]
    if flags:
        lines.append("- Flag: " + ", ".join(f"`{flag}`" for flag in flags))
    lines.append("")
    for section in sections:
        lines.extend([f"## {section['title']}", "", str(section.get("body") or ""), ""])
        if section.get("flags"):
            lines.extend(f"- `{flag}`" for flag in section["flags"])
            lines.append("")
        if section.get("items"):
            for item in section["items"]:
                lines.append(f"- {item['label']}: {item['value']}")
            lines.append("")
        if section.get("steps"):
            for index, step in enumerate(section["steps"], 1):
                lines.append(f"{index}. {step}")
            lines.append("")
    return "\n".join(lines).strip() + "\n"

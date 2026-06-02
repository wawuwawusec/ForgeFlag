from __future__ import annotations

from typing import Any

from forgeflag.domain import Challenge, Finding, Observation
from forgeflag.trace import shortest_trace_path, trace_steps_from_observations


class ReportBuilder:
    def build(
        self,
        challenge_id: str,
        accepted_flags: tuple[str, ...],
        findings: list[Finding],
        observations: list[Observation],
        challenge: Challenge | None = None,
    ) -> dict[str, Any]:
        solve_trace = trace_steps_from_observations(observations)
        flag_reports = [
            self._flag_report(flag, findings, observations, solve_trace)
            for flag in accepted_flags
        ]
        writeup = self._writeup_report(
            challenge_id,
            accepted_flags,
            flag_reports,
            findings,
            observations,
            challenge,
            solve_trace,
        )
        return {
            "challenge_id": challenge_id,
            "flags": flag_reports,
            "solve_trace": solve_trace,
            "writeup": writeup,
        }

    def _flag_report(
        self,
        flag: str,
        findings: list[Finding],
        observations: list[Observation],
        solve_trace: list[dict[str, Any]],
    ) -> dict[str, Any]:
        path = _dedupe_steps(
            [
                self._finding_step(finding)
                for finding in findings
                if flag in str(finding.evidence) or flag in finding.finding
            ],
            ("solver", "finding", "next_action"),
        )
        trace_path = shortest_trace_path(flag, solve_trace)
        related_observations = _dedupe_steps(
            [
                self._observation_step(observation)
                for observation in observations
                if flag in observation.summary or flag in str(observation.evidence)
            ],
            ("source", "kind", "summary"),
        )
        replay_steps = [
            step["next_action"]
            for step in path
            if step.get("next_action")
        ]
        return {
            "flag": flag,
            "path": path[:3],
            "trace_path": trace_path,
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
        solve_trace: list[dict[str, Any]],
    ) -> dict[str, Any]:
        title = challenge.title if challenge and challenge.title else challenge_id
        category = challenge.category.value if challenge else "unknown"
        tags = list(challenge.tags) if challenge else []
        attachments = list(challenge.attachment_paths) if challenge else []
        path_steps = flag_reports[0]["path"] if flag_reports else []
        trace_path = flag_reports[0]["trace_path"] if flag_reports else solve_trace[:5]
        observation_steps = flag_reports[0]["observations"] if flag_reports else []
        replay_steps = flag_reports[0]["replay_steps"] if flag_reports else []
        reproduction_steps = _reproduction_steps(path_steps, trace_path, replay_steps, attachments)

        sections = [
            {
                "title": "题目概览",
                "body": challenge.description if challenge and challenge.description else "基于附件和运行证据整理的精简复盘。",
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
                "title": "解题思路",
                "body": _approach_summary(path_steps, findings),
                "items": _approach_items(path_steps, trace_path),
            },
            {
                "title": "复现步骤",
                "body": "照下面做即可复现获取 flag 的过程。",
                "steps": reproduction_steps,
            },
            {
                "title": "关键证据",
                "body": "只保留支撑结论的关键参数和结果，完整内部日志可在 Raw JSON 中查看。",
                "items": _evidence_items(path_steps, observation_steps),
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
            "solve_trace": solve_trace,
            "shortest_discovery_path": trace_path,
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


def _dedupe_steps(steps: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    deduped: list[dict[str, Any]] = []
    for step in reversed(steps):
        identity = tuple(str(step.get(key) or "") for key in keys)
        if identity in seen:
            continue
        seen.add(identity)
        deduped.append(step)
    return list(reversed(deduped))


def _approach_summary(path_steps: list[dict[str, Any]], findings: list[Finding]) -> str:
    random_xor = _first_nested(path_steps, "python_random_xor")
    if random_xor:
        return "关键点是弱随机种子：题目用小范围 seed 初始化 Python random，再生成 XOR key；遍历 seed 后即可还原明文。"
    rsa_recovery = _first_nested(path_steps, "rsa_recovery")
    if rsa_recovery:
        return "关键点是 RSA 参数足够恢复私钥或明文；利用已知因子/私钥参数计算明文后提取 flag。"
    if path_steps:
        solvers = " -> ".join(step.get("solver") or "solver" for step in path_steps)
        return f"最短有效路径由 {solvers} 完成：定位可疑线索，提取候选 flag，并交给 verifier 确认。"
    if findings:
        solvers = " -> ".join(dict.fromkeys(finding.solver for finding in findings))
        return f"本次运行记录了 {solvers} 的分析结果，但没有找到直接关联 flag 的最短证据路径。"
    return "暂无 solver 证据。"


def _approach_items(path_steps: list[dict[str, Any]], trace_path: list[dict[str, Any]]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for step in path_steps[:3]:
        items.append(
            {
                "label": step.get("solver") or "solver",
                "value": step.get("hypothesis") or step.get("finding") or "记录关键分析步骤。",
            }
        )
    if not items:
        for step in trace_path[:3]:
            items.append(
                {
                    "label": step.get("solver") or "solver",
                    "value": step.get("rationale") or step.get("summary") or "执行该 solver 并保留输出证据。",
                }
            )
    return items


def _evidence_items(path_steps: list[dict[str, Any]], observation_steps: list[dict[str, Any]]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for step in path_steps:
        evidence = step.get("evidence") or {}
        items.extend(_human_evidence_items(step, evidence))
    if items:
        return items[:6]
    for observation in observation_steps:
        items.append(
            {
                "label": f"{observation.get('source') or 'observation'}: {observation.get('kind') or 'note'}",
                "value": observation.get("summary") or _short_text(observation.get("evidence") or {}),
            }
        )
    return items[:6]


def _human_evidence_items(step: dict[str, Any], evidence: dict[str, Any]) -> list[dict[str, str]]:
    random_xor = evidence.get("python_random_xor")
    if isinstance(random_xor, dict):
        items = [
            ("密文整数", random_xor.get("enc")),
            ("key 位数", random_xor.get("key_bits")),
            ("命中 seed", random_xor.get("seed")),
            ("还原明文", random_xor.get("plaintext_preview") or ", ".join(_string_list(random_xor.get("flags")))),
        ]
        return [{"label": label, "value": str(value)} for label, value in items if value not in (None, "")]
    rsa_recovery = evidence.get("rsa_recovery")
    if isinstance(rsa_recovery, dict):
        items = [
            ("恢复方法", rsa_recovery.get("method")),
            ("恢复 flag", ", ".join(_string_list(rsa_recovery.get("flags")))),
        ]
        return [{"label": label, "value": str(value)} for label, value in items if value not in (None, "")]
    transform_candidates = evidence.get("transform_candidates")
    if isinstance(transform_candidates, list) and transform_candidates:
        first = transform_candidates[0] if isinstance(transform_candidates[0], dict) else {"value": transform_candidates[0]}
        return [
            {"label": "转换方法", "value": str(first.get("method") or step.get("finding") or "transform")},
            {"label": "候选结果", "value": str(first.get("value") or first)},
        ]
    return [
        {
            "label": f"{step.get('solver') or 'solver'}: {step.get('finding') or 'finding'}",
            "value": _short_text(evidence),
        }
    ]


def _reproduction_steps(
    path_steps: list[dict[str, Any]],
    trace_path: list[dict[str, Any]],
    replay_steps: list[str],
    attachments: list[str],
) -> list[str]:
    random_xor = _first_nested(path_steps, "python_random_xor")
    if random_xor:
        filename = _basename(attachments[0]) if attachments else "题目附件"
        key_bits = random_xor.get("key_bits") or "对应位数"
        seed = random_xor.get("seed")
        preview = random_xor.get("plaintext_preview") or _first_string(random_xor.get("flags")) or "flag 候选"
        return [
            f"打开附件 {filename}，确认它用小范围 seed 初始化 Python random，并用 getrandbits({key_bits}) 生成 XOR key。",
            "遍历 seed 取值范围，按相同逻辑执行 random.seed(seed) 和 random.getrandbits(150)。" if key_bits == 150 else f"遍历 seed 取值范围，按相同逻辑执行 random.seed(seed) 和 random.getrandbits({key_bits})。",
            "用 ciphertext XOR key 还原明文，并按 flag 格式筛选候选结果。",
            f"命中 seed={seed}，明文为 {preview}。" if seed is not None else f"得到明文 {preview}。",
        ]
    rsa_recovery = _first_nested(path_steps, "rsa_recovery")
    if rsa_recovery:
        method = rsa_recovery.get("method") or "RSA recovery"
        flags = _string_list(rsa_recovery.get("flags"))
        result = flags[0] if flags else "flag 候选"
        return [
            "从题目文本或附件中提取 RSA 参数 n/e/c 以及可用的 p/q/d 等信息。",
            f"使用 {method} 恢复私钥或直接计算明文整数。",
            "把明文整数转回 bytes，并按 flag 格式提取结果。",
            f"得到 {result}。",
        ]
    if replay_steps:
        return replay_steps[:5]
    trace_steps = _trace_replay_steps(trace_path)
    if trace_steps:
        return trace_steps[:5]
    return _fallback_replay_steps(path_steps)


def _fallback_replay_steps(path_steps: list[dict[str, Any]]) -> list[str]:
    steps = []
    for step in path_steps:
        solver = step.get("solver") or "solver"
        finding = step.get("finding") or "finding"
        steps.append(f"复查 {solver} 的 {finding} 证据。")
    return steps[:5]


def _trace_replay_steps(trace_path: list[dict[str, Any]]) -> list[str]:
    steps = []
    for step in trace_path:
        index = step.get("step_index") or len(steps) + 1
        solver = step.get("solver") or "solver"
        rationale = step.get("rationale") or step.get("summary") or "记录分析步骤。"
        candidates = step.get("flag_candidates") or []
        suffix = f" 候选 flag: {', '.join(candidates)}。" if candidates else ""
        steps.append(f"{index}. {solver}: {rationale}{suffix}")
    return steps[:8]


def _tool_observation_items(findings: list[Finding], observations: list[Observation]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for finding in findings[-5:]:
        items.append({"label": finding.solver, "value": finding.finding})
    for observation in observations[-5:]:
        items.append({"label": f"{observation.source} / {observation.kind}", "value": observation.summary})
    return _dedupe_steps(items, ("label", "value"))[:8]


def _short_text(value: Any) -> str:
    text = str(value)
    return text if len(text) <= 360 else text[:357] + "..."


def _first_nested(steps: list[dict[str, Any]], key: str) -> dict[str, Any]:
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        value = evidence.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _first_string(value: object) -> str | None:
    values = _string_list(value)
    return values[0] if values else None


def _basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1] or path


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


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

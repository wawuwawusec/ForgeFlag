from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

from forgeflag.domain import ChallengeCategory


@dataclass(frozen=True)
class AgentIdentity:
    id: str
    name: str
    mission: str
    responsibilities: tuple[str, ...] = ()
    team_type: str = "stream-aligned"
    reports_to: str = "forgeflag-manager"
    cadence: str = "per challenge"
    success_metrics: tuple[str, ...] = ()
    deliverables: tuple[str, ...] = ()
    categories: tuple[str, ...] = ("*",)
    solvers: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    playbooks: tuple[str, ...] = ()
    llm: bool = False
    active_probe: bool = False
    enabled: bool = True

    def applies_to(self, category: ChallengeCategory) -> bool:
        return "*" in self.categories or category.value in self.categories

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "mission": self.mission,
            "responsibilities": list(self.responsibilities),
            "team_type": self.team_type,
            "reports_to": self.reports_to,
            "cadence": self.cadence,
            "success_metrics": list(self.success_metrics),
            "deliverables": list(self.deliverables),
            "categories": list(self.categories),
            "solvers": list(self.solvers),
            "tools": list(self.tools),
            "playbooks": list(self.playbooks),
            "llm": self.llm,
            "active_probe": self.active_probe,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
        *,
        team_type_default: str = "stream-aligned",
        reports_to_default: str = "forgeflag-manager",
    ) -> AgentIdentity:
        return cls(
            id=str(payload.get("id") or ""),
            name=str(payload.get("name") or ""),
            mission=str(payload.get("mission") or ""),
            responsibilities=tuple(_string_list(payload.get("responsibilities"))),
            team_type=str(payload.get("team_type") or team_type_default),
            reports_to=str(payload.get("reports_to") if payload.get("reports_to") is not None else reports_to_default),
            cadence=str(payload.get("cadence") or "per challenge"),
            success_metrics=tuple(_string_list(payload.get("success_metrics"))),
            deliverables=tuple(_string_list(payload.get("deliverables"))),
            categories=tuple(_string_list(payload.get("categories")) or ["*"]),
            solvers=tuple(_string_list(payload.get("solvers"))),
            tools=tuple(_string_list(payload.get("tools"))),
            playbooks=tuple(_string_list(payload.get("playbooks"))),
            llm=bool(payload.get("llm")),
            active_probe=bool(payload.get("active_probe")),
            enabled=bool(payload.get("enabled", True)),
        )


@dataclass(frozen=True)
class SubagentWorkPolicy:
    mode: str = "conservative"
    max_parallel: int = 1
    cooldown_seconds: int = 120
    failure_circuit_breaker: int = 1
    prefer_local_verification: bool = True
    allowed_uses: tuple[str, ...] = (
        "independent code review after deterministic tests pass",
        "read-only architecture exploration with no shared file edits",
        "disjoint implementation task with explicit file ownership",
    )
    blocked_after: tuple[str, ...] = (
        "429 Too Many Requests",
        "rate limit",
        "quota",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "max_parallel": self.max_parallel,
            "cooldown_seconds": self.cooldown_seconds,
            "failure_circuit_breaker": self.failure_circuit_breaker,
            "prefer_local_verification": self.prefer_local_verification,
            "allowed_uses": list(self.allowed_uses),
            "blocked_after": list(self.blocked_after),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> SubagentWorkPolicy:
        default = default_subagent_work_policy()
        return cls(
            mode=str(payload.get("mode") or default.mode),
            max_parallel=_int_value(payload.get("max_parallel"), default.max_parallel),
            cooldown_seconds=_int_value(payload.get("cooldown_seconds"), default.cooldown_seconds),
            failure_circuit_breaker=_int_value(payload.get("failure_circuit_breaker"), default.failure_circuit_breaker),
            prefer_local_verification=_bool_value(payload.get("prefer_local_verification"), default.prefer_local_verification),
            allowed_uses=tuple(_string_list(payload.get("allowed_uses")) or default.allowed_uses),
            blocked_after=tuple(_string_list(payload.get("blocked_after")) or default.blocked_after),
        )


@dataclass(frozen=True)
class AgentRoster:
    version: int
    coordinator: AgentIdentity
    agents: tuple[AgentIdentity, ...] = field(default_factory=tuple)
    subagent_work_policy: SubagentWorkPolicy = field(default_factory=lambda: default_subagent_work_policy())
    warnings: tuple[str, ...] = ()

    def active_agents_for(self, category: ChallengeCategory) -> tuple[AgentIdentity, ...]:
        if category == ChallengeCategory.UNKNOWN:
            return tuple(agent for agent in self.agents if agent.enabled)
        return tuple(agent for agent in self.agents if agent.enabled and agent.applies_to(category))

    def managed_solver_names(self) -> tuple[str, ...]:
        names: list[str] = []
        for agent in self.agents:
            names.extend(agent.solvers)
        return tuple(_dedupe(names))

    def solver_names_for(self, category: ChallengeCategory) -> tuple[str, ...]:
        names: list[str] = []
        for agent in self.active_agents_for(category):
            names.extend(agent.solvers)
        return tuple(
            name
            for name in _dedupe(names)
            if name not in {"Verifier", "ReportBuilder"}
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "coordinator": self.coordinator.to_dict(),
            "agents": [agent.to_dict() for agent in self.agents],
            "subagent_work_policy": self.subagent_work_policy.to_dict(),
            "warnings": list(self.warnings),
        }

    def to_public_dict(self) -> dict[str, Any]:
        return self.to_dict()

    def to_run_summary(self, category: ChallengeCategory, solver_names: list[str] | tuple[str, ...]) -> dict[str, Any]:
        executed = set(solver_names)
        active = tuple(
            agent
            for agent in self.active_agents_for(category)
            if agent.solvers and any(solver in executed for solver in agent.solvers)
        )
        return {
            "version": self.version,
            "coordinator": self.coordinator.to_dict(),
            "category": category.value,
            "solver_queue": list(solver_names),
            "agents": [agent.to_dict() for agent in active],
            "subagent_work_policy": {
                "mode": self.subagent_work_policy.mode,
                "max_parallel": self.subagent_work_policy.max_parallel,
                "prefer_local_verification": self.subagent_work_policy.prefer_local_verification,
            },
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AgentRoster:
        coordinator_raw = payload.get("coordinator")
        default = default_agent_roster()
        coordinator = (
            _identity_from_dict_with_defaults(coordinator_raw, default.coordinator)
            if isinstance(coordinator_raw, dict)
            else default.coordinator
        )
        default_agents = {agent.id: agent for agent in default.agents}
        agents = tuple(
            _identity_from_dict_with_defaults(item, default_agents.get(str(item.get("id") or "")))
            for item in payload.get("agents", [])
            if isinstance(item, dict)
        )
        if "agents" not in payload:
            agents = default.agents
        policy_raw = payload.get("subagent_work_policy")
        policy = (
            SubagentWorkPolicy.from_dict(policy_raw)
            if isinstance(policy_raw, dict)
            else default_subagent_work_policy()
        )
        return cls(
            version=_int_value(payload.get("version"), 1),
            coordinator=coordinator,
            agents=agents,
            subagent_work_policy=policy,
            warnings=tuple(_string_list(payload.get("warnings"))),
        )


def _identity_from_dict_with_defaults(payload: dict[str, Any], fallback: AgentIdentity | None) -> AgentIdentity:
    if fallback is None:
        return AgentIdentity.from_dict(payload)
    merged = dict(payload)
    for field_name in (
        "team_type",
        "reports_to",
        "cadence",
        "success_metrics",
        "deliverables",
    ):
        if field_name not in merged:
            value = getattr(fallback, field_name)
            merged[field_name] = list(value) if isinstance(value, tuple) else value
    return AgentIdentity.from_dict(
        merged,
        team_type_default=fallback.team_type,
        reports_to_default=fallback.reports_to,
    )


def agent_roster_path_for_db(db_path: str | Path) -> Path:
    return Path(db_path).parent / "agent-roster.json"


def load_agent_roster(path: str | Path | None = None) -> AgentRoster:
    if path is None:
        return default_agent_roster()
    roster_path = Path(path)
    if not roster_path.exists():
        return default_agent_roster()
    try:
        payload = json.loads(roster_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("agent roster config must be a JSON object")
        return AgentRoster.from_dict(payload)
    except Exception as exc:  # noqa: BLE001 - hand-edited config must not break runs.
        fallback = default_agent_roster()
        return AgentRoster(
            version=fallback.version,
            coordinator=fallback.coordinator,
            agents=fallback.agents,
            subagent_work_policy=fallback.subagent_work_policy,
            warnings=(f"{roster_path.name} could not be loaded: {exc}",),
        )


def write_default_agent_roster(path: str | Path) -> AgentRoster:
    roster = default_agent_roster()
    roster_path = Path(path)
    roster_path.parent.mkdir(parents=True, exist_ok=True)
    roster_path.write_text(json.dumps(roster.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return roster


def default_agent_roster() -> AgentRoster:
    coordinator = AgentIdentity(
        id="forgeflag-manager",
        name="ForgeFlagManager",
        mission="Coordinate scoped CTF solving, keep evidence in the notebook, and decide the next solver route.",
        responsibilities=(
            "Select category specialists for the challenge.",
            "Preserve solver evidence, observations, verification status, and write-up data.",
            "Keep active probing within explicit scope.",
        ),
        team_type="manager",
        reports_to="",
        cadence="continuous",
        success_metrics=(
            "held-out pass rate",
            "hard evidence score",
            "browser UI flow rate",
            "scope safety rate",
        ),
        deliverables=(
            "prioritized improvement backlog",
            "accepted flag summary",
            "reproducible write-up",
            "benchmark status",
        ),
        solvers=("ReconSolver", "LLMSolver", "WebSolver", "CryptoSolver", "ReverseSolver", "PwnSolver", "ForensicsSolver", "TrafficSolver", "MiscSolver", "InfraSolver"),
    )
    agents = (
        AgentIdentity(
            id="challenge-triage",
            name="ChallengeTriageAgent",
            mission="Read the statement, metadata, and attachment summary to correct category routing before deep solving.",
            responsibilities=("Classify the challenge.", "Identify suspicious attachment types.", "Choose the first specialist route."),
            team_type="stream-aligned",
            cadence="per challenge",
            success_metrics=("correct category routing", "first-pass solver fit"),
            deliverables=("triage summary", "solver route recommendation"),
            solvers=("ReconSolver",),
            playbooks=("docs/ctf-playbook.md",),
        ),
        AgentIdentity(
            id="llm-route-planner",
            name="LLMRoutePlannerAgent",
            mission="Use the configured LLM to produce hypotheses, tool routes, and expected evidence without guessing flags.",
            responsibilities=("Generate Planner v2 JSON.", "Suggest exact ForgeFlag solver names.", "Explain missing evidence and fallback routes."),
            team_type="enabling",
            cadence="when deterministic routing stalls",
            success_metrics=("valid planner json", "useful fallback route", "no unsupported flag claims"),
            deliverables=("hypothesis plan", "expected evidence list", "fallback actions"),
            solvers=("LLMSolver",),
            playbooks=("src/forgeflag/llm_prompts.py", "docs/ctf-playbook.md"),
            llm=True,
        ),
        AgentIdentity(
            id="web-exploit",
            name="WebExploitAgent",
            mission="Analyze scoped Web challenges for routes, API leaks, JWT/session bugs, SSRF, and path traversal evidence.",
            responsibilities=("Inspect source routes and sinks.", "Probe allowlisted targets only when active probing is enabled.", "Extract flags from response bodies, headers, and cookies."),
            team_type="stream-aligned",
            cadence="per web challenge",
            success_metrics=("web flag acceptance", "source evidence completeness", "active probe scope compliance"),
            deliverables=("route evidence", "source sink notes", "scoped request transcript"),
            categories=("web",),
            solvers=("WebSolver",),
            tools=("http_probe", "ffuf", "nmap_tcp_basic"),
            active_probe=True,
        ),
        AgentIdentity(
            id="crypto-math",
            name="CryptoMathAgent",
            mission="Recognize crypto primitives and produce reproducible recovery routes for encodings, XOR, RSA, AES misuse, oracle, and lattice-style tasks.",
            responsibilities=("Run bounded transform candidates.", "Summarize RSA and hash parameters.", "Recommend Sage/RsaCtfTool/Z3 when deterministic recovery is not yet implemented."),
            team_type="complicated-subsystem",
            cadence="per crypto or math-heavy misc challenge",
            success_metrics=("crypto flag acceptance", "parameter extraction quality", "scripted replay coverage"),
            deliverables=("primitive classification", "recovery script", "math-tool recommendation"),
            categories=("crypto", "misc"),
            solvers=("CryptoSolver", "MiscSolver"),
            tools=("RsaCtfTool", "hashcat", "john"),
        ),
        AgentIdentity(
            id="binary-agent",
            name="BinaryAgent",
            mission="Handle reverse and pwn binaries with static triage, exploit-pattern recognition, and IDA/Ghidra route suggestions.",
            responsibilities=("Run file/strings/objdump/readelf/radare2/checksec/gadget triage.", "Identify ret2win and format-string patterns.", "Prepare crash harness and pwntools template hints."),
            team_type="complicated-subsystem",
            cadence="per reverse or pwn challenge",
            success_metrics=("binary flag acceptance", "local artifact evidence", "harness replay coverage"),
            deliverables=("static triage", "validation logic notes", "bounded exploit harness"),
            categories=("reverse", "pwn"),
            solvers=("ReverseSolver", "PwnSolver"),
            tools=("file", "strings", "objdump", "readelf", "radare2", "checksec", "ROPgadget", "ropper", "ida-mcp"),
            playbooks=("docs/tool-containers.md",),
        ),
        AgentIdentity(
            id="forensics-agent",
            name="ForensicsAgent",
            mission="Triage files, images, archives, metadata, macros, scripts, and stego-style evidence.",
            responsibilities=("Inspect file metadata and strings.", "Detect PNG/JPEG/archive clues.", "Run carving and YARA follow-up when broad triage stalls.", "Promote extracted artifacts and flags into notebook evidence."),
            team_type="stream-aligned",
            cadence="per forensics or file-heavy misc challenge",
            success_metrics=("artifact extraction rate", "forensics flag acceptance", "evidence hash coverage"),
            deliverables=("artifact inventory", "extraction notes", "flag candidate evidence"),
            categories=("forensics", "misc"),
            solvers=("ForensicsSolver", "MiscSolver"),
            tools=("file", "strings", "binwalk", "exiftool", "foremost", "yara"),
        ),
        AgentIdentity(
            id="traffic-agent",
            name="TrafficAgent",
            mission="Reconstruct PCAP evidence across HTTP, DNS, SMTP, FTP, IRC-style streams, and exported objects.",
            responsibilities=("Summarize flows and protocols.", "Decode DNS/HTTP exfil patterns.", "Shortlist TCP streams and exported objects for flag recovery."),
            team_type="stream-aligned",
            cadence="per traffic or pcap-backed challenge",
            success_metrics=("traffic flag acceptance", "stream reconstruction coverage", "exported artifact replay"),
            deliverables=("flow summary", "stream shortlist", "extracted artifact evidence"),
            categories=("traffic", "forensics"),
            solvers=("TrafficSolver", "ForensicsSolver"),
            tools=("tshark", "tshark_dns_summary", "tshark_tcp_streams", "tshark_http_requests", "tshark_http_object_export"),
        ),
        AgentIdentity(
            id="evidence-judge",
            name="EvidenceJudgeAgent",
            mission="Accept only evidence-backed flags, reject unsupported candidates, and keep the shortest reproducible discovery path.",
            responsibilities=("Verify candidates from findings.", "Record rejected candidates.", "Ensure Write-up focuses on solving idea and reproduction steps."),
            team_type="enabling",
            cadence="every run",
            success_metrics=("accepted flag evidence coverage", "rejected candidate clarity", "write-up replay completeness"),
            deliverables=("verification decision", "rejected candidate log", "reproducible write-up"),
            solvers=("Verifier", "ReportBuilder"),
            playbooks=("src/forgeflag/report.py", "src/forgeflag/verifier.py"),
        ),
        AgentIdentity(
            id="browser-player-qa",
            name="BrowserPlayerQAAgent",
            mission="Operate ForgeFlag through the Web UI like a CTF player and catch UX or workflow regressions.",
            responsibilities=("Create challenges through visible controls.", "Upload attachments and run selected challenges.", "Inspect Summary and Write-up before deleting cleanup fixtures."),
            team_type="enabling",
            cadence="after UI or workflow changes",
            success_metrics=("browser UI flow rate", "workflow regression count", "write-up visibility"),
            deliverables=("browser benchmark result", "UI regression note", "player workflow finding"),
            solvers=(),
            tools=("playwright",),
            playbooks=("scripts/forgeflag-web-player-benchmark", "docs/web-player-benchmark.md"),
        ),
    )
    return AgentRoster(version=1, coordinator=coordinator, agents=agents, subagent_work_policy=default_subagent_work_policy())


def default_subagent_work_policy() -> SubagentWorkPolicy:
    return SubagentWorkPolicy()


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _int_value(value: object, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _bool_value(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    if value is None:
        return default
    return bool(value)


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result

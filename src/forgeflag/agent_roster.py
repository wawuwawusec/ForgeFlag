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
            "categories": list(self.categories),
            "solvers": list(self.solvers),
            "tools": list(self.tools),
            "playbooks": list(self.playbooks),
            "llm": self.llm,
            "active_probe": self.active_probe,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AgentIdentity:
        return cls(
            id=str(payload.get("id") or ""),
            name=str(payload.get("name") or ""),
            mission=str(payload.get("mission") or ""),
            responsibilities=tuple(_string_list(payload.get("responsibilities"))),
            categories=tuple(_string_list(payload.get("categories")) or ["*"]),
            solvers=tuple(_string_list(payload.get("solvers"))),
            tools=tuple(_string_list(payload.get("tools"))),
            playbooks=tuple(_string_list(payload.get("playbooks"))),
            llm=bool(payload.get("llm")),
            active_probe=bool(payload.get("active_probe")),
            enabled=bool(payload.get("enabled", True)),
        )


@dataclass(frozen=True)
class AgentRoster:
    version: int
    coordinator: AgentIdentity
    agents: tuple[AgentIdentity, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = ()

    def active_agents_for(self, category: ChallengeCategory) -> tuple[AgentIdentity, ...]:
        return tuple(agent for agent in self.agents if agent.enabled and agent.applies_to(category))

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "coordinator": self.coordinator.to_dict(),
            "agents": [agent.to_dict() for agent in self.agents],
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
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AgentRoster:
        coordinator_raw = payload.get("coordinator")
        coordinator = (
            AgentIdentity.from_dict(coordinator_raw)
            if isinstance(coordinator_raw, dict)
            else default_agent_roster().coordinator
        )
        agents = tuple(
            AgentIdentity.from_dict(item)
            for item in payload.get("agents", [])
            if isinstance(item, dict)
        )
        if "agents" not in payload:
            agents = default_agent_roster().agents
        return cls(
            version=_int_value(payload.get("version"), 1),
            coordinator=coordinator,
            agents=agents,
            warnings=tuple(_string_list(payload.get("warnings"))),
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
        solvers=("ReconSolver", "LLMSolver", "WebSolver", "CryptoSolver", "ReverseSolver", "PwnSolver", "ForensicsSolver", "TrafficSolver", "MiscSolver", "InfraSolver"),
    )
    agents = (
        AgentIdentity(
            id="challenge-triage",
            name="ChallengeTriageAgent",
            mission="Read the statement, metadata, and attachment summary to correct category routing before deep solving.",
            responsibilities=("Classify the challenge.", "Identify suspicious attachment types.", "Choose the first specialist route."),
            solvers=("ReconSolver",),
            playbooks=("docs/ctf-playbook.md",),
        ),
        AgentIdentity(
            id="llm-route-planner",
            name="LLMRoutePlannerAgent",
            mission="Use the configured LLM to produce hypotheses, tool routes, and expected evidence without guessing flags.",
            responsibilities=("Generate Planner v2 JSON.", "Suggest exact ForgeFlag solver names.", "Explain missing evidence and fallback routes."),
            solvers=("LLMSolver",),
            playbooks=("src/forgeflag/llm_prompts.py", "docs/ctf-playbook.md"),
            llm=True,
        ),
        AgentIdentity(
            id="web-exploit",
            name="WebExploitAgent",
            mission="Analyze scoped Web challenges for routes, API leaks, JWT/session bugs, SSRF, and path traversal evidence.",
            responsibilities=("Inspect source routes and sinks.", "Probe allowlisted targets only when active probing is enabled.", "Extract flags from response bodies, headers, and cookies."),
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
            categories=("crypto", "misc"),
            solvers=("CryptoSolver", "MiscSolver"),
            tools=("RsaCtfTool", "hashcat", "john"),
        ),
        AgentIdentity(
            id="binary-agent",
            name="BinaryAgent",
            mission="Handle reverse and pwn binaries with static triage, exploit-pattern recognition, and IDA/Ghidra route suggestions.",
            responsibilities=("Run file/strings/checksec/gadget triage.", "Identify ret2win and format-string patterns.", "Prepare crash harness and pwntools template hints."),
            categories=("reverse", "pwn"),
            solvers=("ReverseSolver", "PwnSolver"),
            tools=("file", "strings", "checksec", "ROPgadget", "ropper", "ida-mcp"),
            playbooks=("docs/tool-containers.md",),
        ),
        AgentIdentity(
            id="forensics-agent",
            name="ForensicsAgent",
            mission="Triage files, images, archives, metadata, macros, scripts, and stego-style evidence.",
            responsibilities=("Inspect file metadata and strings.", "Detect PNG/JPEG/archive clues.", "Promote extracted artifacts and flags into notebook evidence."),
            categories=("forensics", "misc"),
            solvers=("ForensicsSolver", "MiscSolver"),
            tools=("file", "strings", "binwalk", "exiftool"),
        ),
        AgentIdentity(
            id="traffic-agent",
            name="TrafficAgent",
            mission="Reconstruct PCAP evidence across HTTP, DNS, SMTP, FTP, IRC-style streams, and exported objects.",
            responsibilities=("Summarize flows and protocols.", "Decode DNS/HTTP exfil patterns.", "Shortlist TCP streams and exported objects for flag recovery."),
            categories=("traffic", "forensics"),
            solvers=("TrafficSolver", "ForensicsSolver"),
            tools=("tshark", "tshark_dns_summary", "tshark_tcp_streams", "tshark_http_requests", "tshark_http_object_export"),
        ),
        AgentIdentity(
            id="evidence-judge",
            name="EvidenceJudgeAgent",
            mission="Accept only evidence-backed flags, reject unsupported candidates, and keep the shortest reproducible discovery path.",
            responsibilities=("Verify candidates from findings.", "Record rejected candidates.", "Ensure Write-up focuses on solving idea and reproduction steps."),
            solvers=("Verifier", "ReportBuilder"),
            playbooks=("src/forgeflag/report.py", "src/forgeflag/verifier.py"),
        ),
        AgentIdentity(
            id="browser-player-qa",
            name="BrowserPlayerQAAgent",
            mission="Operate ForgeFlag through the Web UI like a CTF player and catch UX or workflow regressions.",
            responsibilities=("Create challenges through visible controls.", "Upload attachments and run selected challenges.", "Inspect Summary and Write-up before deleting cleanup fixtures."),
            solvers=(),
            tools=("playwright",),
            playbooks=("scripts/forgeflag-web-player-benchmark", "docs/web-player-benchmark.md"),
        ),
    )
    return AgentRoster(version=1, coordinator=coordinator, agents=agents)


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _int_value(value: object, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default

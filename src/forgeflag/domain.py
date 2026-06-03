from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import os
import shlex
from typing import Any


DEFAULT_ZHIPU_MODEL = "glm-5.1"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class ChallengeCategory(StrEnum):
    RECON = "recon"
    WEB = "web"
    PWN = "pwn"
    REVERSE = "reverse"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    TRAFFIC = "traffic"
    MISC = "misc"
    INFRA = "infra"
    UNKNOWN = "unknown"


class FindingStatus(StrEnum):
    ACTIVE = "active"
    VERIFIED = "verified"
    REJECTED = "rejected"
    STALE = "stale"


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    category: ChallengeCategory = ChallengeCategory.UNKNOWN
    title: str | None = None
    target: str | None = None
    description: str | None = None
    tags: tuple[str, ...] = ()
    attachment_paths: tuple[str, ...] = ()
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class Finding:
    challenge_id: str
    solver: str
    finding: str
    evidence: dict[str, Any] = field(default_factory=dict)
    hypothesis: str | None = None
    confidence: float = 0.0
    next_action: str | None = None
    status: FindingStatus = FindingStatus.ACTIVE
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class Observation:
    challenge_id: str
    source: str
    kind: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class ToolResult:
    tool: str
    target: str | None
    status: str
    evidence: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    next_hints: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class SolverResult:
    solver: str
    challenge_id: str
    status: str
    findings: tuple[Finding, ...] = ()
    flag_candidates: tuple[str, ...] = ()
    notes: str | None = None


@dataclass(frozen=True)
class LLMConfig:
    provider: str = "disabled"
    model: str | None = None
    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: int = 30
    max_retries: int = 2
    retry_initial_seconds: int = 1
    retry_max_seconds: int = 20
    cooldown_seconds: int = 120

    @property
    def enabled(self) -> bool:
        return self.provider != "disabled" and bool(self.model)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> LLMConfig:
        values = env if env is not None else os.environ
        provider = values.get("FORGEFLAG_LLM_PROVIDER", "disabled").strip().lower() or "disabled"
        model = values.get("FORGEFLAG_LLM_MODEL")
        if provider == "zhipu" and not model:
            model = DEFAULT_ZHIPU_MODEL
        api_key = values.get("FORGEFLAG_LLM_API_KEY")
        if provider == "openai":
            api_key = api_key or values.get("OPENAI_API_KEY")
        if provider == "zhipu":
            api_key = (
                api_key
                or values.get("ZAI_API_KEY")
                or values.get("ZHIPU_API_KEY")
                or values.get("ZHIPUAI_API_KEY")
                or values.get("BIGMODEL_API_KEY")
            )
        timeout = _int_env(values.get("FORGEFLAG_LLM_TIMEOUT_SECONDS"), default=30)
        return cls(
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=values.get("FORGEFLAG_LLM_BASE_URL") or _default_llm_base_url(provider),
            timeout_seconds=timeout,
            max_retries=max(0, _int_env(values.get("FORGEFLAG_LLM_MAX_RETRIES"), default=2)),
            retry_initial_seconds=max(0, _int_env(values.get("FORGEFLAG_LLM_RETRY_INITIAL_SECONDS"), default=1)),
            retry_max_seconds=max(1, _int_env(values.get("FORGEFLAG_LLM_RETRY_MAX_SECONDS"), default=20)),
            cooldown_seconds=max(0, _int_env(values.get("FORGEFLAG_LLM_COOLDOWN_SECONDS"), default=120)),
        )


@dataclass(frozen=True)
class IDAMCPConfig:
    enabled: bool = False
    command: tuple[str, ...] = ("ida-mcp", "--read-only")
    read_only: bool = True
    timeout_seconds: int = 30

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> IDAMCPConfig:
        values = env if env is not None else os.environ
        enabled = _bool_env(values.get("FORGEFLAG_IDA_MCP_ENABLED"), default=False)
        command = tuple(shlex.split(values.get("FORGEFLAG_IDA_MCP_COMMAND", "ida-mcp --read-only")))
        if not command:
            command = ("ida-mcp", "--read-only")
        read_only = _bool_env(values.get("FORGEFLAG_IDA_MCP_READ_ONLY"), default=True)
        timeout = _int_env(values.get("FORGEFLAG_IDA_MCP_TIMEOUT_SECONDS"), default=30)
        return cls(enabled=enabled, command=command, read_only=read_only, timeout_seconds=timeout)


@dataclass(frozen=True)
class RunConfig:
    max_iterations: int = 20
    max_solver_repeats: int = 3
    active_probe: bool = False
    allowed_hosts: tuple[str, ...] = ()
    llm_config: LLMConfig = field(default_factory=LLMConfig.from_env)
    ida_mcp_config: IDAMCPConfig = field(default_factory=IDAMCPConfig.from_env)


def _int_env(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _bool_env(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _default_llm_base_url(provider: str) -> str:
    if provider == "zhipu":
        return "https://open.bigmodel.cn/api/paas/v4"
    return "https://api.openai.com/v1"

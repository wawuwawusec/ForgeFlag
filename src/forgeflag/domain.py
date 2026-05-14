from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class ChallengeCategory(StrEnum):
    RECON = "recon"
    WEB = "web"
    PWN = "pwn"
    REVERSE = "reverse"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
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
class RunConfig:
    max_iterations: int = 20
    max_solver_repeats: int = 3
    active_probe: bool = False
    allowed_hosts: tuple[str, ...] = ()

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from forgeflag.domain import Challenge, ChallengeCategory, SolverResult
from forgeflag.notebook import SQLiteNotebook
from forgeflag.safety import ScopePolicy


@dataclass(frozen=True)
class SolverContext:
    challenge: Challenge
    notebook: SQLiteNotebook
    scope: ScopePolicy


class Solver(Protocol):
    name: str
    supported_categories: set[ChallengeCategory]

    def solve(self, context: SolverContext) -> SolverResult:
        ...


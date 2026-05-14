from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from forgeflag.domain import RunConfig


@dataclass
class HarnessDecision:
    allowed: bool
    reason: str | None = None


@dataclass
class Harness:
    config: RunConfig
    iterations: int = 0
    solver_counts: Counter[str] = field(default_factory=Counter)

    def before_solver(self, solver_name: str) -> HarnessDecision:
        if self.iterations >= self.config.max_iterations:
            return HarnessDecision(False, "max iterations reached")
        if self.solver_counts[solver_name] >= self.config.max_solver_repeats:
            return HarnessDecision(False, f"solver repeat limit reached for {solver_name}")
        return HarnessDecision(True)

    def after_solver(self, solver_name: str) -> None:
        self.iterations += 1
        self.solver_counts[solver_name] += 1

    def summary(self) -> dict[str, object]:
        return {
            "iterations": self.iterations,
            "solver_counts": dict(self.solver_counts),
            "max_iterations": self.config.max_iterations,
            "max_solver_repeats": self.config.max_solver_repeats,
        }


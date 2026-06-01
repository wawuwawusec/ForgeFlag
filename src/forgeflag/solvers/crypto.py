from __future__ import annotations

from pathlib import Path

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf
from forgeflag.transforms import candidates_to_payload, transform_candidates


class CryptoSolver:
    name = "CryptoSolver"
    supported_categories = {ChallengeCategory.CRYPTO}

    def solve(self, context: SolverContext) -> SolverResult:
        candidates = transform_candidates("\n".join(_text_inputs(context)))
        flags = extract_flags("\n".join(candidate.value for candidate in candidates))
        if candidates:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Decoded crypto transform candidates",
                evidence={"transform_candidates": candidates_to_payload(candidates)},
                hypothesis=_transform_hypothesis(flags),
                confidence=0.82 if flags else 0.56,
                next_action=_transform_next_action(flags),
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate" if flags else "ok",
                (finding,),
                flags,
            )

        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Crypto solver placeholder registered",
            evidence={"planned_adapters": ["z3", "sage", "hash/fingerprint classifiers"]},
            hypothesis="Future implementation should extract parameters and generate reproducible solve scripts.",
            confidence=0.4,
            next_action="Implement primitive fingerprinting and solver script workspace.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))


def _text_inputs(context: SolverContext) -> list[str]:
    challenge = context.challenge
    values = [
        challenge.title or "",
        challenge.description or "",
        " ".join(challenge.tags),
    ]
    for attachment_path in challenge.attachment_paths:
        try:
            resolved = ctf.ensure_existing_file(attachment_path)
        except FileNotFoundError:
            continue
        try:
            raw = Path(resolved).read_bytes()[:64_000]
        except OSError:
            continue
        values.append(raw.decode("utf-8", errors="ignore"))
    return [value for value in values if value.strip()]


def _transform_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "A reversible transform chain produced a flag-like token."
    return "Challenge text contains encoded or transformed data worth preserving for the next solver step."


def _transform_next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send decoded candidates to Verifier and preserve the transform recipe."
    return "Inspect transform candidates for keys, parameters, or secondary encodings."

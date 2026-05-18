from __future__ import annotations

from pathlib import Path

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.image import analyze_png_ihdr
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf


class MiscSolver:
    name = "MiscSolver"
    supported_categories = {ChallengeCategory.MISC}

    def solve(self, context: SolverContext) -> SolverResult:
        image_findings = self._analyze_image_attachments(context)
        if image_findings:
            return SolverResult(self.name, context.challenge.challenge_id, "ok", tuple(image_findings))

        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Misc solver placeholder registered",
            evidence={"planned_adapters": ["archive triage", "encoding detection", "osint-style CTF artifact parsing"]},
            hypothesis="Future implementation should route unusual artifacts into the closest specialist workflow.",
            confidence=0.35,
            next_action="Implement archive, encoding, and puzzle triage.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))

    def _analyze_image_attachments(self, context: SolverContext) -> list[Finding]:
        findings: list[Finding] = []
        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = Path(ctf.ensure_existing_file(attachment_path))
            except FileNotFoundError:
                continue
            png_ihdr = analyze_png_ihdr(resolved)
            if not png_ihdr:
                continue
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed misc image artifact",
                evidence={
                    "artifact": {"name": resolved.name, "path": str(resolved)},
                    "png_ihdr": png_ihdr,
                },
                hypothesis="Misc image puzzle has PNG structure evidence that should be inspected before broader puzzle triage.",
                confidence=0.72,
                next_action="Open the repaired PNG, then inspect visible hints, channels, and bit planes.",
            )
            context.notebook.add_finding(finding)
            findings.append(finding)
        return findings

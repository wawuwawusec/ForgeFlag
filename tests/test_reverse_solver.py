from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import Challenge, ChallengeCategory, ToolResult
from forgeflag.notebook import SQLiteNotebook
from forgeflag.safety import ScopePolicy
from forgeflag.solvers.base import SolverContext
from forgeflag.solvers.reverse import ReverseSolver


class ReverseSolverTest(unittest.TestCase):
    def test_reverse_solver_triages_binary_with_strings_and_gadget_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "rev.bin"
            binary.write_bytes(b"fake elf")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="rev-triage",
                category=ChallengeCategory.REVERSE,
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            with (
                patch(
                    "forgeflag.solvers.reverse.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "ELF 64-bit"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": "check_flag\nmain"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="missing", evidence=["not installed"]),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", evidence=["not installed"]),
                ),
            ):
                result = ReverseSolver().solve(
                    SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy())
                )
                finding = notebook.findings_for("rev-triage")[0]

        self.assertEqual(result.status, "ok")
        self.assertEqual(finding.finding, "Analyzed reverse binary artifact")
        self.assertEqual(finding.evidence["tool_statuses"]["strings_extract"], "success")
        self.assertEqual(finding.evidence["tool_statuses"]["ropgadget_scan"], "missing")
        self.assertIn("check_flag", finding.evidence["tool_samples"]["strings_extract"]["stdout"])


if __name__ == "__main__":
    unittest.main()

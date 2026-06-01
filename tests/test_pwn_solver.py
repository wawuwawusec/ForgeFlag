from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import Challenge, ChallengeCategory, ToolResult
from forgeflag.notebook import SQLiteNotebook
from forgeflag.safety import ScopePolicy
from forgeflag.solvers.base import SolverContext
from forgeflag.solvers.pwn import PwnSolver


class PwnSolverTest(unittest.TestCase):
    def test_pwn_solver_triages_binary_with_gadget_tools_and_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "pwn"
            binary.write_bytes(b"fake elf")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="pwn-triage",
                category=ChallengeCategory.PWN,
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            with (
                patch(
                    "forgeflag.solvers.pwn.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "ELF 64-bit"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": "flag{pwn_string}"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.checksec_binary",
                    return_value=ToolResult(tool="checksec", target=None, status="success", raw={"stdout": "NX enabled"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="missing", evidence=["not installed"]),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", evidence=["not installed"]),
                ),
            ):
                result = PwnSolver().solve(
                    SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy())
                )
                finding = notebook.findings_for("pwn-triage")[0]

        self.assertEqual(result.status, "flag_candidate")
        self.assertEqual(result.flag_candidates, ("flag{pwn_string}",))
        self.assertEqual(finding.finding, "Analyzed pwn binary artifact")
        self.assertEqual(finding.evidence["tool_statuses"]["checksec_binary"], "success")
        self.assertEqual(finding.evidence["tool_statuses"]["ropgadget_scan"], "missing")
        self.assertEqual(finding.evidence["tool_statuses"]["ropper_scan"], "missing")


if __name__ == "__main__":
    unittest.main()

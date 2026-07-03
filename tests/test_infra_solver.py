from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers import InfraSolver


class InfraSolverTest(unittest.TestCase):
    def test_infra_solver_records_ctf_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="infra-scope", category=ChallengeCategory.INFRA))

            summary = Manager(notebook, RunConfig(), solvers=[InfraSolver()]).run_challenge("infra-scope")
            finding = next(f for f in notebook.findings_for("infra-scope") if f.solver == "InfraSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.evidence["ctf_scope"]["category"], "infra")
        self.assertEqual(finding.evidence["ctf_scope"]["research_context"], "local_or_authorized_ctf_lab")


if __name__ == "__main__":
    unittest.main()

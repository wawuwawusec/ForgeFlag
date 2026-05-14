from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook


class WorkflowTest(unittest.TestCase):
    def test_manager_records_recon_and_web_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="web-01",
                    category=ChallengeCategory.WEB,
                    target="http://127.0.0.1:8080",
                    tags=("login",),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("web-01")
            findings = notebook.findings_for("web-01")

        self.assertEqual(summary["status"], "completed")
        self.assertGreaterEqual(len(findings), 2)
        self.assertEqual(findings[0].solver, "ReconSolver")
        self.assertTrue(any(f.solver == "WebSolver" for f in findings))

    def test_unknown_category_still_runs_recon(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="misc-unknown", tags=("rsa",)))

            summary = Manager(notebook, RunConfig()).run_challenge("misc-unknown")
            findings = notebook.findings_for("misc-unknown")

        self.assertEqual(summary["status"], "completed")
        self.assertTrue(any("category=crypto" in f.finding for f in findings))

    def test_all_declared_categories_have_solver_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            categories = [
                ChallengeCategory.WEB,
                ChallengeCategory.PWN,
                ChallengeCategory.REVERSE,
                ChallengeCategory.CRYPTO,
                ChallengeCategory.FORENSICS,
                ChallengeCategory.MISC,
                ChallengeCategory.INFRA,
            ]
            for category in categories:
                notebook.add_challenge(Challenge(challenge_id=f"{category.value}-01", category=category))
                summary = Manager(notebook, RunConfig()).run_challenge(f"{category.value}-01")
                self.assertEqual(summary["status"], "completed")

                findings = notebook.findings_for(f"{category.value}-01")
                self.assertGreaterEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()

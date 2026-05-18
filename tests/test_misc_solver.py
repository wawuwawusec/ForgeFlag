from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from tests.png_fixtures import png_with_wrong_declared_height


class MiscSolverTest(unittest.TestCase):
    def test_misc_solver_runs_png_ihdr_analysis_for_image_puzzle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "ihdr.png"
            attachment.write_bytes(png_with_wrong_declared_height(width=2, actual_height=3, declared_height=9))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="ihdr-misc",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("ihdr-misc")
            finding = next(f for f in notebook.findings_for("ihdr-misc") if f.solver == "MiscSolver")

            self.assertEqual(summary["status"], "completed")
            self.assertEqual(finding.finding, "Analyzed misc image artifact")
            self.assertEqual(finding.evidence["png_ihdr"]["declared_height"], 9)
            self.assertEqual(finding.evidence["png_ihdr"]["derived_height"], 3)
            self.assertTrue(Path(finding.evidence["png_ihdr"]["repaired_path"]).is_file())


if __name__ == "__main__":
    unittest.main()

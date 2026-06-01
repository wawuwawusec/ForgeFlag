from __future__ import annotations

import tempfile
import unittest
import zipfile
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

    def test_misc_solver_decodes_flag_from_text_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "note.txt"
            attachment.write_text("Jmx0OyEtdm9pZC0tJmd0OyBmbGFnJTdCbWlzY190cmFuc2Zvcm0lN0Q=", encoding="utf-8")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-transform",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-transform")
            finding = next(f for f in notebook.findings_for("misc-transform") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{misc_transform}"])
        self.assertEqual(finding.finding, "Decoded misc transform candidates")
        recipes = {tuple(candidate["recipe"]) for candidate in finding.evidence["transform_candidates"]}
        self.assertIn(("base64_decode", "html_unescape", "url_decode"), recipes)

    def test_misc_solver_records_archive_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "puzzle.zip"
            with zipfile.ZipFile(attachment, "w") as zf:
                zf.writestr("secret.txt", "redacted")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-archive",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-archive")
            finding = next(f for f in notebook.findings_for("misc-archive") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Analyzed misc archive artifact")
        self.assertEqual(finding.evidence["archive"]["kind"], "zip")
        self.assertIn("secret.txt", finding.evidence["archive"]["interesting_entries"])


if __name__ == "__main__":
    unittest.main()

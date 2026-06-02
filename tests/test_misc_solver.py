from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from tests.png_fixtures import png_with_text_and_trailing_data, png_with_wrong_declared_height


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

    def test_misc_solver_records_image_stego_hints_and_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "hint.png"
            attachment.write_bytes(png_with_text_and_trailing_data("flag{png_text_chunk}"))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="png-stego-misc",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("png-stego-misc")
            finding = next(f for f in notebook.findings_for("png-stego-misc") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{png_text_chunk}"])
        self.assertEqual(finding.finding, "Analyzed misc image artifact")
        self.assertIn("image_stego", finding.evidence)
        self.assertEqual(finding.evidence["image_stego"]["text_chunks"][0]["keyword"], "Comment")

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

    def test_misc_solver_decodes_binary_ascii_attachment_with_metadata_noise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "binary.txt"
            attachment.write_text(
                "01100110 01101100 01100001 01100111 01111011 01100011 01101111 "
                "01110010 01110000 01110101 01110011 01011111 01101101 01101001 "
                "01110011 01100011 01111101\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-binary-corpus",
                    category=ChallengeCategory.MISC,
                    title="Corpus Misc binary ASCII",
                    description="Binary ASCII puzzle pattern.",
                    tags=("corpus", "web-smoke"),
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-binary-corpus")
            finding = next(f for f in notebook.findings_for("misc-binary-corpus") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{corpus_misc}"])
        recipes = {tuple(candidate["recipe"]) for candidate in finding.evidence["transform_candidates"]}
        self.assertIn(("binary_ascii_decode",), recipes)

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

    def test_misc_solver_extracts_flag_from_interesting_archive_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "nested.zip"
            with zipfile.ZipFile(attachment, "w") as zf:
                zf.writestr("docs/readme.txt", "look in the secret note")
                zf.writestr("secret/flag.txt", "flag{archive_text_preview}")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-archive-flag",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-archive-flag")
            finding = next(f for f in notebook.findings_for("misc-archive-flag") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{archive_text_preview}"])
        self.assertEqual(finding.evidence["archive_text_previews"][0]["name"], "secret/flag.txt")

    def test_misc_solver_records_hash_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "hash.txt"
            attachment.write_text("5d41402abc4b2a76b9719d911017c592", encoding="utf-8")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-hash",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-hash")
            finding = next(f for f in notebook.findings_for("misc-hash") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Analyzed misc hash candidates")
        self.assertEqual(finding.evidence["hashes"]["candidates"][0]["type"], "md5_or_ntlm")


if __name__ == "__main__":
    unittest.main()

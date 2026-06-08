from __future__ import annotations

import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig, ToolResult
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers import ForensicsSolver
from tests.png_fixtures import png_with_text_and_trailing_data, png_with_wrong_declared_height


@unittest.skipUnless(shutil.which("file") and shutil.which("strings"), "file and strings commands are required")
class ForensicsSolverTest(unittest.TestCase):
    def test_forensics_solver_triages_attachment_and_returns_flag_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "capture.bin"
            attachment.write_bytes(b"\x00noise\x00flag{artifact_solver}\x00")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-flag",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("forensics-flag")
            findings = notebook.findings_for("forensics-flag")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{artifact_solver}"])
        self.assertTrue(any(f.finding == "Triaged forensic attachment" for f in findings))
        forensic_finding = next(f for f in findings if f.finding == "Triaged forensic attachment")
        self.assertEqual(forensic_finding.evidence["artifact"]["name"], "capture.bin")
        self.assertIn("file", forensic_finding.evidence["tool_statuses"])
        self.assertIn("strings", forensic_finding.evidence["tool_statuses"])

    def test_forensics_solver_decodes_base64_mail_payload_hints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "powershell.eml"
            attachment.write_text(
                "Subject: urgent\n\nSuspicious command:\n"
                "cG93ZXJzaGVsbCAtZW5jIFpteGhaM3RrWldOdlpHVmtYMlJoZEdGOUNnPT0=\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-mail-base64",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("forensics-mail-base64")
            finding = next(f for f in notebook.findings_for("forensics-mail-base64") if f.solver == "ForensicsSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{decoded_data}"])
        self.assertIn("decoded_transform_candidates", finding.evidence)
        recipes = {tuple(candidate["recipe"]) for candidate in finding.evidence["decoded_transform_candidates"]}
        self.assertIn(("base64_decode", "base64_decode"), recipes)

    def test_forensics_solver_leaves_pcap_traffic_analysis_to_traffic_solver(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "capture.pcap"
            attachment.write_bytes(b"pcap fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-flag",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "pcap capture file"}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.binwalk_scan",
                    return_value=ToolResult(tool="binwalk", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.exiftool_read",
                    return_value=ToolResult(tool="exiftool", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "1 0.0 TCP"}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.tshark_traffic_analysis",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "Protocol Hierarchy"}),
                ) as traffic_analysis,
                patch(
                    "forgeflag.solvers.forensics.ctf.tshark_flag_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "flag{pcap_payload}"}),
                ) as flag_scan,
            ):
                Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("traffic-flag")
                finding = next(
                    f for f in notebook.findings_for("traffic-flag") if f.finding == "Triaged forensic attachment"
                )

        traffic_analysis.assert_not_called()
        flag_scan.assert_not_called()
        self.assertNotIn("tshark_traffic_analysis", finding.evidence["tool_statuses"])
        self.assertNotIn("tshark_flag_scan", finding.evidence["tool_statuses"])

    def test_forensics_solver_detects_png_ihdr_height_mismatch_and_writes_repair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "ihdr.png"
            attachment.write_bytes(png_with_wrong_declared_height(width=2, actual_height=3, declared_height=9))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="ihdr-forensics",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "PNG image data"}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.binwalk_scan",
                    return_value=ToolResult(tool="binwalk", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.exiftool_read",
                    return_value=ToolResult(tool="exiftool", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("ihdr-forensics")
                finding = next(
                    f for f in notebook.findings_for("ihdr-forensics") if f.finding == "Triaged forensic attachment"
                )

            png_evidence = finding.evidence["png_ihdr"]
            self.assertEqual(png_evidence["declared_height"], 9)
            self.assertEqual(png_evidence["derived_height"], 3)
            self.assertFalse(png_evidence["ihdr_crc_ok"])
            self.assertTrue(Path(png_evidence["repaired_path"]).is_file())

    def test_forensics_solver_records_image_stego_hints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "hint.png"
            attachment.write_bytes(png_with_text_and_trailing_data("look deeper", trailing=b"hidden-tail"))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="stego-forensics",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "PNG image data"}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.binwalk_scan",
                    return_value=ToolResult(tool="binwalk", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.exiftool_read",
                    return_value=ToolResult(tool="exiftool", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("stego-forensics")
                finding = next(
                    f for f in notebook.findings_for("stego-forensics") if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(finding.evidence["image_stego"]["format"], "png")
        self.assertEqual(finding.evidence["image_stego"]["trailing_data"]["length"], len(b"hidden-tail"))

    def test_forensics_solver_records_magic_extension_mismatch_for_png_named_jpg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "evidence.jpg"
            attachment.write_bytes(png_with_text_and_trailing_data("flag{forensics_wrong_extension}"))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-wrong-extension",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "PNG image data"}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.binwalk_scan",
                    return_value=ToolResult(tool="binwalk", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.exiftool_read",
                    return_value=ToolResult(tool="exiftool", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("forensics-wrong-extension")
                finding = next(
                    f for f in notebook.findings_for("forensics-wrong-extension")
                    if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{forensics_wrong_extension}"])
        self.assertEqual(finding.evidence["magic_extension_mismatch"]["declared_extension"], "jpg")
        self.assertEqual(finding.evidence["magic_extension_mismatch"]["actual_format"], "png")

    def test_forensics_solver_records_archive_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "bundle.zip"
            with zipfile.ZipFile(attachment, "w") as zf:
                zf.writestr("flag.txt", "redacted")
                zf.writestr("hint/readme.txt", "look deeper")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="archive-forensics",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "Zip archive data"}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.binwalk_scan",
                    return_value=ToolResult(tool="binwalk", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.exiftool_read",
                    return_value=ToolResult(tool="exiftool", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("archive-forensics")
                finding = next(
                    f for f in notebook.findings_for("archive-forensics") if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(finding.evidence["archive"]["kind"], "zip")
        self.assertIn("flag.txt", finding.evidence["archive"]["interesting_entries"])

    def test_forensics_solver_extracts_flag_from_interesting_archive_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "bundle.zip"
            with zipfile.ZipFile(attachment, "w") as zf:
                zf.writestr("notes/readme.txt", "analyst note")
                zf.writestr("flag.txt", "flag{forensics_archive_preview}")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="archive-flag-forensics",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "Zip archive data"}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.binwalk_scan",
                    return_value=ToolResult(tool="binwalk", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.exiftool_read",
                    return_value=ToolResult(tool="exiftool", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("archive-flag-forensics")
                finding = next(
                    f for f in notebook.findings_for("archive-flag-forensics") if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{forensics_archive_preview}"])
        self.assertEqual(finding.evidence["archive_text_previews"][0]["name"], "flag.txt")
        self.assertIn("flag.txt", finding.evidence["archive"]["interesting_entries"])

if __name__ == "__main__":
    unittest.main()

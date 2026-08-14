from __future__ import annotations

import base64
import shutil
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig, ToolResult
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers import ForensicsSolver
from tests.png_fixtures import bmp_with_bgr_lsb_payload, png_with_text_and_trailing_data, png_with_wrong_declared_height


@unittest.skipUnless(shutil.which("file") and shutil.which("strings"), "file and strings commands are required")
class ForensicsSolverTest(unittest.TestCase):
    def test_forensics_solver_recovers_bitlocker_fvestats_from_babybit_vmdk(self) -> None:
        sample = (
            Path(__file__).resolve().parents[1]
            / ".forgeflag"
            / "artifacts"
            / "forensics-20260630-132526-babybit-vmdk"
            / "babybit.vmdk"
        )
        if not sample.exists():
            self.skipTest("local babybit.vmdk fixture is not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "babybit.vmdk"
            attachment.write_bytes(sample.read_bytes())
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-babybit-vmdk",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge(
                "forensics-babybit-vmdk"
            )
            finding = next(
                f for f in notebook.findings_for("forensics-babybit-vmdk")
                if f.finding == "Triaged forensic attachment"
            )

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["PCL{2022/6/13_15:17:39_2022/6/13_15:23:46}"])
        bitlocker = finding.evidence["registry_bitlocker_fvestats"]
        self.assertEqual(bitlocker["source"], "SYSTEM\\ControlSet001\\Control\\FVEStats")
        self.assertEqual(bitlocker["timestamps"]["OsvEncryptInit"]["local"], "2022/6/13_15:17:39")
        self.assertEqual(bitlocker["timestamps"]["OsvEncryptComplete"]["local"], "2022/6/13_15:23:46")

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
        self.assertEqual(forensic_finding.evidence["ctf_scope"]["category"], "forensics")
        self.assertEqual(forensic_finding.evidence["ctf_scope"]["research_context"], "local_or_authorized_ctf_lab")
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

    def test_forensics_solver_decrypts_group_policy_preferences_cpassword(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "badpolicies.zip"
            groups_xml = (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<Groups><User name="Backup"><Properties userName="Backup" '
                'cpassword="B+iL/dnbBHSlVf66R8HOuAiGHAtFOVLZwXu0FYf+jQ6553UUgGNwSZucgdz98klzBuFqKtTpO1bRZIsrF8b4Hu5n6KccA7SBWlbLBWnLXAkPquHFwdC70HXBcRlz38q2" '
                "/></User></Groups>\n"
            )
            with zipfile.ZipFile(attachment, "w") as zf:
                zf.writestr(
                    "Policies/{B6EF}/Machine/Preferences/Groups/Groups.xml",
                    groups_xml,
                )
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-gpp-cpassword",
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
                summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge(
                    "forensics-gpp-cpassword"
                )
                finding = next(
                    f for f in notebook.findings_for("forensics-gpp-cpassword")
                    if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["DUCTF{D0n7_Us3_P4s5w0rds_1n_Gr0up_P0l1cy}"])
        self.assertEqual(finding.evidence["gpp_cpasswords"][0]["username"], "Backup")
        self.assertEqual(finding.evidence["gpp_cpasswords"][0]["password"], "DUCTF{D0n7_Us3_P4s5w0rds_1n_Gr0up_P0l1cy}")

    def test_forensics_solver_prioritizes_gpp_groups_xml_in_large_archives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "large-badpolicies.zip"
            groups_xml = (
                '<Groups><User name="Backup"><Properties userName="Backup" '
                'cpassword="B+iL/dnbBHSlVf66R8HOuAiGHAtFOVLZwXu0FYf+jQ6553UUgGNwSZucgdz98klzBuFqKtTpO1bRZIsrF8b4Hu5n6KccA7SBWlbLBWnLXAkPquHFwdC70HXBcRlz38q2" '
                "/></User></Groups>\n"
            )
            with zipfile.ZipFile(attachment, "w") as zf:
                for index in range(30):
                    zf.writestr(f"Policies/{{A{index:02d}}}/Machine/comment.cmtx", "ordinary policy comment")
                zf.writestr(
                    "Policies/{B6EF}/Machine/Preferences/Groups/Groups.xml",
                    groups_xml,
                )
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-large-gpp",
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
                summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("forensics-large-gpp")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["DUCTF{D0n7_Us3_P4s5w0rds_1n_Gr0up_P0l1cy}"])

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

    def test_forensics_solver_recovers_wifi_name_from_windows_reg_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "zhucebiao.reg"
            registry_text = (
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Wireless]\r\n\r\n"
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Wireless\\ABCDEF]\r\n"
                '@="4F50504F2052656E6F"\r\n'
                '"4F50504F2052656E6F"=hex:01,00,00,00\r\n\r\n'
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{GUID}]\r\n"
                '"ProfileName"="OPPO Reno"\r\n'
                '"Description"="OPPO Reno"\r\n'
            )
            attachment.write_bytes(b"\xff\xfe" + registry_text.encode("utf-16le"))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-reg-wifi",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "Windows Registry text"}),
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
                summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("forensics-reg-wifi")
                finding = next(
                    f for f in notebook.findings_for("forensics-reg-wifi")
                    if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{OPPOReno}"])
        self.assertEqual(finding.evidence["registry_wifi"]["wireless_ssids"], ["OPPO Reno"])
        self.assertEqual(finding.evidence["registry_wifi"]["profile_names"], ["OPPO Reno"])

    def test_forensics_solver_decodes_bmp_quickstego_braille_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "coolguy.bmp"
            attachment.write_bytes(bmp_with_bgr_lsb_payload("2471491ED07C69930E8F994E383E415F"))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-bmp-braille",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "PC bitmap"}),
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
                summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge(
                    "forensics-bmp-braille"
                )
                finding = next(
                    f for f in notebook.findings_for("forensics-bmp-braille")
                    if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["csictf{ucbr4ill3}"])
        self.assertEqual(finding.evidence["image_stego"]["format"], "bmp")
        transform_values = {item["value"] for item in finding.evidence["decoded_image_text_candidates"]}
        self.assertIn("csictf{ucbr4ill3}", transform_values)

    def test_forensics_solver_decodes_base64_jpeg_comment_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "cat.jpg"
            encoded = base64.b64encode(b"SVIBRG{jpeg_comment_b64}").decode("ascii").encode("ascii")
            attachment.write_bytes(b"\xff\xd8" + b"\xff\xfe" + (len(encoded) + 2).to_bytes(2, "big") + encoded + b"\xff\xd9")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-jpeg-comment-base64",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "JPEG image data"}),
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
                summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("forensics-jpeg-comment-base64")
                finding = next(
                    f for f in notebook.findings_for("forensics-jpeg-comment-base64")
                    if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["SVIBRG{jpeg_comment_b64}"])
        self.assertIn("decoded_image_text_candidates", finding.evidence)
        recipes = {tuple(candidate["recipe"]) for candidate in finding.evidence["decoded_image_text_candidates"]}
        self.assertIn(("base64_decode",), recipes)

    def test_forensics_solver_recovers_flag_from_minecraft_region_orphan_chunk(self) -> None:
        def nbt_string(value: str) -> bytes:
            raw = value.encode("utf-8")
            return len(raw).to_bytes(2, "big") + raw

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "r.0.0.mca"
            chunk_payload = b"".join(
                nbt_string(value)
                for value in (
                    '{"text":"My Important Items"}',
                    '{"text":"ir"}',
                    '{"text":"Michael\'s Shovel"}',
                    '{"text":"is"}',
                    '{"text":"ct"}',
                    '{"text":"f{minecraft_region_orphan}"}',
                )
            )
            compressed = zlib.compress(chunk_payload)
            sector = bytearray(4096 * 3)
            sector_offset = 2
            sector[sector_offset * 4096 : sector_offset * 4096 + 5 + len(compressed)] = (
                (len(compressed) + 1).to_bytes(4, "big") + b"\x02" + compressed
            )
            attachment.write_bytes(sector)
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-mca-orphan",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "Minecraft region data"}),
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
                summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge(
                    "forensics-mca-orphan"
                )
                finding = next(
                    f for f in notebook.findings_for("forensics-mca-orphan")
                    if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["irisctf{minecraft_region_orphan}"])
        self.assertEqual(finding.evidence["minecraft_region"]["chunks"][0]["sector"], 2)
        self.assertTrue(finding.evidence["minecraft_region"]["chunks"][0]["orphan_sector"])

    def test_forensics_solver_scans_minecraft_region_beyond_summary_limit(self) -> None:
        def nbt_string(value: str) -> bytes:
            raw = value.encode("utf-8")
            return len(raw).to_bytes(2, "big") + raw

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "r.0.0.mca"
            data = bytearray(4096 * 150)
            for sector in range(2, 130):
                payload = zlib.compress(nbt_string("minecraft:stone"))
                data[sector * 4096 : sector * 4096 + 5 + len(payload)] = (
                    (len(payload) + 1).to_bytes(4, "big") + b"\x02" + payload
                )
            late_payload = zlib.compress(nbt_string('{"text":"irisctf{late_orphan_chunk}"}'))
            data[140 * 4096 : 140 * 4096 + 5 + len(late_payload)] = (
                (len(late_payload) + 1).to_bytes(4, "big") + b"\x02" + late_payload
            )
            attachment.write_bytes(data)
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-mca-late-orphan",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "Minecraft region data"}),
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
                summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge(
                    "forensics-mca-late-orphan"
                )
                finding = next(
                    f for f in notebook.findings_for("forensics-mca-late-orphan")
                    if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["irisctf{late_orphan_chunk}"])
        self.assertLessEqual(len(finding.evidence["minecraft_region"]["chunks"]), 20)

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

    def test_forensics_solver_runs_carving_and_yara_when_initial_triage_has_no_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "blob.bin"
            attachment.write_bytes(b"packed noise")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-carve-yara",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.forensics.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "data"}),
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
                    "forgeflag.solvers.forensics.ctf.foremost_carve",
                    return_value=ToolResult(tool="foremost", target=None, status="success", raw={"stdout": "Processing:"}),
                ),
                patch(
                    "forgeflag.solvers.forensics.ctf.yara_scan",
                    return_value=ToolResult(tool="yara", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("forensics-carve-yara")
                finding = next(
                    f for f in notebook.findings_for("forensics-carve-yara") if f.finding == "Triaged forensic attachment"
                )

        self.assertEqual(finding.evidence["tool_statuses"]["foremost"], "success")
        self.assertEqual(finding.evidence["tool_statuses"]["yara"], "success")
        self.assertIn("foremost", finding.evidence["tool_samples"])
        self.assertIn("yara", finding.evidence["tool_samples"])

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

    def test_forensics_solver_repairs_mangled_png_inside_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "flag.pdf"
            png = b"JESS" + png_with_text_and_trailing_data("flag{archive_repaired_png}")[4:]
            with zipfile.ZipFile(attachment, "w") as zf:
                zf.writestr("flag.png", png)
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="archive-mangled-png",
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
                patch(
                    "forgeflag.solvers.forensics.ctf.image_ocr",
                    return_value=ToolResult(
                        tool="tesseract",
                        target=None,
                        status="success",
                        raw={"stdout": "flag{archive_\nrepaired_png}"},
                    ),
                ),
            ):
                summary = Manager(notebook, RunConfig(), solvers=[ForensicsSolver()]).run_challenge("archive-mangled-png")
                finding = next(
                    f for f in notebook.findings_for("archive-mangled-png")
                    if f.finding == "Triaged forensic attachment"
                )
                repaired_exists = Path(finding.evidence["archive_image_recoveries"][0]["repaired_path"]).is_file()

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{archive_repaired_png}"])
        recovery = finding.evidence["archive_image_recoveries"][0]
        self.assertEqual(recovery["entry_name"], "flag.png")
        self.assertEqual(recovery["ocr"]["flag_candidates"], ["flag{archive_repaired_png}"])
        self.assertTrue(repaired_exists)

if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig, ToolResult
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers import ForensicsSolver


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


if __name__ == "__main__":
    unittest.main()

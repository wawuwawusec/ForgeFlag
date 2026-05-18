from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig, ToolResult
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers import TrafficSolver


class TrafficSolverTest(unittest.TestCase):
    def test_traffic_solver_triages_pcap_and_returns_flag_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "capture.pcap"
            attachment.write_bytes(b"pcap fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-flag",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.traffic.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "pcap capture file"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "1 0.0 TCP"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_traffic_analysis",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "Protocol Hierarchy"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_flag_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "flag{pcap_payload}"}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-flag")
                findings = notebook.findings_for("traffic-flag")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{pcap_payload}"])
        traffic_finding = next(f for f in findings if f.finding == "Analyzed packet capture traffic")
        self.assertEqual(traffic_finding.solver, "TrafficSolver")
        self.assertIn("tshark_traffic_analysis", traffic_finding.evidence["tool_statuses"])
        self.assertIn("tshark_flag_scan", traffic_finding.evidence["tool_statuses"])

    def test_traffic_solver_skips_non_pcap_attachments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "note.txt"
            attachment.write_text("not traffic", encoding="utf-8")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-skip",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig(), solvers=[TrafficSolver()]).run_challenge("traffic-skip")
            findings = notebook.findings_for("traffic-skip")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(findings[0].finding, "Traffic solver found no packet captures")


if __name__ == "__main__":
    unittest.main()

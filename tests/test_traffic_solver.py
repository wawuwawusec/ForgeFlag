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
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_dns_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_tcp_streams",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
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

    def test_traffic_solver_decodes_http_artifact_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "capture.pcapng"
            attachment.write_bytes(b"pcapng fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-http-flag",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )
            multipart = (
                'Content-Disposition: form-data; name="image"; filename="hnt.txt"\\r\\n'
                "\\r\\n"
                "&#102;&#49;&#97;&#103;&#123;&#115;&#105;&#49;&#49;&#121;&#98;&#48;&#121;&#101;&#109;&#109;&#109;&#125;"
            )
            artifact_stdout = f"456|16|POST|/upload/example1.php||{multipart.encode().hex()}"

            with (
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "HTTP POST"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_traffic_analysis",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "http frames"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_flag_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_dns_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_tcp_streams",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "456|16|10.0.0.2|4444|10.0.0.3|80|HTTP|POST /upload/example1.php HTTP/1.1"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "456|16|POST|/upload/example1.php|Java"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": artifact_stdout}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-http-flag")
                finding = next(f for f in notebook.findings_for("traffic-http-flag") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["f1ag{si11yb0yemmm}"])
        self.assertIn("f1ag{si11yb0yemmm}", finding.evidence["decoded_http_artifacts"][0])
        self.assertEqual(finding.evidence["tcp_streams"][0]["stream_id"], "16")

    def test_traffic_solver_summarizes_dns_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "capture.pcap"
            attachment.write_bytes(b"pcap fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-dns",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )
            dns_stdout = "\n".join(
                [
                    "12|short.example.com|||0",
                    "13|covertcovertcovertcovert.example.com|||3",
                    "14|txt.example.com||flag{dns_txt}|0",
                ]
            )

            with (
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "DNS"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_traffic_analysis",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "dns frames"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_flag_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_dns_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": dns_stdout}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_tcp_streams",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-dns")
                finding = next(f for f in notebook.findings_for("traffic-dns") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{dns_txt}"])
        self.assertIn("flag{dns_txt}", finding.evidence["dns_summary"]["txt_answers"])
        self.assertEqual(finding.evidence["dns_summary"]["rcode_counts"]["3"], 1)

    def test_traffic_solver_accepts_dns_query_encoded_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "capture.pcap"
            attachment.write_bytes(b"pcap fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-dns-query",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )
            dns_stdout = "42|MZWGCZ33MRXHGX3TOVRGI33NMFUW47I.exfil.example|||0"

            with (
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "DNS"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_traffic_analysis",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "dns frames"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_flag_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_dns_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": dns_stdout}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_tcp_streams",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-dns-query")
                finding = next(f for f in notebook.findings_for("traffic-dns-query") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{dns_subdomain}"])
        self.assertIn("flag{dns_subdomain}", finding.evidence["dns_summary"]["decoded_query_hints"])

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

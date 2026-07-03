from __future__ import annotations

import base64
import math
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import ANY, patch

from PIL import Image, ImageDraw

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig, ToolResult
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers import TrafficSolver
from forgeflag.solvers.traffic import _ip_id_stego_recovery, _pcap_record_resync_repair, _raw_capture_flag_scan


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
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-flag")
                findings = notebook.findings_for("traffic-flag")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{pcap_payload}"])
        traffic_finding = next(f for f in findings if f.finding == "Analyzed packet capture traffic")
        self.assertEqual(traffic_finding.solver, "TrafficSolver")
        self.assertEqual(traffic_finding.evidence["ctf_scope"]["category"], "traffic")
        self.assertEqual(traffic_finding.evidence["ctf_scope"]["research_context"], "local_or_authorized_ctf_lab")
        self.assertIn("tshark_traffic_analysis", traffic_finding.evidence["tool_statuses"])
        self.assertIn("tshark_flag_scan", traffic_finding.evidence["tool_statuses"])

    def test_traffic_solver_scans_raw_capture_bytes_for_plaintext_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "capture.pcap"
            attachment.write_bytes(b"\xd4\xc3\xb2\xa1" + (b"A" * 1600) + b" raw HTTP object tjctf{raw_pcap_payload_flag}\x00tail")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-raw-flag",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_traffic_analysis",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
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
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-raw-flag")
                finding = next(f for f in notebook.findings_for("traffic-raw-flag") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["tjctf{raw_pcap_payload_flag}"])
        self.assertEqual(finding.evidence["raw_capture_flag_scan"]["flags"], ["tjctf{raw_pcap_payload_flag}"])

    def test_raw_capture_flag_scan_reads_only_bounded_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            attachment = Path(tmp) / "large.pcap"
            attachment.write_bytes(b"A" * 32 + b"flag{past_limit}")

            scan = _raw_capture_flag_scan(str(attachment), max_bytes=16)

        self.assertEqual(scan["bytes_scanned"], 16)
        self.assertTrue(scan["truncated"])
        self.assertEqual(scan["flags"], [])

    def test_traffic_solver_repairs_corrupt_pcap_and_decodes_ip_id_stego(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "findtheflag.cap"
            attachment.write_bytes(_corrupt_ip_id_stego_pcap("flag{pcap_resync}"))
            repair_dir = root / "repairs"

            repair = _pcap_record_resync_repair(str(attachment), repair_dir)
            self.assertIsNotNone(repair)
            assert repair is not None
            self.assertGreaterEqual(len(repair["repairs"]), 1)
            recovery = _ip_id_stego_recovery(str(repair["path"]))
            self.assertEqual(recovery["flag_candidates"], ["flag{pcap_resync}"])

            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-corrupt-ipid",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )

            tshark_error = ToolResult(
                tool="tshark",
                target=None,
                status="error",
                raw={"stdout": "", "stderr": "pcap: File has 3138333535-byte packet, bigger than maximum of 262144"},
            )
            with (
                patch("forgeflag.solvers.traffic.ctf.tshark_pcap_summary", return_value=tshark_error),
                patch("forgeflag.solvers.traffic.ctf.tshark_traffic_analysis", return_value=tshark_error),
                patch("forgeflag.solvers.traffic.ctf.tshark_flag_scan", return_value=tshark_error),
                patch("forgeflag.solvers.traffic.ctf.tshark_dns_summary", return_value=tshark_error),
                patch("forgeflag.solvers.traffic.ctf.tshark_tcp_streams", return_value=tshark_error),
                patch("forgeflag.solvers.traffic.ctf.tshark_http_requests", return_value=tshark_error),
                patch("forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan", return_value=tshark_error),
                patch("forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream", return_value=tshark_error),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-corrupt-ipid")
                finding = next(f for f in notebook.findings_for("traffic-corrupt-ipid") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{pcap_resync}"])
        self.assertEqual(finding.evidence["pcap_record_resync"]["recovered_flags"], ["flag{pcap_resync}"])
        self.assertEqual(finding.evidence["ip_id_stego"]["flag_candidates"], ["flag{pcap_resync}"])

    def test_traffic_solver_wraps_nikto_user_agent_tool_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "capture.pcap"
            attachment.write_bytes(b"pcap fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-nikto-version",
                    category=ChallengeCategory.TRAFFIC,
                    title="DUCTF 2024 - Baby's First Forensics",
                    description="Tell us what tool they were using and its version. Wrap your answer in DUCTF{}.",
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
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "HTTP GET"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_traffic_analysis",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "Protocol Hierarchy: http"}),
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
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(
                        tool="tshark",
                        target=None,
                        status="success",
                        raw={"stdout": "1|1|GET|/admin.php|Mozilla/5.00 (Nikto/2.1.6)"},
                    ),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-nikto-version")
                finding = next(f for f in notebook.findings_for("traffic-nikto-version") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["DUCTF{nikto_2.1.6}"])
        self.assertEqual(finding.evidence["tool_version_flags"][0]["tool"], "nikto")
        self.assertEqual(finding.evidence["tool_version_flags"][0]["version"], "2.1.6")

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
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_object_export",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-http-flag")
                finding = next(f for f in notebook.findings_for("traffic-http-flag") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["f1ag{si11yb0yemmm}"])
        self.assertIn("f1ag{si11yb0yemmm}", finding.evidence["decoded_http_artifacts"][0])
        self.assertEqual(finding.evidence["tcp_streams"][0]["stream_id"], "16")

    def test_traffic_solver_accepts_generic_flag_after_http_response_delimiter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "key.pcapng"
            attachment.write_bytes(b"pcapng fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-http-webshell",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )
            payload = "X@Yflag{This_is_a_f10g}\n[S]\n/var/www/html\n[E]\nX@Y"
            artifact_stdout = f"105|4|POST|/shell.php||{payload.encode().hex()}"

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
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "105|4|10.0.0.2|4444|10.0.0.3|80|HTTP|POST /shell.php HTTP/1.1"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "105|4|POST|/shell.php|Mozilla/5.0"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": artifact_stdout}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_object_export",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-http-webshell")
                finding = next(f for f in notebook.findings_for("traffic-http-webshell") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{This_is_a_f10g}"])
        self.assertIn("flag{This_is_a_f10g}", finding.evidence["decoded_http_artifacts"])
        self.assertEqual(finding.evidence["flag_candidates"], ["flag{This_is_a_f10g}"])

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
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
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
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-dns-query")
                finding = next(f for f in notebook.findings_for("traffic-dns-query") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{dns_subdomain}"])
        self.assertIn("flag{dns_subdomain}", finding.evidence["dns_summary"]["decoded_query_hints"])

    def test_traffic_solver_decodes_ask_manchester_waveform_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "spicy-sines.png"
            _write_ask_manchester_waveform_png(attachment, "flag{ask_manchester_image}")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-rf-image",
                    category=ChallengeCategory.TRAFFIC,
                    title="Spicy Sines",
                    description="ASK/OOK radio waveform image with Manchester encoding.",
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig(), solvers=[TrafficSolver()]).run_challenge("traffic-rf-image")
            finding = next(f for f in notebook.findings_for("traffic-rf-image") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{ask_manchester_image}"])
        self.assertEqual(finding.finding, "Decoded RF image waveform")
        self.assertEqual(finding.evidence["rf_image_waveform"]["encoding"], "ask_ook_manchester")
        self.assertEqual(finding.evidence["rf_image_waveform"]["flag_candidates"], ["flag{ask_manchester_image}"])
        self.assertIn("low_high_is_one", finding.evidence["rf_image_waveform"]["manchester_mapping"])

    def test_traffic_solver_follows_shortlisted_tcp_streams_for_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "capture.pcap"
            attachment.write_bytes(b"pcap fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-follow-stream",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )
            tcp_stdout = "7|3|10.0.0.2|5000|10.0.0.4|80|HTTP|POST /submit HTTP/1.1"
            http_stdout = "7|3|POST|example.test|/submit|curl/8"

            with (
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "HTTP"}),
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
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": tcp_stdout}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": http_stdout}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_object_export",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(
                        tool="tshark",
                        target=None,
                        status="success",
                        raw={"stdout": "POST /submit HTTP/1.1\\r\\n\\r\\nflag{follow_stream_payload}\\n"},
                    ),
                ) as follow_stream,
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-follow-stream")
                finding = next(f for f in notebook.findings_for("traffic-follow-stream") if f.solver == "TrafficSolver")

        follow_stream.assert_called_once_with(str(attachment.resolve()), 3, scope=ANY)
        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{follow_stream_payload}"])
        self.assertEqual(finding.evidence["tcp_stream_payloads"][0]["stream_id"], "3")
        self.assertIn("flag{follow_stream_payload}", finding.evidence["tcp_stream_payloads"][0]["flags"])

    def test_traffic_solver_summarizes_smtp_stream_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "mail.pcap"
            attachment.write_bytes(b"pcap fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-smtp-stream",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )
            tcp_stdout = "9|7|10.0.0.2|53333|10.0.0.25|25|SMTP|C: DATA"
            smtp_stream = (
                "220 mail.ctf.local ESMTP\r\n"
                "EHLO analyst\r\n"
                "MAIL FROM:<admin@ctf.local>\r\n"
                "RCPT TO:<player@ctf.local>\r\n"
                "DATA\r\n"
                "Subject: clue\r\n"
                "flag{smtp_stream_summary}\r\n"
                ".\r\n"
                "QUIT\r\n"
            )

            with (
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "SMTP"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_traffic_analysis",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "smtp frames"}),
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
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": tcp_stdout}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": smtp_stream}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-smtp-stream")
                finding = next(f for f in notebook.findings_for("traffic-smtp-stream") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{smtp_stream_summary}"])
        self.assertEqual(finding.evidence["protocol_streams"][0]["protocol"], "SMTP")
        self.assertEqual(finding.evidence["protocol_streams"][0]["stream_id"], "7")
        self.assertIn("EHLO", finding.evidence["protocol_streams"][0]["commands"])
        self.assertIn("flag{smtp_stream_summary}", finding.evidence["protocol_streams"][0]["flags"])

    def test_traffic_solver_extracts_data_uri_images_from_tcp_streams(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "data-uri.pcap"
            attachment.write_bytes(b"pcap fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-data-uri",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )
            image_bytes = b"\xff\xd8" + (b"A" * 1800) + b" visual flag{data_uri_image}\xff\xd9"
            data_uri = "data:image/jpeg;base64," + base64.b64encode(image_bytes).decode("ascii")

            with (
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "TCP"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_traffic_analysis",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "tcp frames"}),
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
                    return_value=ToolResult(
                        tool="tshark",
                        target=None,
                        status="success",
                        raw={"stdout": "15|2|10.0.0.2|25697|10.0.0.3|29793|TCP|data:image/jpeg;base64"},
                    ),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": data_uri}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-data-uri")
                finding = next(f for f in notebook.findings_for("traffic-data-uri") if f.solver == "TrafficSolver")
                data_uri_artifact = finding.evidence["data_uri_artifacts"][0]
                artifact_exists = Path(data_uri_artifact["path"]).is_file()

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{data_uri_image}"])
        self.assertEqual(data_uri_artifact["stream_id"], "2")
        self.assertEqual(data_uri_artifact["media_type"], "image/jpeg")
        self.assertTrue(artifact_exists)
        self.assertIn("flag{data_uri_image}", data_uri_artifact["flags"])

    def test_traffic_solver_exports_http_objects_and_records_file_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "capture.pcap"
            attachment.write_bytes(b"pcap fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-http-export",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )
            http_stdout = "12|4|GET|example.test|/download/loot.txt|curl/8"

            def export_objects(path: str, output_dir: str, scope=None) -> ToolResult:
                del path, scope
                exported = Path(output_dir) / "loot.txt"
                exported.parent.mkdir(parents=True, exist_ok=True)
                exported.write_text("downloaded flag{http_object_export}\n", encoding="utf-8")
                return ToolResult(tool="tshark", target=None, status="success", artifacts=[str(exported)], raw={"stdout": ""})

            with (
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "HTTP"}),
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
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "12|4|10.0.0.2|4444|10.0.0.3|80|HTTP|GET /download/loot.txt HTTP/1.1"}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": http_stdout}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch("forgeflag.solvers.traffic.ctf.tshark_http_object_export", side_effect=export_objects),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-http-export")
                finding = next(f for f in notebook.findings_for("traffic-http-export") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{http_object_export}"])
        self.assertEqual(finding.evidence["http_object_exports"][0]["name"], "loot.txt")
        self.assertIn("flag{http_object_export}", finding.evidence["http_object_exports"][0]["flags"])

    def test_traffic_solver_recovers_antsword_rot13_reverse_cut_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "antsword.pcapng"
            attachment.write_bytes(b"pcapng fixture placeholder")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="traffic-antsword",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(attachment),),
                )
            )
            http_stdout = "\n".join(
                [
                    "1|0|POST|ctf.local|/FileuploadServlet|Mozilla",
                    "2|1|POST|ctf.local|/upload/ms.jsp|AntSword",
                ]
            )
            positions = [
                10,
                9,
                1,
                2,
                33,
                32,
                39,
                6,
                14,
                38,
                27,
                7,
                25,
                3,
                15,
                20,
                31,
                18,
                24,
                29,
                16,
                23,
                11,
                30,
                42,
                37,
                41,
                36,
                12,
                21,
                34,
                4,
                13,
                19,
                5,
                8,
                26,
                28,
                22,
                35,
                17,
                40,
            ]
            command_log = ("\n".join(f"cut -c {position} /flag" for position in positions) + "2b701bd4a893")[::-1]
            output_log = "\n".join(
                [
                    "7b68ec1230p",
                    "r",
                    "s",
                    "y",
                    "6",
                    "p",
                    "p",
                    "r",
                    "-",
                    "1",
                    "q",
                    "n",
                    "8",
                    "n",
                    "q",
                    "4",
                    "2",
                    "r",
                    "-",
                    "-",
                    "2",
                    "0",
                    "s",
                    "p",
                    "}",
                    "7",
                    "s",
                    "p",
                    "2",
                    "1",
                    "9",
                    "t",
                    "o",
                    "-",
                    "{",
                    "r",
                    "5",
                    "7",
                    "o",
                    "r",
                    "6",
                    "6",
                    "ror91spo0",
                    "/gbzpng",
                    "4477155q",
                ]
            )

            def export_objects(path: str, output_dir: str, scope=None) -> ToolResult:
                del path, scope
                export_dir = Path(output_dir)
                export_dir.mkdir(parents=True, exist_ok=True)
                (export_dir / "FileuploadServlet").write_text(
                    'new U(this.getClass().getClassLoader()).g(base64Decode(request.getParameter("study")))',
                    encoding="utf-8",
                )
                (export_dir / "ms(14).jsp").write_text(output_log, encoding="utf-8")
                (export_dir / "ms(18).jsp").write_text(command_log, encoding="utf-8")
                return ToolResult(
                    tool="tshark",
                    target=None,
                    status="success",
                    artifacts=[
                        str(export_dir / "FileuploadServlet"),
                        str(export_dir / "ms(14).jsp"),
                        str(export_dir / "ms(18).jsp"),
                    ],
                    raw={"stdout": ""},
                )

            with (
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_pcap_summary",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": "HTTP AntSword"}),
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
                    return_value=ToolResult(
                        tool="tshark",
                        target=None,
                        status="success",
                        raw={"stdout": "2|1|10.0.0.2|4444|10.0.0.3|80|HTTP|POST /upload/ms.jsp HTTP/1.1"},
                    ),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_requests",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": http_stdout}),
                ),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_http_artifact_scan",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
                patch("forgeflag.solvers.traffic.ctf.tshark_http_object_export", side_effect=export_objects),
                patch(
                    "forgeflag.solvers.traffic.ctf.tshark_follow_tcp_stream",
                    return_value=ToolResult(tool="tshark", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("traffic-antsword")
                finding = next(f for f in notebook.findings_for("traffic-antsword") if f.solver == "TrafficSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{eaeecf2b-d26e-41b0-85d7-c2c69ec71c6f}"])
        self.assertEqual(
            finding.evidence["antsword_recovery"]["flag_candidates"],
            ["flag{eaeecf2b-d26e-41b0-85d7-c2c69ec71c6f}"],
        )

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


def _corrupt_ip_id_stego_pcap(flag: str) -> bytes:
    records: list[bytes] = []
    first_packet = _ether_ipv4_tcp_packet(0x1234, b"warmup", sport=12345)
    records.append(_pcap_record(1_700_000_000, 1, first_packet, incl_len=len(first_packet) + 7))
    encoded = flag.encode("ascii")
    if len(encoded) % 2:
        encoded += b"\x00"
    for index in range(0, len(encoded), 2):
        ip_id = int.from_bytes(encoded[index : index + 2], "little")
        packet = _ether_ipv4_tcp_packet(ip_id, b"where is the flag?", sport=20000 + index)
        records.append(_pcap_record(1_700_000_000, 2 + index, packet))
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    return global_header + b"".join(records)


def _pcap_record(ts_sec: int, ts_usec: int, packet: bytes, incl_len: int | None = None) -> bytes:
    captured_length = len(packet) if incl_len is None else incl_len
    return struct.pack("<IIII", ts_sec, ts_usec, captured_length, max(captured_length, len(packet))) + packet


def _ether_ipv4_tcp_packet(ip_id: int, payload: bytes, sport: int = 12345, dport: int = 2222) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    src = bytes([10, 0, 0, 1])
    dst = bytes([10, 0, 0, 2])
    tcp_header_len = 20
    total_length = 20 + tcp_header_len + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        ip_id,
        0,
        64,
        6,
        0,
        src,
        dst,
    )
    tcp_header = struct.pack("!HHIIHHHH", sport, dport, 1, 0, 0x5000, 8192, 0, 0)
    return eth + ip_header + tcp_header + payload


def _write_ask_manchester_waveform_png(path: Path, message: str) -> None:
    start = 128
    half_width = 16
    carrier_period = 8.0
    amplitude = 34
    height = 120
    mid = height // 2
    bits = "".join(f"{byte:08b}" for byte in message.encode("ascii"))
    manchester_halves: list[int] = []
    for bit in bits:
        manchester_halves.extend((0, 1) if bit == "1" else (1, 0))
    width = start + len(manchester_halves) * half_width + 128
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    points: list[tuple[int, int]] = []
    for x in range(width):
        half_index = int((x - start) // half_width)
        active = 0 <= half_index < len(manchester_halves) and manchester_halves[half_index]
        offset = amplitude * math.sin(2 * math.pi * x / carrier_period) if active else 0
        points.append((x, int(round(mid + offset))))
    draw.line(points, fill=(0, 80, 255), width=2)
    image.save(path)


if __name__ == "__main__":
    unittest.main()

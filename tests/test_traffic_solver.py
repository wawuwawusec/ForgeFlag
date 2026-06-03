from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import ANY, patch

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


if __name__ == "__main__":
    unittest.main()

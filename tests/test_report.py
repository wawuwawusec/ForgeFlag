from __future__ import annotations

import unittest

from forgeflag.domain import Challenge, ChallengeCategory, Finding, Observation
from forgeflag.report import ReportBuilder


class ReportBuilderTest(unittest.TestCase):
    def test_flag_report_selects_shortest_finding_path(self) -> None:
        findings = [
            Finding(
                challenge_id="report-01",
                solver="ReconSolver",
                finding="Initial triage",
                evidence={"note": "no flag here"},
                confidence=0.7,
                next_action="Run specialist solver.",
            ),
            Finding(
                challenge_id="report-01",
                solver="TrafficSolver",
                finding="Analyzed packet capture traffic",
                evidence={"flag_candidates": ["flag{short_path}"], "artifact": {"name": "capture.pcap"}},
                confidence=0.82,
                next_action="Send candidates to Verifier.",
            ),
        ]
        observations = [
            Observation(
                challenge_id="report-01",
                source="TrafficSolver",
                kind="flag_candidate",
                summary="flag{short_path}",
                evidence={"candidate": "flag{short_path}"},
            )
        ]

        report = ReportBuilder().build("report-01", ("flag{short_path}",), findings, observations)

        self.assertEqual(report["challenge_id"], "report-01")
        self.assertEqual(report["flags"][0]["flag"], "flag{short_path}")
        self.assertEqual(report["flags"][0]["path"][0]["solver"], "TrafficSolver")
        self.assertEqual(report["flags"][0]["path"][0]["finding"], "Analyzed packet capture traffic")
        self.assertEqual(report["flags"][0]["replay_steps"], ["Send candidates to Verifier."])
        self.assertEqual(report["flags"][0]["observations"][0]["summary"], "flag{short_path}")

    def test_writeup_report_contains_ctf_sections_and_markdown(self) -> None:
        findings = [
            Finding(
                challenge_id="writeup-01",
                solver="MiscSolver",
                finding="Decoded Base32 artifact",
                evidence={"transform_candidates": [{"value": "flag{writeup_style}", "method": "base32"}]},
                confidence=0.91,
                hypothesis="The attachment content decodes cleanly as Base32.",
                next_action="Submit verified flag candidate.",
            )
        ]
        observations = [
            Observation(
                challenge_id="writeup-01",
                source="MiscSolver",
                kind="flag_candidate",
                summary="flag{writeup_style}",
                evidence={"candidate": "flag{writeup_style}", "source": "transform_candidates"},
            )
        ]
        challenge = Challenge(
            challenge_id="writeup-01",
            category=ChallengeCategory.MISC,
            title="Base32 warmup",
            description="A small encoding puzzle.",
            tags=("base32", "misc"),
            attachment_paths=("/tmp/base32.txt",),
        )

        report = ReportBuilder().build("writeup-01", ("flag{writeup_style}",), findings, observations, challenge=challenge)

        writeup = report["writeup"]
        self.assertEqual(writeup["kind"], "ctf_writeup")
        self.assertEqual(writeup["title"], "Base32 warmup")
        self.assertEqual(writeup["final_flags"], ["flag{writeup_style}"])
        self.assertEqual([section["title"] for section in writeup["sections"]], ["解题思路", "复现步骤"])
        self.assertNotIn("题目概览", [section["title"] for section in writeup["sections"]])
        self.assertIn("解题思路", [section["title"] for section in writeup["sections"]])
        self.assertIn("复现步骤", [section["title"] for section in writeup["sections"]])
        self.assertNotIn("结论", [section["title"] for section in writeup["sections"]])
        self.assertNotIn("关键证据", [section["title"] for section in writeup["sections"]])
        self.assertNotIn("工具与观察", [section["title"] for section in writeup["sections"]])
        self.assertIn("# Base32 warmup", writeup["markdown"])
        self.assertNotIn("## 结论", writeup["markdown"])
        self.assertIn("## 复现步骤", writeup["markdown"])
        self.assertIn("flag{writeup_style}", writeup["markdown"])
        sections = {section["title"]: section for section in writeup["sections"]}
        self.assertEqual(
            sections["复现步骤"]["steps"],
            [
                "打开附件 base32.txt，读取题面文本和文件内容。",
                "对可疑文本执行 base32 转换，并按 flag 格式筛选候选结果。",
                "得到候选 flag{writeup_style}，交给 verifier 验证通过。",
            ],
        )
        self.assertNotIn("Raw JSON", writeup["markdown"])

    def test_report_includes_solve_trace_and_shortest_discovery_path(self) -> None:
        findings = [
            Finding(
                challenge_id="trace-report",
                solver="MiscSolver",
                finding="Recovered flag candidate",
                evidence={"flag_candidates": ["flag{trace_report}"]},
                confidence=0.91,
                next_action="Submit flag candidate.",
            )
        ]
        observations = [
            Observation(
                challenge_id="trace-report",
                source="ReconSolver",
                kind="solve_trace_step",
                summary="Step 1: ReconSolver completed with ok",
                evidence={
                    "step_index": 1,
                    "solver": "ReconSolver",
                    "status": "ok",
                    "flag_candidates": [],
                    "made_progress": True,
                },
            ),
            Observation(
                challenge_id="trace-report",
                source="MiscSolver",
                kind="solve_trace_step",
                summary="Step 2: MiscSolver completed with ok",
                evidence={
                    "step_index": 2,
                    "solver": "MiscSolver",
                    "status": "ok",
                    "flag_candidates": ["flag{trace_report}"],
                    "made_progress": True,
                },
            ),
        ]

        report = ReportBuilder().build("trace-report", ("flag{trace_report}",), findings, observations)

        self.assertEqual([step["solver"] for step in report["solve_trace"]], ["ReconSolver", "MiscSolver"])
        self.assertEqual(
            [step["solver"] for step in report["flags"][0]["trace_path"]],
            ["ReconSolver", "MiscSolver"],
        )
        self.assertIn("复现步骤", [section["title"] for section in report["writeup"]["sections"]])

    def test_report_uses_latest_solve_trace_after_rerun(self) -> None:
        findings = [
            Finding(
                challenge_id="trace-rerun",
                solver="CryptoSolver",
                finding="Recovered Python random XOR flag candidates",
                evidence={"flag_candidates": ["flag{just_a_seed}"], "seed": 3277},
                confidence=0.86,
                next_action="Submit recovered flag candidate.",
            ),
            Finding(
                challenge_id="trace-rerun",
                solver="CryptoSolver",
                finding="Recovered Python random XOR flag candidates",
                evidence={"flag_candidates": ["flag{just_a_seed}"], "seed": 3277},
                confidence=0.86,
                next_action="Submit recovered flag candidate.",
            ),
        ]
        observations = [
            Observation(
                challenge_id="trace-rerun",
                source="ReconSolver",
                kind="solve_trace_step",
                summary="Step 1: ReconSolver completed with ok",
                evidence={"step_index": 1, "solver": "ReconSolver", "status": "ok", "made_progress": True},
            ),
            Observation(
                challenge_id="trace-rerun",
                source="CryptoSolver",
                kind="solve_trace_step",
                summary="Step 2: CryptoSolver completed with completed",
                evidence={"step_index": 2, "solver": "CryptoSolver", "status": "completed", "made_progress": False},
            ),
            Observation(
                challenge_id="trace-rerun",
                source="ReconSolver",
                kind="solve_trace_step",
                summary="Step 1: ReconSolver completed with ok",
                evidence={"step_index": 1, "solver": "ReconSolver", "status": "ok", "made_progress": True},
            ),
            Observation(
                challenge_id="trace-rerun",
                source="CryptoSolver",
                kind="solve_trace_step",
                summary="Step 2: CryptoSolver completed with flag_candidate",
                evidence={
                    "step_index": 2,
                    "solver": "CryptoSolver",
                    "status": "flag_candidate",
                    "flag_candidates": ["flag{just_a_seed}"],
                    "made_progress": True,
                },
            ),
        ]

        report = ReportBuilder().build("trace-rerun", ("flag{just_a_seed}",), findings, observations)

        self.assertEqual(
            [(step["solver"], step["status"]) for step in report["solve_trace"]],
            [("ReconSolver", "ok"), ("CryptoSolver", "flag_candidate")],
        )
        self.assertEqual([step["solver"] for step in report["flags"][0]["path"]], ["CryptoSolver"])
        self.assertEqual(report["flags"][0]["replay_steps"], ["Submit recovered flag candidate."])
        self.assertEqual(
            [(step["solver"], step["status"]) for step in report["writeup"]["shortest_discovery_path"]],
            [("ReconSolver", "ok"), ("CryptoSolver", "flag_candidate")],
        )
        self.assertNotIn("工具与观察", [section["title"] for section in report["writeup"]["sections"]])

    def test_writeup_prioritizes_reproducible_python_random_xor_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="crypto-repro",
                solver="CryptoSolver",
                finding="Recovered Python random XOR flag candidates",
                evidence={
                    "python_random_xor": {
                        "enc": "1027275529278332342097876075445098700759415489",
                        "flags": ["flag{just_a_seed}"],
                        "key_bits": 150,
                        "method": "python_random_xor",
                        "plaintext_preview": "flag{just_a_seed}",
                        "seed": 3277,
                    }
                },
                confidence=0.86,
                hypothesis="Python random was seeded from a small range before deriving an XOR key, so seed brute force recovered plaintext.",
                next_action="Send recovered candidates to Verifier and preserve the seed/key evidence for replay.",
            )
        ]
        observations = [
            Observation(
                challenge_id="crypto-repro",
                source="CryptoSolver",
                kind="flag_candidate",
                summary="flag{just_a_seed}",
                evidence={"candidate": "flag{just_a_seed}"},
            )
        ]
        challenge = Challenge(
            challenge_id="crypto-repro",
            category=ChallengeCategory.CRYPTO,
            attachment_paths=("/tmp/easy_seed.py",),
        )

        report = ReportBuilder().build("crypto-repro", ("flag{just_a_seed}",), findings, observations, challenge=challenge)

        sections = {section["title"]: section for section in report["writeup"]["sections"]}
        self.assertEqual(list(sections), ["解题思路", "复现步骤"])
        self.assertIn("弱随机种子", sections["解题思路"]["body"])
        self.assertEqual(
            sections["复现步骤"]["steps"],
            [
                "打开附件 easy_seed.py，确认它用小范围 seed 初始化 Python random，并用 getrandbits(150) 生成 XOR key。",
                "遍历 seed 取值范围，按相同逻辑执行 random.seed(seed) 和 random.getrandbits(150)。",
                "用 ciphertext XOR key 还原明文，并按 flag 格式筛选候选结果。",
                "命中 seed=3277，明文为 flag{just_a_seed}。",
            ],
        )
        self.assertIn("seed=3277", report["writeup"]["markdown"])
        self.assertNotIn("关键证据", report["writeup"]["markdown"])

    def test_writeup_describes_plain_transform_candidates_without_awkward_method_text(self) -> None:
        findings = [
            Finding(
                challenge_id="plain-transform",
                solver="MiscSolver",
                finding="Decoded misc transform candidates",
                evidence={"transform_candidates": [{"recipe": [], "value": "flag{plain_text}"}]},
                confidence=0.8,
                hypothesis="Plain text contains a flag-like token.",
                next_action="Submit verified flag candidate.",
            )
        ]
        challenge = Challenge(
            challenge_id="plain-transform",
            category=ChallengeCategory.MISC,
            attachment_paths=("/tmp/plain.txt",),
        )

        report = ReportBuilder().build("plain-transform", ("flag{plain_text}",), findings, [], challenge=challenge)

        sections = {section["title"]: section for section in report["writeup"]["sections"]}
        self.assertEqual(
            sections["复现步骤"]["steps"][1],
            "直接从题面文本或附件明文中按 flag 格式筛选候选结果。",
        )
        self.assertNotIn("可逆编码/转换 转换", report["writeup"]["markdown"])

    def test_writeup_describes_reverse_strings_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="reverse-strings",
                solver="ReverseSolver",
                finding="Analyzed reverse binary artifact",
                evidence={
                    "artifact": "/tmp/reverse_0",
                    "flag_candidates": ["flag{reverse_strings}"],
                    "tool_samples": {
                        "file_identify": {
                            "stdout": "/tmp/reverse_0: Mach-O 64-bit executable arm64\n",
                            "stderr": "",
                        },
                        "strings_extract": {
                            "stdout": "flag{reverse_strings}\n",
                            "stderr": "",
                        },
                    },
                },
                confidence=0.78,
                hypothesis="Local reverse triage surfaced a flag-like token that should be verified.",
                next_action="Send candidates to Verifier and preserve local tool outputs as replay evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="reverse-strings",
            category=ChallengeCategory.REVERSE,
            attachment_paths=("/tmp/reverse_0",),
        )

        report = ReportBuilder().build("reverse-strings", ("flag{reverse_strings}",), findings, [], challenge=challenge)

        sections = {section["title"]: section for section in report["writeup"]["sections"]}
        self.assertIn("明文字符串泄露", sections["解题思路"]["body"])
        self.assertEqual(
            sections["复现步骤"]["steps"],
            [
                "进入附件所在目录，确认目标文件为 reverse_0。",
                "执行 `file reverse_0`，输出显示：Mach-O 64-bit executable arm64。",
                "执行 `strings -n 4 reverse_0` 提取可打印字符串。",
                "在 strings 输出中看到 `flag{reverse_strings}`，提交该 flag。",
            ],
        )
        self.assertIn("strings -n 4 reverse_0", report["writeup"]["markdown"])
        self.assertNotIn("关键证据", report["writeup"]["markdown"])
        self.assertNotIn("tool_samples", report["writeup"]["markdown"])

    def test_writeup_uses_transform_candidate_matching_accepted_flag(self) -> None:
        findings = [
            Finding(
                challenge_id="caesar-report",
                solver="CryptoSolver",
                finding="Decoded crypto transform candidates",
                evidence={
                    "transform_candidates": [
                        {"recipe": ["rot13_decode"], "value": "zfua{wrong_candidate}"},
                        {"recipe": ["caesar_shift_7"], "value": "flag{expanded_caesar}"},
                    ]
                },
                confidence=0.82,
                hypothesis="A reversible transform chain produced a flag-like token.",
                next_action="Send decoded candidates to Verifier and preserve the transform recipe.",
            )
        ]
        challenge = Challenge(
            challenge_id="caesar-report",
            category=ChallengeCategory.CRYPTO,
            attachment_paths=("/tmp/crypto_caesar.txt",),
        )

        report = ReportBuilder().build("caesar-report", ("flag{expanded_caesar}",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("caesar_shift_7", markdown)
        self.assertIn("flag{expanded_caesar}", markdown)
        self.assertNotIn("zfua{wrong_candidate}", markdown)

    def test_writeup_describes_classical_xor_recovery_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="xor-report",
                solver="CryptoSolver",
                finding="Recovered classical crypto flag candidates",
                evidence={
                    "flags": ["flag{expanded_single_xor}"],
                    "single_byte_xor": {
                        "ciphertext": "515b56504c524f47565953525368445e59505b52684f58454a",
                        "flags": ["flag{expanded_single_xor}"],
                        "key": "0x37",
                        "method": "single_byte_xor",
                        "plaintext_preview": "flag{expanded_single_xor}",
                    },
                },
                confidence=0.84,
                hypothesis="Classical XOR recovery produced a flag-like plaintext.",
                next_action="Send recovered candidates to Verifier and preserve the ciphertext, key, and method evidence for replay.",
            )
        ]
        challenge = Challenge(
            challenge_id="xor-report",
            category=ChallengeCategory.CRYPTO,
            attachment_paths=("/tmp/crypto_single_xor.txt",),
        )

        report = ReportBuilder().build("xor-report", ("flag{expanded_single_xor}",), findings, [], challenge=challenge)

        steps = {section["title"]: section for section in report["writeup"]["sections"]}["复现步骤"]["steps"]
        self.assertIn("single_byte_xor", " ".join(steps))
        self.assertIn("0x37", " ".join(steps))
        self.assertIn("flag{expanded_single_xor}", " ".join(steps))

    def test_writeup_describes_direct_web_response_flag_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="web-visible-writeup",
                solver="WebSolver",
                finding="Analyzed scoped HTTP response structure",
                evidence={
                    "target": "http://127.0.0.1:18094/visible",
                    "response_sample": "flag{expanded_web_visible}",
                    "response_headers": {"content-type": "text/plain"},
                    "flag_candidates": ["flag{expanded_web_visible}"],
                },
                confidence=0.82,
                hypothesis="The first scoped response contains a flag-like token that should be verified.",
                next_action="Send candidates to Verifier and record the minimal reproduction path.",
            )
        ]
        challenge = Challenge(
            challenge_id="web-visible-writeup",
            category=ChallengeCategory.WEB,
            target="http://127.0.0.1:18094/visible",
        )

        report = ReportBuilder().build("web-visible-writeup", ("flag{expanded_web_visible}",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("curl -i http://127.0.0.1:18094/visible", markdown)
        self.assertIn("flag{expanded_web_visible}", markdown)

    def test_writeup_describes_web_header_cookie_flag_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="web-header-writeup",
                solver="WebSolver",
                finding="Analyzed scoped HTTP response structure",
                evidence={
                    "target": "http://127.0.0.1:18094/header-cookie",
                    "response_sample": "",
                    "response_headers": {
                        "X-Flag-Hint": "flag{expanded_web_header_cookie}",
                        "Set-Cookie": "session=flag{expanded_web_header_cookie}; HttpOnly; Path=/",
                    },
                    "set_cookie_names": ["session"],
                    "flag_candidates": ["flag{expanded_web_header_cookie}"],
                },
                confidence=0.82,
                hypothesis="The first scoped response contains a flag-like token that should be verified.",
                next_action="Send candidates to Verifier and record the minimal reproduction path.",
            )
        ]
        challenge = Challenge(
            challenge_id="web-header-writeup",
            category=ChallengeCategory.WEB,
            target="http://127.0.0.1:18094/header-cookie",
        )

        report = ReportBuilder().build("web-header-writeup", ("flag{expanded_web_header_cookie}",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("curl -i http://127.0.0.1:18094/header-cookie", markdown)
        self.assertIn("X-Flag-Hint", markdown)
        self.assertIn("session", markdown)
        self.assertIn("flag{expanded_web_header_cookie}", markdown)

    def test_writeup_describes_traffic_pcap_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="traffic-writeup",
                solver="TrafficSolver",
                finding="Analyzed packet capture traffic",
                evidence={
                    "artifact": {"name": "traffic_http_0.pcap"},
                    "flag_candidates": ["flag{expanded_traffic_http_0}"],
                    "http_object_exports": [
                        {
                            "name": "%2f",
                            "flags": ["flag{expanded_traffic_http_0}"],
                            "text_preview": "flag{expanded_traffic_http_0}",
                        }
                    ],
                    "tcp_stream_payloads": [
                        {
                            "stream_id": "0",
                            "flags": ["flag{expanded_traffic_http_0}"],
                            "sample": "GET / HTTP/1.1 flag{expanded_traffic_http_0}",
                        }
                    ],
                },
                confidence=0.82,
                next_action="Send candidates to Verifier and preserve the packet capture as reproduction evidence.",
            )
        ]
        observations = [
            Observation(
                challenge_id="traffic-writeup",
                source="TrafficSolver",
                kind="flag_candidate",
                summary="flag{expanded_traffic_http_0}",
                evidence={"candidate": "flag{expanded_traffic_http_0}"},
            )
        ]
        challenge = Challenge(
            challenge_id="traffic-writeup",
            category=ChallengeCategory.TRAFFIC,
            attachment_paths=("/tmp/traffic_http_0.pcap",),
        )

        report = ReportBuilder().build("traffic-writeup", ("flag{expanded_traffic_http_0}",), findings, observations, challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("tshark", markdown)
        self.assertIn("tcp.stream eq 0", markdown)
        self.assertIn("flag{expanded_traffic_http_0}", markdown)

    def test_writeup_describes_antsword_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="antsword-writeup",
                solver="TrafficSolver",
                finding="Analyzed packet capture traffic",
                evidence={
                    "artifact": {"name": "antsword.pcapng"},
                    "flag_candidates": ["flag{antsword_recovered}"],
                    "antsword_recovery": {
                        "method": "antsword_rot13_reverse_cut",
                        "command_object": "ms(18).jsp",
                        "output_object": "ms(14).jsp",
                        "positions": [1, 2, 3],
                        "reconstructed_text": "flag{antsword_recovered}",
                        "flag_candidates": ["flag{antsword_recovered}"],
                    },
                },
                confidence=0.82,
                next_action="Send candidates to Verifier and preserve the packet capture as reproduction evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="antsword-writeup",
            category=ChallengeCategory.TRAFFIC,
            attachment_paths=("/tmp/antsword.pcapng",),
        )

        report = ReportBuilder().build("antsword-writeup", ("flag{antsword_recovered}",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("导出 HTTP object", markdown)
        self.assertIn("ms(18).jsp", markdown)
        self.assertIn("cut -c", markdown)
        self.assertIn("ms(14).jsp", markdown)
        self.assertIn("ROT13", markdown)
        self.assertIn("flag{antsword_recovered}", markdown)

    def test_writeup_describes_dns_exfil_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="dns-writeup",
                solver="TrafficSolver",
                finding="Analyzed packet capture traffic",
                evidence={
                    "artifact": {"name": "traffic_dns_0.pcap"},
                    "flag_candidates": ["flag{expanded_traffic_dns_0}"],
                    "dns_summary": {
                        "decoded_query_hints": ["flag{expanded_traffic_dns_0}"],
                        "query_names": [
                            {
                                "name": "mzwgcz33mv4haylomr.swix3uojqwmztjmnpw.i3ttl4yh2.exfil.test",
                                "count": 1,
                            }
                        ],
                    },
                },
                confidence=0.82,
                next_action="Send candidates to Verifier and preserve the packet capture as reproduction evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="dns-writeup",
            category=ChallengeCategory.TRAFFIC,
            attachment_paths=("/tmp/traffic_dns_0.pcap",),
        )

        report = ReportBuilder().build("dns-writeup", ("flag{expanded_traffic_dns_0}",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("dns.qry.name", markdown)
        self.assertIn("mzwgcz33mv4haylomr", markdown)
        self.assertIn("flag{expanded_traffic_dns_0}", markdown)

    def test_writeup_describes_forensics_strings_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="forensics-writeup",
                solver="ForensicsSolver",
                finding="Triaged forensic attachment",
                evidence={
                    "artifact": {"name": "forensics_strings.bin"},
                    "flag_candidates": ["flag{expanded_forensics_strings}"],
                    "tool_samples": {
                        "file": {"stdout": "forensics_strings.bin: data\n"},
                        "strings": {"stdout": "flag{expanded_forensics_strings}\n"},
                    },
                },
                confidence=0.78,
                next_action="Send candidates to Verifier and preserve the attachment path as reproduction evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="forensics-writeup",
            category=ChallengeCategory.FORENSICS,
            attachment_paths=("/tmp/forensics_strings.bin",),
        )

        report = ReportBuilder().build("forensics-writeup", ("flag{expanded_forensics_strings}",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("file forensics_strings.bin", markdown)
        self.assertIn("strings -n 4 forensics_strings.bin", markdown)
        self.assertIn("flag{expanded_forensics_strings}", markdown)

    def test_writeup_describes_pwn_tcp_banner_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="pwn-service-writeup",
                solver="PwnSolver",
                finding="Interacted with scoped pwn service",
                evidence={
                    "target": "127.0.0.1:31337",
                    "flag_candidates": ["flag{expanded_pwn_service_banner}"],
                    "transcript": "ready\nflag{expanded_pwn_service_banner}\n",
                },
                confidence=0.78,
                next_action="Send candidates to Verifier and preserve the TCP transcript as replay evidence.",
            )
        ]

        report = ReportBuilder().build("pwn-service-writeup", ("flag{expanded_pwn_service_banner}",), findings, [])

        markdown = report["writeup"]["markdown"]
        self.assertIn("nc 127.0.0.1 31337", markdown)
        self.assertIn("flag{expanded_pwn_service_banner}", markdown)

    def test_writeup_describes_extra_png_idat_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="png-idat-writeup",
                solver="MiscSolver",
                finding="Analyzed misc image artifact",
                evidence={
                    "artifact": {"name": "pngcheck.png", "path": "/tmp/pngcheck.png"},
                    "flag_candidates": ["flag{extra_png_idat}"],
                    "image_stego": {
                        "chunks": [
                            {"type": "IHDR", "size": 13},
                            {"type": "IDAT", "size": 135317},
                            {"type": "IDAT", "size": 92, "truncated": True},
                        ],
                        "idat_payloads": [
                            {
                                "chunk_index": 1,
                                "decompressed_size": 22,
                                "text_preview": "flag{extra_png_idat}",
                                "flag_like_strings": ["flag{extra_png_idat}"],
                                "truncated_chunk": True,
                            }
                        ],
                    },
                },
                confidence=0.78,
                hypothesis="Image metadata or appended bytes contain a flag-like token.",
                next_action="Send image-derived flag candidates to Verifier and preserve the image evidence path.",
            )
        ]
        challenge = Challenge(
            challenge_id="png-idat-writeup",
            category=ChallengeCategory.MISC,
            attachment_paths=("/tmp/pngcheck.png",),
        )

        report = ReportBuilder().build("png-idat-writeup", ("flag{extra_png_idat}",), findings, [], challenge=challenge)

        sections = {section["title"]: section for section in report["writeup"]["sections"]}
        self.assertEqual(
            sections["复现步骤"]["steps"],
            [
                "打开附件 pngcheck.png，用 PNG chunk 解析工具检查结构。",
                "发现额外的 IDAT chunk：chunk_index=1，且该 chunk 存在截断/长度异常。",
                "将该 IDAT 数据按独立 zlib 流解压，得到文本 flag{extra_png_idat}。",
                "提交 flag{extra_png_idat}，verifier 验证通过。",
            ],
        )
        self.assertEqual(list(sections), ["解题思路", "复现步骤"])
        self.assertNotIn("关键证据", report["writeup"]["markdown"])

    def test_writeup_describes_archive_preview_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="archive-writeup",
                solver="MiscSolver",
                finding="Analyzed misc archive artifact",
                evidence={
                    "artifact": {"name": "misc_zip.zip", "path": "/tmp/misc_zip.zip"},
                    "archive": {
                        "kind": "zip",
                        "entry_count": 1,
                        "interesting_entries": ["secret/flag.txt"],
                        "entries": [
                            {
                                "name": "secret/flag.txt",
                                "size": 23,
                                "compressed_size": 23,
                                "encrypted": False,
                                "is_dir": False,
                            }
                        ],
                    },
                    "archive_text_previews": [
                        {"name": "secret/flag.txt", "size": 23, "text_preview": "flag{expanded_misc_zip}"}
                    ],
                    "flag_candidates": ["flag{expanded_misc_zip}"],
                },
                confidence=0.78,
                hypothesis="Archive preview contains a flag-like token.",
                next_action="Send archive-derived candidates to Verifier and preserve the archive preview evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="archive-writeup",
            category=ChallengeCategory.MISC,
            attachment_paths=("/tmp/misc_zip.zip",),
        )

        report = ReportBuilder().build("archive-writeup", ("flag{expanded_misc_zip}",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("unzip -l misc_zip.zip", markdown)
        self.assertIn("unzip -p misc_zip.zip secret/flag.txt", markdown)
        self.assertIn("flag{expanded_misc_zip}", markdown)

    def test_writeup_describes_png_text_chunk_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="png-text-writeup",
                solver="MiscSolver",
                finding="Analyzed misc image artifact",
                evidence={
                    "artifact": {"name": "misc_png.png", "path": "/tmp/misc_png.png"},
                    "flag_candidates": ["flag{expanded_misc_png}"],
                    "image_stego": {
                        "format": "png",
                        "chunks": [
                            {"type": "IHDR", "size": 13},
                            {"type": "tEXt", "size": 31},
                            {"type": "IDAT", "size": 12},
                            {"type": "IEND", "size": 0},
                        ],
                        "text_chunks": [
                            {
                                "keyword": "Comment",
                                "text_preview": "flag{expanded_misc_png}",
                                "type": "tEXt",
                            }
                        ],
                    },
                },
                confidence=0.78,
                hypothesis="PNG text chunk contains a flag-like token.",
                next_action="Send image-derived flag candidates to Verifier and preserve the image evidence path.",
            )
        ]
        challenge = Challenge(
            challenge_id="png-text-writeup",
            category=ChallengeCategory.MISC,
            attachment_paths=("/tmp/misc_png.png",),
        )

        report = ReportBuilder().build("png-text-writeup", ("flag{expanded_misc_png}",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("file misc_png.png", markdown)
        self.assertIn("exiftool misc_png.png", markdown)
        self.assertIn("tEXt/Comment", markdown)
        self.assertIn("flag{expanded_misc_png}", markdown)


if __name__ == "__main__":
    unittest.main()

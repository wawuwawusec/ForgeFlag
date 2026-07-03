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

    def test_flag_report_prefers_latest_candidate_evidence_over_stale_payload_match(self) -> None:
        findings = [
            Finding(
                challenge_id="report-stale",
                solver="TrafficSolver",
                finding="Analyzed packet capture traffic",
                evidence={"decoded_http_artifacts": ["X@Yflag{This_is_a_f10g} [S] /var/www/html [E] X@Y"], "flag_candidates": []},
                confidence=0.62,
                next_action="Add DNS, HTTP, or TCP stream-specific analysis based on protocol hierarchy and conversations.",
                created_at="2026-06-30T03:05:46+00:00",
            ),
            Finding(
                challenge_id="report-stale",
                solver="TrafficSolver",
                finding="Analyzed packet capture traffic",
                evidence={"decoded_http_artifacts": ["flag{This_is_a_f10g}"], "flag_candidates": ["flag{This_is_a_f10g}"]},
                confidence=0.82,
                next_action="Send candidates to Verifier and preserve the packet capture as reproduction evidence.",
                created_at="2026-06-30T03:12:19+00:00",
            ),
        ]
        observations = [
            Observation(
                challenge_id="report-stale",
                source="TrafficSolver",
                kind="flag_candidate",
                summary="flag{This_is_a_f10g}",
                evidence={"candidate": "flag{This_is_a_f10g}"},
            )
        ]

        report = ReportBuilder().build("report-stale", ("flag{This_is_a_f10g}",), findings, observations)

        self.assertEqual(report["flags"][0]["path"][0]["evidence"]["flag_candidates"], ["flag{This_is_a_f10g}"])
        self.assertEqual(
            report["flags"][0]["path"][0]["next_action"],
            "Send candidates to Verifier and preserve the packet capture as reproduction evidence.",
        )

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

    def test_writeup_generic_replay_steps_include_verified_flag(self) -> None:
        findings = [
            Finding(
                challenge_id="web-visible-generic",
                solver="ReconSolver",
                finding="Found visible text flag candidate",
                evidence={"flag_candidates": ["flag{generic_visible}"]},
                confidence=0.82,
                hypothesis="The prompt text contains a flag-like token.",
                next_action="Verify whether the text candidate is the intended flag, then record the shortest reproduction path.",
            )
        ]
        observations = [
            Observation(
                challenge_id="web-visible-generic",
                source="ReconSolver",
                kind="flag_candidate",
                summary="flag{generic_visible}",
                evidence={"candidate": "flag{generic_visible}"},
            )
        ]

        report = ReportBuilder().build("web-visible-generic", ("flag{generic_visible}",), findings, observations)

        sections = {section["title"]: section for section in report["writeup"]["sections"]}
        replay_text = "\n".join(sections["复现步骤"]["steps"])
        self.assertIn("flag{generic_visible}", replay_text)
        self.assertIn("flag{generic_visible}", report["writeup"]["markdown"])
        self.assertEqual([section["title"] for section in report["writeup"]["sections"]], ["解题思路", "复现步骤"])

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

    def test_writeup_prioritizes_python_random_prime_offset_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="crypto-random-prime-offset",
                solver="CryptoSolver",
                finding="Recovered Python random prime-offset flag candidates",
                evidence={
                    "python_random_prime_offset": {
                        "enc": "567785900217270586430439246129051365510368280197",
                        "flags": ["ctf{true_0r_false??}"],
                        "gift_hex": "12131e00001f0a1301",
                        "key": "fake_seed",
                        "method": "python_random_prime_offset",
                        "plaintext_preview": "ctf{true_0r_false??}",
                        "r": 9533,
                        "randint_bounds": [[1048576, 2097152], [1000, 10000]],
                        "seed_hex": "747275655f6c6f7665",
                        "seed_int": "2148069922303422461541",
                        "seed_text": "true_love",
                        "t": 1713221,
                    }
                },
                confidence=0.86,
                hypothesis="A byte seed was recovered from key XOR gift output, then Python random reproduced prime offsets around the flag integer.",
                next_action="Send recovered candidates to Verifier and preserve the XOR-derived seed and prime offsets for replay.",
            )
        ]
        observations = [
            Observation(
                challenge_id="crypto-random-prime-offset",
                source="CryptoSolver",
                kind="flag_candidate",
                summary="ctf{true_0r_false??}",
                evidence={"candidate": "ctf{true_0r_false??}"},
            )
        ]
        challenge = Challenge(
            challenge_id="crypto-random-prime-offset",
            category=ChallengeCategory.CRYPTO,
            attachment_paths=("/tmp/easy_random.py",),
        )

        report = ReportBuilder().build(
            "crypto-random-prime-offset",
            ("ctf{true_0r_false??}",),
            findings,
            observations,
            challenge=challenge,
        )

        sections = {section["title"]: section for section in report["writeup"]["sections"]}
        self.assertIn("key ^ gift", sections["解题思路"]["body"])
        self.assertEqual(
            sections["复现步骤"]["steps"],
            [
                "打开附件 easy_random.py，确认 key 与 gift 输出可异或恢复 Python random 的字节 seed。",
                "计算 seed = key XOR gift，得到 seed=true_love。",
                "按源码执行 random.seed(bytes_to_long(seed))，再计算 t=next_prime(randint(...)) 与 r=next_prime(randint(...))。",
                "用输出整数减去 t 并加回 r，转 bytes 得到 ctf{true_0r_false??}。",
            ],
        )
        self.assertIn("seed=true_love", report["writeup"]["markdown"])

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

    def test_writeup_describes_pe_stack_xor_key_check_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="reverse-pe-xor",
                solver="ReverseSolver",
                finding="Analyzed reverse binary artifact",
                evidence={
                    "artifact": "/tmp/reverseMe.exe",
                    "flag_candidates": ["XCTF{5eacs6y8p1o9gitc9521}"],
                    "pe_stack_xor_key_check": {
                        "pattern": "PE stack byte array decrypted by generated XOR key before input compare",
                        "source": "binary_bytes",
                        "seed": 56,
                        "length": 26,
                        "encrypted_hex": "e376fb6fd828f270e87649804b9d568e62b226bd208402831ad8",
                        "xor_key_preview_hex": "bb35af29a31d97118b057ff973ed67e1",
                        "decoded_text": "XCTF{5eacs6y8p1o9gitc9521}",
                        "flag_candidates": ["XCTF{5eacs6y8p1o9gitc9521}"],
                    },
                    "tool_samples": {
                        "file_identify": {
                            "stdout": "/tmp/reverseMe.exe: PE32 executable (console) Intel 80386, for MS Windows\n",
                            "stderr": "",
                        },
                        "strings_extract": {
                            "stdout": "please input the key:\nright!!!\nerror!!!\n",
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
            challenge_id="reverse-pe-xor",
            category=ChallengeCategory.REVERSE,
            attachment_paths=("/tmp/reverseMe.exe",),
        )

        report = ReportBuilder().build("reverse-pe-xor", ("XCTF{5eacs6y8p1o9gitc9521}",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("栈上初始化的加密字节", markdown)
        self.assertIn("seed `56`", markdown)
        self.assertIn("e376fb6fd828f270e87649804b9d568e62b226bd208402831ad8", markdown)
        self.assertIn("XOR key", markdown)
        self.assertIn("XCTF{5eacs6y8p1o9gitc9521}", markdown)
        self.assertNotIn("strings 输出中看到", markdown)

    def test_writeup_describes_elf_argv_repeating_xor_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="reverse-xor-nodebug",
                solver="ReverseSolver",
                finding="Analyzed reverse binary artifact",
                evidence={
                    "artifact": "/tmp/xor_nodebug",
                    "flag_candidates": ["reverse_xor"],
                    "elf_argv_repeating_xor": {
                        "pattern": "ELF argv repeating XOR validation against .rodata string",
                        "source": "objdump_disassemble+objdump_rodata",
                        "key_hex": "010203050607",
                        "key_length": 6,
                        "ciphertext_address": "0x2015",
                        "ciphertext": "sgu`ttd]{jt",
                        "recovered_input": "reverse_xor",
                        "flag_candidates": ["reverse_xor"],
                    },
                    "tool_samples": {
                        "file_identify": {
                            "stdout": "/tmp/xor_nodebug: ELF 64-bit LSB pie executable, x86-64\n",
                            "stderr": "",
                        },
                        "strings_extract": {
                            "stdout": "ptrace\nstrcmp\nstrlen\ndon't trace me:(\nsgu`ttd]{jt\nright\n",
                            "stderr": "",
                        },
                    },
                },
                confidence=0.78,
                hypothesis="Local reverse triage surfaced a recovered input that should be verified.",
                next_action="Send candidates to Verifier and preserve local tool outputs as replay evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="reverse-xor-nodebug",
            category=ChallengeCategory.REVERSE,
            attachment_paths=("/tmp/xor_nodebug",),
        )

        report = ReportBuilder().build("reverse-xor-nodebug", ("reverse_xor",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("argv 参数", markdown)
        self.assertIn("0x2015", markdown)
        self.assertIn("``sgu`ttd]{jt``", markdown)
        self.assertIn("010203050607", markdown)
        self.assertIn("reverse_xor", markdown)
        self.assertNotIn("strings 输出中看到", markdown)

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

    def test_writeup_describes_encoded_jpeg_comment_reproduction_steps(self) -> None:
        source = "U1ZJQlJHe2pwZWdfY29tbWVudF9iNjR9"
        findings = [
            Finding(
                challenge_id="jpeg-comment-report",
                solver="ForensicsSolver",
                finding="Triaged forensic attachment",
                evidence={
                    "artifact": {"name": "cat.jpg", "path": "/tmp/cat.jpg"},
                    "flag_candidates": ["SVIBRG{jpeg_comment_b64}"],
                    "image_stego": {
                        "format": "jpeg",
                        "comments": [{"text_preview": source}],
                    },
                    "decoded_image_text_candidates": [
                        {
                            "recipe": ["base64_decode"],
                            "source": source,
                            "value": "SVIBRG{jpeg_comment_b64}",
                        }
                    ],
                    "tool_samples": {
                        "file": {"stdout": "/tmp/cat.jpg: JPEG image data\n", "stderr": ""},
                        "strings": {"stdout": source + "\n", "stderr": ""},
                    },
                },
                confidence=0.78,
                hypothesis="Image metadata contains encoded flag-like data.",
                next_action="Send candidates to Verifier and preserve the attachment path as reproduction evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="jpeg-comment-report",
            category=ChallengeCategory.FORENSICS,
            attachment_paths=("/tmp/cat.jpg",),
        )

        report = ReportBuilder().build(
            "jpeg-comment-report",
            ("SVIBRG{jpeg_comment_b64}",),
            findings,
            [],
            challenge=challenge,
        )

        markdown = report["writeup"]["markdown"]
        self.assertIn("JPEG COM 注释", markdown)
        self.assertIn(f"printf '%s' '{source}' | base64 -d", markdown)
        self.assertIn("SVIBRG{jpeg_comment_b64}", markdown)
        self.assertNotIn("在 strings/元数据输出中看到 SVIBRG{jpeg_comment_b64}", markdown)

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

    def test_writeup_describes_lfsr_berlekamp_massey_recovery(self) -> None:
        findings = [
            Finding(
                challenge_id="lfsr-bm-report",
                solver="CryptoSolver",
                finding="Recovered LFSR Berlekamp-Massey flag candidates",
                evidence={
                    "lfsr_bm": {
                        "method": "lfsr_berlekamp_massey",
                        "flags": ["de1ctf{1224473d5e349dbf2946353444d727d8fa91da3275ed3ac0dedeb7e6a9ad8619}"],
                        "plaintext_preview": "de1ctf{1224473d5e349dbf2946353444d727d8fa91da3275ed3ac0dedeb7e6a9ad8619}",
                        "linear_complexity": 256,
                        "free_variables": 7,
                        "sequence_bits": 504,
                        "key_sha256_prefix": "1224",
                    }
                },
                confidence=0.86,
                hypothesis="LFSR output was recovered with GF(2) linear algebra.",
                next_action="Send recovered candidates to Verifier and preserve the sequence, key, mask, and free-variable evidence for replay.",
            )
        ]
        challenge = Challenge(
            challenge_id="lfsr-bm-report",
            category=ChallengeCategory.CRYPTO,
            attachment_paths=("/tmp/BM.py",),
        )

        report = ReportBuilder().build(
            "lfsr-bm-report",
            ("de1ctf{1224473d5e349dbf2946353444d727d8fa91da3275ed3ac0dedeb7e6a9ad8619}",),
            findings,
            [],
            challenge=challenge,
        )

        markdown = report["writeup"]["markdown"]
        self.assertIn("Berlekamp-Massey", markdown)
        self.assertIn("504 bit", markdown)
        self.assertIn("free variables=7", markdown)
        self.assertIn("1224", markdown)
        self.assertIn("de1ctf{1224473d5e349dbf2946353444d727d8fa91da3275ed3ac0dedeb7e6a9ad8619}", markdown)

    def test_rsa_writeup_outputs_reproducible_solve_script(self) -> None:
        findings = [
            Finding(
                challenge_id="rsa-writeup",
                solver="CryptoSolver",
                finding="Recovered RSA flag candidates",
                evidence={
                    "rsa_recovery": {
                        "method": "known_factors",
                        "flags": ["flag{rsa_known_factors}"],
                        "plaintext_preview": "flag{rsa_known_factors}",
                        "parameters": {
                            "n": "499",
                            "e": "5",
                            "c": "42",
                            "p": "31",
                            "q": "17",
                        },
                    }
                },
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the RSA parameters as replay evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="rsa-writeup",
            category=ChallengeCategory.CRYPTO,
            title="RSA known factors",
        )

        report = ReportBuilder().build("rsa-writeup", ("flag{rsa_known_factors}",), findings, [], challenge=challenge)

        writeup = report["writeup"]
        script = writeup["solve_script"]["content"]
        self.assertEqual(writeup["solve_script"]["filename"], "solve_rsa_writeup.py")
        self.assertIn("n = 499", script)
        self.assertIn("p = 31", script)
        self.assertIn("q = 17", script)
        self.assertIn("pow(e, -1, phi)", script)
        self.assertIn("long_to_bytes(m)", script)
        self.assertIn("flag{rsa_known_factors}", writeup["markdown"])
        self.assertIn("### Solve 脚本", writeup["markdown"])

    def test_rsa_low_exponent_writeup_outputs_plaintext_root_solve_script(self) -> None:
        findings = [
            Finding(
                challenge_id="rsa-low-writeup",
                solver="CryptoSolver",
                finding="Recovered RSA flag candidates",
                evidence={
                    "rsa_recovery": {
                        "method": "low_exponent_root",
                        "flags": ["flag{rsa_low_exponent}"],
                        "plaintext_preview": "flag{rsa_low_exponent}",
                        "parameters": {
                            "n": str(2**521 - 1),
                            "e": "3",
                            "c": "123456789",
                        },
                    }
                },
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the RSA parameters as replay evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="rsa-low-writeup",
            category=ChallengeCategory.CRYPTO,
            title="RSA low exponent",
        )

        report = ReportBuilder().build("rsa-low-writeup", ("flag{rsa_low_exponent}",), findings, [], challenge=challenge)

        script = report["writeup"]["solve_script"]["content"]
        self.assertEqual(report["writeup"]["solve_script"]["filename"], "solve_rsa_low_writeup.py")
        self.assertIn('METHOD = "low_exponent_root"', script)
        self.assertIn("integer_nth_root(c, e)", script)
        self.assertIn("if root is None", script)
        self.assertIn("flag{rsa_low_exponent}", report["writeup"]["markdown"])
        self.assertIn("### Solve 脚本", report["writeup"]["markdown"])

    def test_rsa_modular_low_exponent_writeup_outputs_replay_script(self) -> None:
        findings = [
            Finding(
                challenge_id="rsa-modular-low-writeup",
                solver="CryptoSolver",
                finding="Recovered RSA flag candidates",
                evidence={
                    "rsa_recovery": {
                        "method": "modular_low_exponent_root",
                        "flags": ["flag{rsa_modular_low_exp}"],
                        "plaintext_preview": "flag{rsa_modular_low_exp}",
                        "parameters": {
                            "n": str(2**521 - 1),
                            "e": "7",
                            "c": "123456789",
                            "root_multiplier": "8",
                            "root_search_limit": "10000",
                        },
                    }
                },
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the RSA parameters as replay evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="rsa-modular-low-writeup",
            category=ChallengeCategory.CRYPTO,
            title="RSA modular low exponent",
        )

        report = ReportBuilder().build("rsa-modular-low-writeup", ("flag{rsa_modular_low_exp}",), findings, [], challenge=challenge)

        script = report["writeup"]["solve_script"]["content"]
        self.assertEqual(report["writeup"]["solve_script"]["filename"], "solve_rsa_modular_low_writeup.py")
        self.assertIn('METHOD = "modular_low_exponent_root"', script)
        self.assertIn("for k in range(root_search_limit):", script)
        self.assertIn("root = integer_nth_root(c + n * k, e)", script)
        self.assertIn("c + k*n", report["writeup"]["markdown"])
        self.assertIn("k=8", report["writeup"]["markdown"])
        self.assertIn("flag{rsa_modular_low_exp}", report["writeup"]["markdown"])

    def test_rsa_common_modulus_writeup_outputs_replay_script(self) -> None:
        findings = [
            Finding(
                challenge_id="rsa-common-writeup",
                solver="CryptoSolver",
                finding="Recovered RSA flag candidates",
                evidence={
                    "rsa_recovery": {
                        "method": "common_modulus",
                        "flags": ["flag{rsa_common_modulus}"],
                        "plaintext_preview": "flag{rsa_common_modulus}",
                        "parameters": {
                            "n": str(2**521 - 1),
                            "e1": "17",
                            "e2": "65537",
                            "c1": "12345",
                            "c2": "67890",
                        },
                    }
                },
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the RSA parameters as replay evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="rsa-common-writeup",
            category=ChallengeCategory.CRYPTO,
            title="RSA common modulus",
        )

        report = ReportBuilder().build("rsa-common-writeup", ("flag{rsa_common_modulus}",), findings, [], challenge=challenge)

        script = report["writeup"]["solve_script"]["content"]
        self.assertEqual(report["writeup"]["solve_script"]["filename"], "solve_rsa_common_writeup.py")
        self.assertIn('METHOD = "common_modulus"', script)
        self.assertIn("common_modulus_recover(c1, c2, e1, e2, n)", script)
        self.assertIn("mod_inverse", script)
        self.assertIn("flag{rsa_common_modulus}", report["writeup"]["markdown"])
        self.assertIn("### Solve 脚本", report["writeup"]["markdown"])

    def test_rsa_shared_prime_writeup_outputs_replay_script(self) -> None:
        findings = [
            Finding(
                challenge_id="rsa-shared-writeup",
                solver="CryptoSolver",
                finding="Recovered RSA flag candidates",
                evidence={
                    "rsa_recovery": {
                        "method": "shared_prime",
                        "flags": ["flag{rsa_shared_prime}"],
                        "plaintext_preview": "flag{rsa_shared_prime}",
                        "parameters": {
                            "n1": "123456789",
                            "n2": "987654321",
                            "e": "65537",
                            "c1": "424242",
                            "p": "9",
                        },
                    }
                },
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the RSA parameters as replay evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="rsa-shared-writeup",
            category=ChallengeCategory.CRYPTO,
            title="RSA shared prime",
        )

        report = ReportBuilder().build("rsa-shared-writeup", ("flag{rsa_shared_prime}",), findings, [], challenge=challenge)

        script = report["writeup"]["solve_script"]["content"]
        self.assertEqual(report["writeup"]["solve_script"]["filename"], "solve_rsa_shared_writeup.py")
        self.assertIn('METHOD = "shared_prime"', script)
        self.assertIn("shared_prime_recover(n1, n2, e, c1)", script)
        self.assertIn("math.gcd(n1, n2)", script)
        self.assertIn("flag{rsa_shared_prime}", report["writeup"]["markdown"])
        self.assertIn("### Solve 脚本", report["writeup"]["markdown"])

    def test_rsa_broadcast_writeup_outputs_replay_script(self) -> None:
        findings = [
            Finding(
                challenge_id="rsa-broadcast-writeup",
                solver="CryptoSolver",
                finding="Recovered RSA flag candidates",
                evidence={
                    "rsa_recovery": {
                        "method": "broadcast",
                        "flags": ["flag{rsa_broadcast}"],
                        "plaintext_preview": "flag{rsa_broadcast}",
                        "parameters": {
                            "n1": "101",
                            "n2": "103",
                            "n3": "107",
                            "e": "3",
                            "c1": "42",
                            "c2": "43",
                            "c3": "44",
                        },
                    }
                },
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the RSA parameters as replay evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="rsa-broadcast-writeup",
            category=ChallengeCategory.CRYPTO,
            title="RSA broadcast",
        )

        report = ReportBuilder().build("rsa-broadcast-writeup", ("flag{rsa_broadcast}",), findings, [], challenge=challenge)

        script = report["writeup"]["solve_script"]["content"]
        self.assertEqual(report["writeup"]["solve_script"]["filename"], "solve_rsa_broadcast_writeup.py")
        self.assertIn('METHOD = "broadcast"', script)
        self.assertIn("broadcast_recover([c1, c2, c3], [n1, n2, n3], e)", script)
        self.assertIn("crt_combine", script)
        self.assertIn("flag{rsa_broadcast}", report["writeup"]["markdown"])
        self.assertIn("### Solve 脚本", report["writeup"]["markdown"])

    def test_rsa_prime_modulus_writeup_outputs_replay_script(self) -> None:
        findings = [
            Finding(
                challenge_id="rsa-prime-writeup",
                solver="CryptoSolver",
                finding="Recovered RSA flag candidates",
                evidence={
                    "rsa_recovery": {
                        "method": "prime_modulus",
                        "flags": ["flag{rsa_prime_modulus}"],
                        "plaintext_preview": "flag{rsa_prime_modulus}",
                        "parameters": {
                            "n": str(2**521 - 1),
                            "e": "65537",
                            "c": "123456789",
                        },
                    }
                },
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the RSA parameters as replay evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="rsa-prime-writeup",
            category=ChallengeCategory.CRYPTO,
            title="RSA prime modulus",
        )

        report = ReportBuilder().build("rsa-prime-writeup", ("flag{rsa_prime_modulus}",), findings, [], challenge=challenge)

        script = report["writeup"]["solve_script"]["content"]
        self.assertEqual(report["writeup"]["solve_script"]["filename"], "solve_rsa_prime_writeup.py")
        self.assertIn('METHOD = "prime_modulus"', script)
        self.assertIn("m = decrypt_prime_modulus(n, e, c)", script)
        self.assertIn("phi = n - 1", script)
        self.assertIn("flag{rsa_prime_modulus}", report["writeup"]["markdown"])
        self.assertIn("### Solve 脚本", report["writeup"]["markdown"])

    def test_rsa_fermat_writeup_outputs_replay_script(self) -> None:
        findings = [
            Finding(
                challenge_id="rsa-fermat-writeup",
                solver="CryptoSolver",
                finding="Recovered RSA flag candidates",
                evidence={
                    "rsa_recovery": {
                        "method": "fermat_factors",
                        "flags": ["flag{rsa_fermat}"],
                        "plaintext_preview": "flag{rsa_fermat}",
                        "parameters": {
                            "n": "28948022309329048855892746252171976968225213274203289145376257814616423610039",
                            "e": "65537",
                            "c": "123456789",
                            "p": "170141183460469231731687303715884105727",
                            "q": "170141183460469231731687303715884105757",
                        },
                    }
                },
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the RSA parameters as replay evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="rsa-fermat-writeup",
            category=ChallengeCategory.CRYPTO,
            title="RSA close primes",
        )

        report = ReportBuilder().build("rsa-fermat-writeup", ("flag{rsa_fermat}",), findings, [], challenge=challenge)

        script = report["writeup"]["solve_script"]["content"]
        self.assertEqual(report["writeup"]["solve_script"]["filename"], "solve_rsa_fermat_writeup.py")
        self.assertIn('METHOD = "fermat_factors"', script)
        self.assertIn("fermat_factor(n)", script)
        self.assertIn("m = decrypt_with_factors(n, e, c, p, q)", script)
        self.assertIn("flag{rsa_fermat}", report["writeup"]["markdown"])
        self.assertIn("### Solve 脚本", report["writeup"]["markdown"])

    def test_aes_ctr_reuse_writeup_outputs_crib_solve_script(self) -> None:
        findings = [
            Finding(
                challenge_id="ctr-writeup",
                solver="CryptoSolver",
                finding="Identified crypto primitive misuse pattern",
                evidence={
                    "pattern": "aes_ctr_nonce_reuse",
                    "source_lines": [
                        "cipher = AES.new(key, AES.MODE_CTR, nonce=b'fixed')",
                        "ct1 = '001122'",
                        "ct2 = '334455'",
                    ],
                },
                confidence=0.72,
                next_action="Collect ciphertexts, nonce, and known plaintext cribs; XOR ciphertexts to recover keystream bytes.",
            )
        ]
        challenge = Challenge(
            challenge_id="ctr-writeup",
            category=ChallengeCategory.CRYPTO,
            title="CTR nonce reuse",
        )

        report = ReportBuilder().build("ctr-writeup", (), findings, [], challenge=challenge)

        writeup = report["writeup"]
        script = writeup["solve_script"]["content"]
        self.assertEqual(writeup["solve_script"]["filename"], "solve_ctr_writeup.py")
        self.assertIn("def xor_bytes", script)
        self.assertIn("CIPHERTEXTS_HEX", script)
        self.assertIn("KNOWN_PLAINTEXTS", script)
        self.assertIn("keystream", script)
        self.assertIn("AES-CTR", writeup["markdown"])
        self.assertIn("### Solve 脚本", writeup["markdown"])

    def test_poly1305_reuse_writeup_outputs_algebra_solve_script(self) -> None:
        findings = [
            Finding(
                challenge_id="poly-writeup",
                solver="CryptoSolver",
                finding="Identified crypto primitive misuse pattern",
                evidence={
                    "pattern": "poly1305_one_time_key_reuse",
                    "source_lines": [
                        "Poly1305 one-time MAC key was reused",
                        "solve algebra equations over message/tag pairs",
                    ],
                },
                confidence=0.72,
                next_action="Extract message/tag pairs, model the reused one-time key equations, then solve with Sage.",
            )
        ]
        challenge = Challenge(
            challenge_id="poly-writeup",
            category=ChallengeCategory.CRYPTO,
            title="Poly1305 reuse",
        )

        report = ReportBuilder().build("poly-writeup", (), findings, [], challenge=challenge)

        writeup = report["writeup"]
        script = writeup["solve_script"]["content"]
        self.assertEqual(writeup["solve_script"]["filename"], "solve_poly_writeup.py")
        self.assertIn("P = 2**130 - 5", script)
        self.assertIn("MESSAGE_TAG_PAIRS", script)
        self.assertIn("PolynomialRing", script)
        self.assertIn("for carry", script)
        self.assertIn(".roots()", script)
        self.assertIn("Poly1305", writeup["markdown"])
        self.assertIn("### Solve 脚本", writeup["markdown"])

    def test_aes_gcm_reuse_writeup_outputs_forbidden_attack_solve_script(self) -> None:
        findings = [
            Finding(
                challenge_id="gcm-writeup",
                solver="CryptoSolver",
                finding="Identified crypto primitive misuse pattern",
                evidence={
                    "pattern": "aes_gcm_nonce_reuse",
                    "source_lines": [
                        "AES.new(key, AES.MODE_GCM, nonce=nonce)",
                        "same nonce reused for c1/tag1 and c2/tag2",
                    ],
                },
                confidence=0.72,
                next_action="Collect nonce, AAD, ciphertexts, and tags; solve GHASH equations before attempting forgery.",
            )
        ]
        challenge = Challenge(
            challenge_id="gcm-writeup",
            category=ChallengeCategory.CRYPTO,
            title="GCM nonce reuse",
        )

        report = ReportBuilder().build("gcm-writeup", (), findings, [], challenge=challenge)

        writeup = report["writeup"]
        script = writeup["solve_script"]["content"]
        self.assertEqual(writeup["solve_script"]["filename"], "solve_gcm_writeup.py")
        self.assertIn("AES-GCM nonce reuse", script)
        self.assertIn("AAD_HEX", script)
        self.assertIn("CIPHERTEXT_TAG_PAIRS", script)
        self.assertIn("GHASH", script)
        self.assertIn("forbidden attack", script)
        self.assertIn("AES-GCM", writeup["markdown"])
        self.assertIn("### Solve 脚本", writeup["markdown"])

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

    def test_writeup_describes_corrupt_pcap_ip_id_stego_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="traffic-ipid-writeup",
                solver="TrafficSolver",
                finding="Analyzed packet capture traffic",
                evidence={
                    "artifact": {"name": "findtheflag.cap"},
                    "flag_candidates": ["flag{aha!_you_found_it!}"],
                    "pcap_record_resync": {
                        "method": "pcap_record_header_resync",
                        "path": ".forgeflag/artifacts/traffic-ipid/pcap-repairs/findtheflag/findtheflag-resync.cap",
                        "records_recovered": 1600,
                        "repair_count": 166,
                        "repairs": [
                            {
                                "record": 18,
                                "old_incl_len": 386,
                                "fixed_incl_len": 377,
                                "next_header_offset": 2307,
                            }
                        ],
                    },
                    "ip_id_stego": {
                        "method": "ipv4_identification_little_endian_pairs",
                        "marker": "where is the flag?",
                        "adjacent_deduped_ip_ids_hex": [
                            "0x6c66",
                            "0x6761",
                            "0x617b",
                            "0x6168",
                        ],
                        "flag_candidates": ["flag{aha!_you_found_it!}"],
                    },
                },
                confidence=0.82,
                next_action="Send candidates to Verifier and preserve the packet capture as reproduction evidence.",
            )
        ]
        challenge = Challenge(
            challenge_id="traffic-ipid-writeup",
            category=ChallengeCategory.TRAFFIC,
            attachment_paths=("/tmp/findtheflag.cap",),
        )

        report = ReportBuilder().build("traffic-ipid-writeup", ("flag{aha!_you_found_it!}",), findings, [], challenge=challenge)

        markdown = report["writeup"]["markdown"]
        self.assertIn("PCAP", markdown)
        self.assertIn("record 18", markdown)
        self.assertIn("findtheflag-resync.cap", markdown)
        self.assertIn("IPv4 Identification", markdown)
        self.assertIn("where is the flag?", markdown)
        self.assertIn("0x6c66 0x6761 0x617b 0x6168", markdown)
        self.assertIn("little-endian", markdown)
        self.assertIn("flag{aha!_you_found_it!}", markdown)

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

    def test_pwn_writeup_outputs_configurable_shell_exploit_script(self) -> None:
        findings = [
            Finding(
                challenge_id="pwn-format-writeup",
                solver="PwnSolver",
                finding="Found FTP heap format string shell path",
                evidence={
                    "workflow_guess": "ftp_heap_format_string",
                    "exploit_plan": {
                        "workflow": "ftp_heap_format_string",
                        "login_input": "rxraclhm",
                        "format_offset": 7,
                        "leak": "Upload p32(elf.got['printf']) and read it back with `%8$.4s`.",
                        "libc_base": "printf_leak - libc.symbols['printf']",
                        "overwrite_target": "Overwrite printf@got with system.",
                        "trigger": "Upload cmd=/bin/sh and get cmd.",
                        "payload_template": "fmtstr_payload(7, {elf.got['printf']: libc.symbols['system']}, write_size='short')",
                    },
                },
                confidence=0.86,
                next_action="Run the generated exploit locally or against the remote service.",
            )
        ]
        challenge = Challenge(
            challenge_id="pwn-format-writeup",
            category=ChallengeCategory.PWN,
            title="CCTF pwn3",
            attachment_paths=("/tmp/2016-CCTF-pwn3",),
        )

        report = ReportBuilder().build("pwn-format-writeup", (), findings, [], challenge=challenge)

        writeup = report["writeup"]
        steps = {section["title"]: section for section in writeup["sections"]}["复现步骤"]["steps"]
        script = writeup["exploit_script"]["content"]
        self.assertEqual(writeup["exploit_script"]["filename"], "exploit_pwn_format_writeup.py")
        self.assertIn("本地模式", steps[0])
        self.assertIn("远程模式", steps[1])
        self.assertIn("LOGIN_INPUT = b\"rxraclhm\"", script)
        self.assertIn('parser.add_argument("--host"', script)
        self.assertIn('parser.add_argument("--port", type=int', script)
        self.assertIn('parser.add_argument("--remote", action="store_true")', script)
        self.assertIn("process(args.binary)", script)
        self.assertIn("remote(args.host, args.port)", script)
        self.assertIn("fmtstr_payload(FMT_OFFSET", script)
        self.assertIn("io.interactive()", script)
        self.assertIn("```python", writeup["markdown"])

    def test_pwn_ret2win_writeup_outputs_usable_exploit_script(self) -> None:
        findings = [
            Finding(
                challenge_id="pwn-ret2win-writeup",
                solver="PwnSolver",
                finding="Identified pwn source vulnerability pattern",
                evidence={
                    "workflow_guess": "ret2win",
                    "exploit_plan": {
                        "workflow": "ret2win",
                        "symbol": "win",
                        "crash_harness": "Send cyclic(512), then inspect the crashing instruction pointer.",
                        "cyclic_offset": "Use cyclic_find(core.rip) to compute the exact offset.",
                        "payload_template": "payload = b'A' * offset + p64(elf.symbols['win'])",
                    },
                },
                confidence=0.78,
                next_action="Crash with a cyclic pattern, compute the offset, then send padding plus win.",
            )
        ]
        challenge = Challenge(
            challenge_id="pwn-ret2win-writeup",
            category=ChallengeCategory.PWN,
            title="ret2win",
            attachment_paths=("/tmp/ret2win",),
        )

        report = ReportBuilder().build("pwn-ret2win-writeup", (), findings, [], challenge=challenge)

        writeup = report["writeup"]
        steps = {section["title"]: section for section in writeup["sections"]}["复现步骤"]["steps"]
        script = writeup["exploit_script"]["content"]
        self.assertEqual(writeup["exploit_script"]["filename"], "exploit_pwn_ret2win_writeup.py")
        self.assertIn("本地模式", steps[0])
        self.assertIn("--offset", steps[0])
        self.assertIn("--remote", steps[1])
        self.assertIn('parser.add_argument("--find-offset"', script)
        self.assertIn('parser.add_argument("--offset", type=int', script)
        self.assertIn("cyclic(512)", script)
        self.assertIn('elf.symbols["win"]', script)
        self.assertIn("remote(args.host, args.port)", script)
        self.assertIn("process(args.binary)", script)
        self.assertIn("io.interactive()", script)
        self.assertIn("```python", writeup["markdown"])

    def test_pwn_format_string_writeup_outputs_probe_exploit_script(self) -> None:
        findings = [
            Finding(
                challenge_id="pwn-format-source-writeup",
                solver="PwnSolver",
                finding="Identified pwn source vulnerability pattern",
                evidence={
                    "workflow_guess": "format_string",
                    "exploit_plan": {
                        "workflow": "format_string",
                        "offset_probe": "%p." * 24,
                        "payload_template": "fmtstr_payload(FMT_OFFSET, {WRITE_TARGET: WRITE_VALUE}, write_size='short')",
                    },
                },
                confidence=0.74,
                next_action="Build a pwntools harness and find the stack offset with %p probes.",
            )
        ]
        challenge = Challenge(
            challenge_id="pwn-format-source-writeup",
            category=ChallengeCategory.PWN,
            title="format string",
            attachment_paths=("/tmp/vuln",),
        )

        report = ReportBuilder().build("pwn-format-source-writeup", (), findings, [], challenge=challenge)

        writeup = report["writeup"]
        steps = {section["title"]: section for section in writeup["sections"]}["复现步骤"]["steps"]
        script = writeup["exploit_script"]["content"]
        self.assertEqual(writeup["exploit_script"]["filename"], "exploit_pwn_format_source_writeup.py")
        self.assertIn("--probe", steps[0])
        self.assertIn("--offset", steps[1])
        self.assertIn('parser.add_argument("--probe"', script)
        self.assertIn('parser.add_argument("--offset", type=int', script)
        self.assertIn('parser.add_argument("--write-target"', script)
        self.assertIn('parser.add_argument("--write-value"', script)
        self.assertIn("fmtstr_payload(args.offset", script)
        self.assertIn("remote(args.host, args.port)", script)
        self.assertIn("process(args.binary)", script)
        self.assertIn("io.interactive()", script)
        self.assertIn("```python", writeup["markdown"])

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

    def test_writeup_describes_png_lsb_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="png-lsb-writeup",
                solver="MiscSolver",
                finding="Analyzed misc image artifact",
                evidence={
                    "artifact": {"name": "lsb.png", "path": "/tmp/lsb.png"},
                    "flag_candidates": ["flag{png_lsb}"],
                    "image_stego": {
                        "format": "png",
                        "lsb_candidates": [
                            {
                                "recipe": "b1,rgb,msb,xy",
                                "bit_plane": 1,
                                "channel_order": "rgb",
                                "bit_order": "msb",
                                "coordinate_order": "xy",
                                "decoders": ["html_unescape"],
                                "text_preview": "flag{png_lsb}",
                                "flag_like_strings": ["flag{png_lsb}"],
                            }
                        ],
                    },
                },
                confidence=0.78,
                hypothesis="Image stego evidence contains a flag-like token.",
                next_action="Send image-derived flag candidates to Verifier and preserve the image evidence path.",
            )
        ]
        challenge = Challenge(
            challenge_id="png-lsb-writeup",
            category=ChallengeCategory.MISC,
            attachment_paths=("/tmp/lsb.png",),
        )

        report = ReportBuilder().build("png-lsb-writeup", ("flag{png_lsb}",), findings, [], challenge=challenge)

        sections = {section["title"]: section for section in report["writeup"]["sections"]}
        self.assertEqual(
            sections["复现步骤"]["steps"],
            [
                "执行 `file lsb.png` 确认附件是 PNG 图片。",
                "按 recipe `b1,rgb,msb,xy` 提取最低位：逐像素按行读取 RGB 通道的第 1 个低位，并按 msb 字节顺序组装文本。",
                "对提取文本执行 html_unescape 解码，得到 flag{png_lsb}。",
                "提交 flag{png_lsb}，verifier 验证通过。",
            ],
        )
        self.assertIn("PNG LSB", sections["解题思路"]["body"])
        self.assertNotIn("关键证据", report["writeup"]["markdown"])

    def test_writeup_describes_bmp_quickstego_braille_reproduction_steps(self) -> None:
        findings = [
            Finding(
                challenge_id="bmp-braille-writeup",
                solver="ForensicsSolver",
                finding="Triaged forensic attachment",
                evidence={
                    "artifact": {"name": "coolguy.bmp", "path": "/tmp/coolguy.bmp"},
                    "flag_candidates": ["csictf{ucbr4ill3}"],
                    "image_stego": {
                        "format": "bmp",
                        "lsb_candidates": [
                            {
                                "recipe": "b1,row,lsb,file",
                                "bit_plane": 1,
                                "channel_order": "row",
                                "bit_order": "lsb",
                                "coordinate_order": "file",
                                "text_preview": "2471491ED07C69930E8F994E383E415F",
                            }
                        ],
                    },
                    "decoded_image_text_candidates": [
                        {
                            "value": "csictf{ucbr4ill3}",
                            "recipe": ["hex_braille_ascii_normalize"],
                            "source": "2471491ED07C69930E8F994E383E415F",
                        }
                    ],
                },
                confidence=0.78,
                hypothesis="Image stego evidence contains a flag-like token.",
                next_action="Send image-derived flag candidates to Verifier and preserve the image evidence path.",
            )
        ]
        challenge = Challenge(
            challenge_id="bmp-braille-writeup",
            category=ChallengeCategory.FORENSICS,
            attachment_paths=("/tmp/coolguy.bmp",),
        )

        report = ReportBuilder().build("bmp-braille-writeup", ("csictf{ucbr4ill3}",), findings, [], challenge=challenge)

        sections = {section["title"]: section for section in report["writeup"]["sections"]}
        self.assertEqual(
            sections["复现步骤"]["steps"],
            [
                "执行 `file coolguy.bmp` 确认附件是 BMP 图片。",
                "按 recipe `b1,row,lsb,file` 提取 BMP 像素/行数据最低位，得到 QuickStego 风格文本 `2471491ED07C69930E8F994E383E415F`。",
                "将该 hex 转为不补前导零的二进制，按 6-bit Braille ASCII 分组，并规范化数字/括号标记。",
                "得到 csictf{ucbr4ill3}，提交该 flag。",
            ],
        )
        self.assertIn("BMP/QuickStego", sections["解题思路"]["body"])
        self.assertIn("Braille", report["writeup"]["markdown"])

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

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
        self.assertEqual(writeup["title"], "Base32 warmup")
        self.assertEqual(writeup["final_flags"], ["flag{writeup_style}"])
        self.assertIn("题目信息", [section["title"] for section in writeup["sections"]])
        self.assertIn("解题思路", [section["title"] for section in writeup["sections"]])
        self.assertIn("关键证据", [section["title"] for section in writeup["sections"]])
        self.assertIn("复现步骤", [section["title"] for section in writeup["sections"]])
        self.assertIn("# Base32 warmup", writeup["markdown"])
        self.assertIn("flag{writeup_style}", writeup["markdown"])

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
        self.assertIn("最短发现路径", [section["title"] for section in report["writeup"]["sections"]])

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
        tool_section = next(section for section in report["writeup"]["sections"] if section["title"] == "工具与观察")
        tool_items = [(item["label"], item["value"]) for item in tool_section["items"]]
        self.assertEqual(
            tool_items.count(("CryptoSolver", "Recovered Python random XOR flag candidates")),
            1,
        )


if __name__ == "__main__":
    unittest.main()

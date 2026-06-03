from __future__ import annotations

import json
import subprocess
import sys
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path


class WebPlayerBenchmarkScriptTest(unittest.TestCase):
    def test_list_mode_describes_browser_player_cases_and_scoring(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-web-player-benchmark"

        completed = subprocess.run([sys.executable, str(script), "--list"], capture_output=True, check=False, text=True)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["agent"], "browser_player")
        self.assertIn("human_ui_flow", payload["scores"])
        self.assertIn("writeup_reproducible", payload["scores"])
        self.assertIn("agent_route_correct", payload["scores"])
        cases = payload["cases"]
        self.assertGreaterEqual(len(cases), 7)
        self.assertTrue(all(case["via"] == "web_ui" for case in cases))
        self.assertTrue(all(case["expected_agents"] for case in cases))
        categories = {case["category"] for case in cases}
        self.assertTrue({"web", "crypto", "forensics", "traffic", "reverse", "pwn", "misc"}.issubset(categories))
        self.assertTrue(any(case["llm_enabled"] is False for case in cases))

    def test_playwright_json_is_formatted_as_readable_scorecard(self) -> None:
        module = _load_script_module()
        report = {
            "stats": {"duration": 1234},
            "suites": [
                {
                    "specs": [
                        {"title": "player-web-visible", "ok": True},
                        {"title": "player-crypto-base32", "ok": True},
                        {"title": "player-traffic-http", "ok": False},
                    ],
                    "suites": [],
                }
            ],
        }

        benchmark_cases = [
            {
                "challenge_id": "player-web-visible",
                "category": "web",
                "expected_agents": ["ChallengeTriageAgent", "WebExploitAgent", "EvidenceJudgeAgent"],
            },
            {
                "challenge_id": "player-crypto-base32",
                "category": "crypto",
                "expected_agents": ["ChallengeTriageAgent", "CryptoMathAgent", "EvidenceJudgeAgent"],
            },
            {
                "challenge_id": "player-traffic-http",
                "category": "traffic",
                "expected_agents": ["ChallengeTriageAgent", "TrafficAgent", "ForensicsAgent", "EvidenceJudgeAgent"],
            },
        ]

        summary = module.summarize_playwright_report(report, benchmark_cases)
        rendered = module.format_playwright_summary(summary)

        self.assertEqual(summary["passed"], 2)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["categories"]["web"]["passed"], 1)
        self.assertEqual(summary["categories"]["traffic"]["passed"], 0)
        self.assertIn("ForgeFlag browser player benchmark: 2/3 passed", rendered)
        self.assertIn("Category results:", rendered)
        self.assertIn("web: 1/1", rendered)
        self.assertIn("traffic: 0/1", rendered)
        self.assertIn("PASS [web] player-web-visible", rendered)
        self.assertIn("agents=ChallengeTriageAgent,WebExploitAgent,EvidenceJudgeAgent", rendered)
        self.assertIn("FAIL [traffic] player-traffic-http", rendered)


def _load_script_module():
    script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-web-player-benchmark"
    loader = SourceFileLoader("forgeflag_web_player_benchmark", str(script))
    spec = spec_from_loader(loader.name, loader)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load forgeflag-web-player-benchmark")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    unittest.main()

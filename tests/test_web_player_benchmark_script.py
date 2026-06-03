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
                "run_profile": "llm",
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
        self.assertEqual(summary["profiles"]["deterministic"]["passed"], 1)
        self.assertEqual(summary["profiles"]["llm"]["passed"], 1)
        self.assertEqual(summary["categories"]["web"]["passed"], 1)
        self.assertEqual(summary["categories"]["traffic"]["passed"], 0)
        self.assertEqual(summary["agents"]["ChallengeTriageAgent"]["passed"], 2)
        self.assertEqual(summary["agents"]["EvidenceJudgeAgent"]["total"], 3)
        self.assertEqual(summary["agents"]["TrafficAgent"]["passed"], 0)
        self.assertIn("ForgeFlag browser player benchmark: 2/3 passed", rendered)
        self.assertIn("Profile results:", rendered)
        self.assertIn("deterministic: 1/2", rendered)
        self.assertIn("llm: 1/1", rendered)
        self.assertIn("Category results:", rendered)
        self.assertIn("web: 1/1", rendered)
        self.assertIn("traffic: 0/1", rendered)
        self.assertIn("Agent results:", rendered)
        self.assertIn("TrafficAgent: 0/1", rendered)
        self.assertIn("EvidenceJudgeAgent: 2/3", rendered)
        self.assertIn("PASS [web/deterministic] player-web-visible", rendered)
        self.assertIn("agents=ChallengeTriageAgent,WebExploitAgent,EvidenceJudgeAgent", rendered)
        self.assertIn("FAIL [traffic/deterministic] player-traffic-http", rendered)

    def test_run_mode_can_create_llm_and_comparison_variants(self) -> None:
        module = _load_script_module()
        llm_settings = module.llm_settings_from_env(
            {
                "FORGEFLAG_LLM_PROVIDER": "zhipu",
                "FORGEFLAG_LLM_MODEL": "glm-5.1",
                "ZAI_API_KEY": "sensitive-token",
                "FORGEFLAG_LLM_BASE_URL": "https://open.bigmodel.cn/api/paas/v4",
            }
        )
        base_cases = [
            {
                "challenge_id": "player-web-visible",
                "category": "web",
                "title": "Browser Player Web visible flag",
                "expected_flag": "flag{player_web_visible}",
                "llm_enabled": False,
                "expected_agents": ["ChallengeTriageAgent", "WebExploitAgent", "EvidenceJudgeAgent"],
                "attachments": [],
                "via": "web_ui",
            }
        ]

        deterministic = module.apply_run_mode(base_cases, llm=False, both=False, llm_settings=llm_settings)
        llm_only = module.apply_run_mode(base_cases, llm=True, both=False, llm_settings=llm_settings)
        comparison = module.apply_run_mode(base_cases, llm=False, both=True, llm_settings=llm_settings)

        self.assertEqual(deterministic[0]["challenge_id"], "player-web-visible")
        self.assertEqual(deterministic[0]["run_profile"], "deterministic")
        self.assertFalse(deterministic[0]["llm_enabled"])
        self.assertEqual(llm_only[0]["challenge_id"], "player-web-visible-llm")
        self.assertEqual(llm_only[0]["run_profile"], "llm")
        self.assertTrue(llm_only[0]["llm_enabled"])
        self.assertTrue(llm_only[0]["llm_configured"])
        self.assertEqual(llm_only[0]["llm_settings"]["api_key"], "sensitive-token")
        self.assertEqual([case["run_profile"] for case in comparison], ["deterministic", "llm"])
        self.assertEqual([case["challenge_id"] for case in comparison], ["player-web-visible", "player-web-visible-llm"])
        listed = module._case_listing(llm_only[0])
        self.assertTrue(listed["llm_configured"])
        self.assertNotIn("api_key", listed)
        self.assertNotIn("sensitive-token", json.dumps(listed))


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

from __future__ import annotations

import json
import subprocess
import sys
import unittest
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
        self.assertGreaterEqual(len(cases), 3)
        self.assertTrue(all(case["via"] == "web_ui" for case in cases))
        self.assertTrue(all(case["expected_agents"] for case in cases))
        self.assertTrue(any(case["category"] == "web" for case in cases))
        self.assertTrue(any(case["category"] == "crypto" for case in cases))
        self.assertTrue(any(case["llm_enabled"] is False for case in cases))


if __name__ == "__main__":
    unittest.main()

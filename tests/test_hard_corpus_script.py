from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


class HardCorpusScriptTest(unittest.TestCase):
    def test_list_mode_reports_hard_cases_sources_and_scoring(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-hard-corpus"

        completed = subprocess.run([str(script), "--list"], capture_output=True, check=False, text=True)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        cases = payload["cases"]
        self.assertGreaterEqual(len(cases), 8)
        self.assertTrue(all(case["difficulty"] in {"hard", "expert"} for case in cases))
        self.assertGreaterEqual(len({case["source_url"] for case in cases}), 4)
        self.assertIn("crypto", {case["category"] for case in cases})
        self.assertIn("web", {case["category"] for case in cases})
        self.assertIn("pwn", {case["category"] for case in cases})
        self.assertIn("hard-traffic-http-stream-follow", {case["challenge_id"] for case in cases})
        self.assertIn("hard-traffic-http-object-export", {case["challenge_id"] for case in cases})
        self.assertIn("hard-traffic-smtp-stream-summary", {case["challenge_id"] for case in cases})
        self.assertIn("hard-web-source-routes", {case["challenge_id"] for case in cases})
        ret2win_cases = [case for case in cases if case["challenge_id"] == "hard-pwn-ret2win-source"]
        self.assertEqual(len(ret2win_cases), 1)
        self.assertIn("cyclic", ret2win_cases[0]["required_evidence"])
        source_route_cases = [case for case in cases if case["challenge_id"] == "hard-web-source-routes"]
        self.assertEqual(len(source_route_cases), 1)
        self.assertIn("JWT/session", source_route_cases[0]["required_evidence"])
        self.assertTrue(all(case["required_evidence"] for case in cases))
        self.assertTrue(any(case["expected_flag"] is None for case in cases))


if __name__ == "__main__":
    unittest.main()

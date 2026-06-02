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
        self.assertTrue(all(case["required_evidence"] for case in cases))
        self.assertTrue(any(case["expected_flag"] is None for case in cases))


if __name__ == "__main__":
    unittest.main()

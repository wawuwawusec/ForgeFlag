from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


class MediumCorpusScriptTest(unittest.TestCase):
    def test_list_mode_reports_medium_cases_and_sources(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-medium-corpus"

        completed = subprocess.run([sys.executable, str(script), "--list"], capture_output=True, check=False, text=True)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertGreaterEqual(len(payload["cases"]), 6)
        self.assertTrue(all(case["difficulty"] == "medium" for case in payload["cases"]))
        self.assertIn("crypto", {case["category"] for case in payload["cases"]})
        self.assertIn("traffic", {case["category"] for case in payload["cases"]})
        self.assertTrue(all(case["source_url"] for case in payload["cases"]))


if __name__ == "__main__":
    unittest.main()

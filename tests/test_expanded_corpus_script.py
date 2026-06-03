from __future__ import annotations

from collections import Counter
import json
import subprocess
import unittest
from pathlib import Path


class ExpandedCorpusScriptTest(unittest.TestCase):
    def test_list_mode_reports_at_least_ten_cases_per_main_category(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-expanded-corpus"

        completed = subprocess.run([str(script), "--list"], capture_output=True, check=False, text=True)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        cases = payload["cases"]
        counts = Counter(case["category"] for case in cases)
        for category in ("web", "crypto", "forensics", "traffic", "reverse", "pwn", "misc"):
            self.assertGreaterEqual(counts[category], 10, category)
        challenge_ids = {case["challenge_id"] for case in cases}
        self.assertIn("expanded-web-header-cookie", challenge_ids)
        self.assertIn("expanded-crypto-crypto_single_xor", challenge_ids)
        self.assertIn("expanded-crypto-crypto_repeating_xor", challenge_ids)
        self.assertIn("expanded-crypto-crypto_vigenere", challenge_ids)
        self.assertGreaterEqual(len({case["source_url"] for case in cases}), 8)
        self.assertTrue(all(case["required_evidence"] for case in cases))
        self.assertTrue(any(case["expected_flag"] for case in cases))
        self.assertTrue(any(case["expected_flag"] is None for case in cases))


if __name__ == "__main__":
    unittest.main()

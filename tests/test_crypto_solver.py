from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook


class CryptoSolverTest(unittest.TestCase):
    def test_crypto_solver_decodes_flag_from_description(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-transform",
                    category=ChallengeCategory.CRYPTO,
                    description="ciphertext: 666c61677b6379626572636865667d",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-transform")
            finding = next(f for f in notebook.findings_for("crypto-transform") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{cyberchef}"])
        self.assertEqual(finding.finding, "Decoded crypto transform candidates")
        self.assertIn("hex_decode", finding.evidence["transform_candidates"][0]["recipe"])


if __name__ == "__main__":
    unittest.main()

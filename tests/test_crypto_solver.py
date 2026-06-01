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

    def test_crypto_solver_records_rsa_parameter_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-rsa",
                    category=ChallengeCategory.CRYPTO,
                    description="RSA task:\nn = 3233\ne = 3\nc = 2790\n",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-rsa")
            finding = next(f for f in notebook.findings_for("crypto-rsa") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Analyzed RSA challenge parameters")
        self.assertEqual(finding.evidence["rsa"]["parameters"]["e"], "3")
        self.assertIn("RsaCtfTool", finding.evidence["rsa"]["recommended_tools"])

    def test_crypto_solver_records_hash_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-hash",
                    category=ChallengeCategory.CRYPTO,
                    description="crack this: 5d41402abc4b2a76b9719d911017c592",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-hash")
            finding = next(f for f in notebook.findings_for("crypto-hash") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Analyzed hash candidates")
        self.assertEqual(finding.evidence["hashes"]["candidates"][0]["type"], "md5_or_ntlm")
        self.assertIn("hashcat", finding.evidence["hashes"]["recommended_tools"])


if __name__ == "__main__":
    unittest.main()

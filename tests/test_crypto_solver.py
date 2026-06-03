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

    def test_crypto_solver_recovers_rsa_flag_from_known_factors(self) -> None:
        p = 2**127 - 1
        q = 2**89 - 1
        n = p * q
        e = 65537
        message = int.from_bytes(b"flag{rsa_known_factors}", "big")
        c = pow(message, e, n)
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-rsa-known-factors",
                    category=ChallengeCategory.CRYPTO,
                    description=f"n = {n}\ne = {e}\nc = {c}\np = {p}\nq = {q}\n",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-rsa-known-factors")
            finding = next(f for f in notebook.findings_for("crypto-rsa-known-factors") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{rsa_known_factors}"])
        self.assertEqual(finding.finding, "Recovered RSA flag candidates")
        self.assertEqual(finding.evidence["rsa_recovery"]["method"], "known_factors")

    def test_crypto_solver_recovers_python_random_xor_flag_from_attachment(self) -> None:
        script = """
import random
from Crypto.Util.number import *

# flag{
flag = b'xxx'
m = bytes_to_long(flag)
seed = random.randint(1,2**12)
random.seed(seed)
key = random.getrandbits(150)
enc = key ^ m
print(enc)
# 1027275529278332342097876075445098700759415489
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "easy_seed.py"
            attachment.write_text(script, encoding="utf-8")
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-random-xor",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-random-xor")
            finding = next(f for f in notebook.findings_for("crypto-random-xor") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{just_a_seed}"])
        self.assertEqual(finding.finding, "Recovered Python random XOR flag candidates")
        self.assertEqual(finding.evidence["python_random_xor"]["seed"], 3277)

    def test_crypto_solver_recovers_common_xor_and_vigenere_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plaintext = b"flag{solver_single_xor}"
            single_byte_ct = bytes(byte ^ 0x42 for byte in plaintext).hex()
            repeating_plaintext = b"flag{solver_repeating_xor}"
            repeating_key = b"ice"
            repeating_ct = bytes(
                byte ^ repeating_key[index % len(repeating_key)]
                for index, byte in enumerate(repeating_plaintext)
            ).hex()
            attachment = root / "xor-vigenere.txt"
            attachment.write_text(
                f"single byte xor ciphertext = {single_byte_ct}\n"
                f"key = ice\nct = {repeating_ct}\n"
                "vigenere key = lemon\nvigenere ciphertext = qpmu{itkqbrci}\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-xor-vigenere",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-xor-vigenere")
            finding = next(f for f in notebook.findings_for("crypto-xor-vigenere") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertIn("flag{solver_single_xor}", summary["accepted_flags"])
        self.assertIn("flag{solver_repeating_xor}", summary["accepted_flags"])
        self.assertIn("flag{vigenere}", summary["accepted_flags"])
        self.assertEqual(finding.finding, "Recovered classical crypto flag candidates")
        self.assertIn("single_byte_xor", finding.evidence)
        self.assertIn("repeating_key_xor", finding.evidence)
        self.assertIn("vigenere", finding.evidence)

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

    def test_crypto_solver_identifies_aes_ctr_nonce_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "ctr.py"
            attachment.write_text(
                "cipher = AES.new(key, AES.MODE_CTR, nonce=b'fixed')\n"
                "Two ciphertexts reuse the same nonce, so recover the keystream with XOR cribbing.\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-ctr-reuse",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-ctr-reuse")
            finding = next(f for f in notebook.findings_for("crypto-ctr-reuse") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Identified crypto primitive misuse pattern")
        self.assertEqual(finding.evidence["pattern"], "aes_ctr_nonce_reuse")
        self.assertIn("nonce", finding.next_action.lower())
        self.assertIn("keystream", finding.next_action.lower())

    def test_crypto_solver_identifies_poly1305_one_time_key_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-poly1305-reuse",
                    category=ChallengeCategory.CRYPTO,
                    description="Poly1305 one-time MAC key was reused; solve algebra equations over message/tag pairs.",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-poly1305-reuse")
            finding = next(f for f in notebook.findings_for("crypto-poly1305-reuse") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.evidence["pattern"], "poly1305_one_time_key_reuse")
        self.assertIn("algebra", finding.next_action.lower())


if __name__ == "__main__":
    unittest.main()

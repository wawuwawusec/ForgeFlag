from __future__ import annotations

import unittest

from forgeflag.crypto_analysis import recover_rsa_flags_from_text, rsa_summary_from_text


class CryptoAnalysisTest(unittest.TestCase):
    def test_rsa_summary_extracts_common_parameters_and_hints(self) -> None:
        summary = rsa_summary_from_text("n = 3233\ne = 3\nc = 2790\n")

        self.assertEqual(summary["parameters"]["n"], "3233")
        self.assertEqual(summary["parameters"]["e"], "3")
        self.assertEqual(summary["parameters"]["c"], "2790")
        self.assertIn("low_exponent", summary["hints"])
        self.assertIn("RsaCtfTool", summary["recommended_tools"])

    def test_rsa_summary_detects_pem_public_key(self) -> None:
        summary = rsa_summary_from_text("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----")

        self.assertTrue(summary["has_public_key"])
        self.assertIn("RsaCtfTool", summary["recommended_tools"])

    def test_recover_rsa_flags_from_known_factors(self) -> None:
        message = int.from_bytes(b"flag{rsa_known_factors}", "big")
        p = 2**127 - 1
        q = 2**89 - 1
        n = p * q
        e = 65537
        c = pow(message, e, n)

        result = recover_rsa_flags_from_text(f"n = {n}\ne = {e}\nc = {c}\np = {p}\nq = {q}\n")

        self.assertEqual(result["flags"], ["flag{rsa_known_factors}"])
        self.assertEqual(result["method"], "known_factors")


if __name__ == "__main__":
    unittest.main()

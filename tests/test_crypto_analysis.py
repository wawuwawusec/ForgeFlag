from __future__ import annotations

import unittest

from forgeflag.crypto_analysis import (
    recover_python_random_xor_flags_from_text,
    recover_repeating_key_xor_flags_from_text,
    recover_rsa_flags_from_text,
    recover_single_byte_xor_flags_from_text,
    recover_vigenere_flags_from_text,
    rsa_summary_from_text,
)


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
        self.assertEqual(result["parameters"]["n"], str(n))
        self.assertEqual(result["parameters"]["e"], str(e))
        self.assertEqual(result["parameters"]["c"], str(c))
        self.assertEqual(result["parameters"]["p"], str(p))
        self.assertEqual(result["parameters"]["q"], str(q))

    def test_recover_rsa_flags_from_low_exponent_plaintext_root(self) -> None:
        message = int.from_bytes(b"flag{rsa_low_exponent}", "big")
        e = 3
        n = 2**521 - 1
        c = message**e

        result = recover_rsa_flags_from_text(f"n = {n}\ne = {e}\nc = {c}\n")

        self.assertEqual(result["flags"], ["flag{rsa_low_exponent}"])
        self.assertEqual(result["method"], "low_exponent_root")
        self.assertEqual(result["parameters"]["n"], str(n))
        self.assertEqual(result["parameters"]["e"], str(e))
        self.assertEqual(result["parameters"]["c"], str(c))

    def test_recover_rsa_flags_from_common_modulus_pair(self) -> None:
        message = int.from_bytes(b"flag{rsa_common_modulus}", "big")
        n = 2**521 - 1
        e1 = 17
        e2 = 65537
        c1 = pow(message, e1, n)
        c2 = pow(message, e2, n)

        result = recover_rsa_flags_from_text(f"n = {n}\ne1 = {e1}\ne2 = {e2}\nc1 = {c1}\nc2 = {c2}\n")

        self.assertEqual(result["flags"], ["flag{rsa_common_modulus}"])
        self.assertEqual(result["method"], "common_modulus")
        self.assertEqual(result["parameters"]["e1"], str(e1))
        self.assertEqual(result["parameters"]["e2"], str(e2))
        self.assertEqual(result["parameters"]["c1"], str(c1))
        self.assertEqual(result["parameters"]["c2"], str(c2))

    def test_recover_rsa_flags_from_shared_prime_moduli(self) -> None:
        p = 2**127 - 1
        q1 = 2**89 - 1
        q2 = 2**107 - 1
        n1 = p * q1
        n2 = p * q2
        e = 65537
        message = int.from_bytes(b"flag{rsa_shared_prime}", "big")
        c1 = pow(message, e, n1)

        result = recover_rsa_flags_from_text(f"n1 = {n1}\nn2 = {n2}\ne = {e}\nc1 = {c1}\n")

        self.assertEqual(result["flags"], ["flag{rsa_shared_prime}"])
        self.assertEqual(result["method"], "shared_prime")
        self.assertEqual(result["parameters"]["n1"], str(n1))
        self.assertEqual(result["parameters"]["n2"], str(n2))
        self.assertEqual(result["parameters"]["c1"], str(c1))
        self.assertEqual(result["parameters"]["p"], str(p))

    def test_recover_python_random_xor_flags_from_small_seed_script(self) -> None:
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

        result = recover_python_random_xor_flags_from_text(script)

        self.assertEqual(result["flags"], ["flag{just_a_seed}"])
        self.assertEqual(result["seed"], 3277)
        self.assertEqual(result["key_bits"], 150)

    def test_recover_single_byte_xor_flag_from_hex_ciphertext(self) -> None:
        plaintext = b"flag{single_byte_xor}"
        ciphertext = bytes(byte ^ 0x37 for byte in plaintext).hex()

        result = recover_single_byte_xor_flags_from_text(f"single byte xor ciphertext = {ciphertext}\n")

        self.assertEqual(result["flags"], ["flag{single_byte_xor}"])
        self.assertEqual(result["key"], "0x37")
        self.assertEqual(result["method"], "single_byte_xor")

    def test_recover_repeating_key_xor_flag_when_key_is_given(self) -> None:
        plaintext = b"flag{repeating_xor}"
        key = b"ice"
        ciphertext = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(plaintext)).hex()

        result = recover_repeating_key_xor_flags_from_text(f"key = ice\nct = {ciphertext}\n")

        self.assertEqual(result["flags"], ["flag{repeating_xor}"])
        self.assertEqual(result["key"], "ice")
        self.assertEqual(result["method"], "repeating_key_xor")

    def test_recover_vigenere_flag_when_key_is_given(self) -> None:
        result = recover_vigenere_flags_from_text("key = lemon\nciphertext = qpmu{itkqbrci}\n")

        self.assertEqual(result["flags"], ["flag{vigenere}"])
        self.assertEqual(result["key"], "lemon")
        self.assertEqual(result["method"], "vigenere")


if __name__ == "__main__":
    unittest.main()

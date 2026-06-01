from __future__ import annotations

import unittest

from forgeflag.hash_analysis import hash_summary_from_text


class HashAnalysisTest(unittest.TestCase):
    def test_hash_summary_fingerprints_common_hashes(self) -> None:
        summary = hash_summary_from_text(
            "md5: 5d41402abc4b2a76b9719d911017c592\n"
            "sha1: 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n"
            "sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n"
        )

        labels = {candidate["type"] for candidate in summary["candidates"]}

        self.assertIn("md5_or_ntlm", labels)
        self.assertIn("sha1", labels)
        self.assertIn("sha256", labels)
        self.assertIn("hashcat", summary["recommended_tools"])
        self.assertIn("john", summary["recommended_tools"])

    def test_hash_summary_detects_bcrypt_and_unix_sha512_crypt(self) -> None:
        summary = hash_summary_from_text(
            "$2y$10$abcdefghijklmnopqrstuu5s8QSDwX9fu7wV2PRldcn6R8T4cXr5K\n"
            "$6$saltstring$abcdefghijklmnopqrstuvabcdefghijklmnopqrstuvabcdefghijklmnopqrstuvabcdefghijklmnop\n"
        )

        labels = {candidate["type"] for candidate in summary["candidates"]}

        self.assertIn("bcrypt", labels)
        self.assertIn("sha512crypt", labels)
        self.assertIn(3200, summary["hashcat_modes"])
        self.assertIn(1800, summary["hashcat_modes"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

from forgeflag.flags import extract_flags


class FlagExtractionTest(unittest.TestCase):
    def test_extract_flags_preserves_platform_prefixes(self) -> None:
        text = (
            "warmup solved: picoCTF{prefix_should_survive} and HTB{box_flag} "
            "and SVIBRG{cat_found} and grey{welcome_flag} and PCL{bitlocker_timeline}"
        )

        self.assertEqual(
            extract_flags(text),
            (
                "picoCTF{prefix_should_survive}",
                "HTB{box_flag}",
                "SVIBRG{cat_found}",
                "grey{welcome_flag}",
                "PCL{bitlocker_timeline}",
            ),
        )

    def test_extract_flags_allows_official_sentence_flags(self) -> None:
        text = "decoded transmission: DUCTF{##TH3 QU0KK4'S AR3 H3LD 1N F4C1LITY #11911!}"

        self.assertEqual(
            extract_flags(text),
            ("DUCTF{##TH3 QU0KK4'S AR3 H3LD 1N F4C1LITY #11911!}",),
        )

    def test_extract_flags_finds_generic_flag_after_ctf_response_delimiter(self) -> None:
        text = "X@Yflag{This_is_a_f10g}\n[S]\n/var/www/html\n[E]\nX@Y"

        self.assertEqual(extract_flags(text), ("flag{This_is_a_f10g}",))


if __name__ == "__main__":
    unittest.main()

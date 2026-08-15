from __future__ import annotations

import unittest

from unittest import mock

from forgeflag.flags import extract_flags, extract_flags_generic


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


class GenericFlagExtractionTest(unittest.TestCase):
    def test_generic_extractor_captures_unknown_competition_prefix(self) -> None:
        text = "All checks passed\nSEKAI{p1ckleeeeeeeee_3a01fea10fb01a88c1cd554e7372f21ced43b497}\n"
        self.assertIn("SEKAI{p1ckleeeeeeeee_3a01fea10fb01a88c1cd554e7372f21ced43b497}", extract_flags_generic(text))

    def test_conservative_extractor_skips_unknown_prefix(self) -> None:
        text = "quux{never_seen_before}"
        self.assertEqual(extract_flags(text), ())
        self.assertEqual(extract_flags_generic(text), ("quux{never_seen_before}",))

    def test_generic_extractor_skips_code_like_braces(self) -> None:
        text = "body { color: #fff; } function(){ return 1; }"
        self.assertEqual(extract_flags_generic(text), ())

    def test_generic_extractor_skips_mangled_flag_prefix(self) -> None:
        text = "X@Yflag{webshell_response}"
        self.assertEqual(extract_flags_generic(text), ("flag{webshell_response}",))

    def test_generic_extractor_honors_env_prefixes(self) -> None:
        import os

        with mock.patch.dict(os.environ, {"FORGEFLAG_FLAG_PREFIXES": "style"}):
            self.assertIn("style{custom_prefix}", extract_flags_generic("style{custom_prefix}"))

from __future__ import annotations

import unittest

from forgeflag.flags import extract_flags


class FlagExtractionTest(unittest.TestCase):
    def test_extract_flags_preserves_platform_prefixes(self) -> None:
        text = "warmup solved: picoCTF{prefix_should_survive} and HTB{box_flag}"

        self.assertEqual(
            extract_flags(text),
            ("picoCTF{prefix_should_survive}", "HTB{box_flag}"),
        )


if __name__ == "__main__":
    unittest.main()

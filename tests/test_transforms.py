from __future__ import annotations

import unittest

from forgeflag.transforms import transform_candidates


class TransformTest(unittest.TestCase):
    def test_transform_candidates_decodes_hex_flag(self) -> None:
        candidates = transform_candidates("666c61677b6865785f666c61677d")

        self.assertIn("flag{hex_flag}", {candidate.value for candidate in candidates})

    def test_transform_candidates_chains_url_and_html_entities(self) -> None:
        encoded = (
            "%26%23102%3B%26%23108%3B%26%2397%3B%26%23103%3B%26%23123%3B"
            "%26%23117%3B%26%23114%3B%26%23108%3B%26%23125%3B"
        )

        candidates = transform_candidates(encoded)

        self.assertIn("flag{url}", {candidate.value for candidate in candidates})
        flag_candidate = next(candidate for candidate in candidates if candidate.value == "flag{url}")
        self.assertEqual(flag_candidate.recipe, ("url_decode", "html_unescape"))

    def test_transform_candidates_decodes_base32_flag(self) -> None:
        candidates = transform_candidates("MZWGCZ33MJQXGZJTGJPWM3DBM56Q")

        self.assertIn("flag{base32_flag}", {candidate.value for candidate in candidates})

    def test_transform_candidates_decodes_binary_ascii_flag(self) -> None:
        encoded = (
            "01100110 01101100 01100001 01100111 01111011 01100010 01101001 "
            "01101110 01100001 01110010 01111001 01011111 01100001 01110011 "
            "01100011 01101001 01101001 01111101"
        )

        candidates = transform_candidates(encoded)

        self.assertIn("flag{binary_ascii}", {candidate.value for candidate in candidates})

    def test_transform_candidates_decodes_rot13_flag(self) -> None:
        candidates = transform_candidates("synt{ebg13}")

        self.assertIn("flag{rot13}", {candidate.value for candidate in candidates})

    def test_transform_candidates_decodes_caesar_shift_flag(self) -> None:
        candidates = transform_candidates("mshn{jhlzhy}")

        self.assertIn("flag{caesar}", {candidate.value for candidate in candidates})
        flag_candidate = next(candidate for candidate in candidates if candidate.value == "flag{caesar}")
        self.assertIn("caesar_shift_", flag_candidate.recipe[0])

    def test_transform_candidates_decodes_morse_flag(self) -> None:
        candidates = transform_candidates("..-. .-.. .- --. / -... .-. .- -.-. . ...")

        self.assertIn("flag{braces}", {candidate.value for candidate in candidates})

    def test_transform_candidates_decodes_decimal_ascii_flag(self) -> None:
        candidates = transform_candidates("102 108 97 103 123 100 101 99 105 109 97 108 125")

        self.assertIn("flag{decimal}", {candidate.value for candidate in candidates})

    def test_transform_candidates_decodes_octal_ascii_flag(self) -> None:
        candidates = transform_candidates("146 154 141 147 173 157 143 164 141 154 175")

        self.assertIn("flag{octal}", {candidate.value for candidate in candidates})


if __name__ == "__main__":
    unittest.main()

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

    def test_transform_candidates_decodes_morse_after_filename_line(self) -> None:
        text = (
            "Expanded benchmark pattern distilled from public CTF writeups and practice notes: Crypto crypto_morse.txt.\n"
            "..-. .-.. .- --. / -.-. .-. -.-- .--. - --- / -- --- .-. ... ."
        )

        candidates = transform_candidates(text)

        self.assertIn("flag{crypto_morse}", {candidate.value for candidate in candidates})
        self.assertNotIn("eflag crypto morse", {candidate.value for candidate in candidates})

    def test_transform_candidates_decodes_decimal_ascii_flag(self) -> None:
        candidates = transform_candidates("102 108 97 103 123 100 101 99 105 109 97 108 125")

        self.assertIn("flag{decimal}", {candidate.value for candidate in candidates})

    def test_transform_candidates_decodes_octal_ascii_flag(self) -> None:
        candidates = transform_candidates("146 154 141 147 173 157 143 164 141 154 175")

        self.assertIn("flag{octal}", {candidate.value for candidate in candidates})

    def test_transform_candidates_decodes_quickstego_hex_braille_flag(self) -> None:
        candidates = transform_candidates("2471491ED07C69930E8F994E383E415F")

        self.assertIn("csictf{ucbr4ill3}", {candidate.value for candidate in candidates})

    def test_transform_candidates_decodes_ccir476_transmission(self) -> None:
        encoded = (
            "10110100110110110100111010011011010111010011010010110110101011010111001011010010111010011100110110010110110110"
            "10001111000111100110110101010110010111011010100101110111001000111101010101101101010110101110010110101101001011"
            "01101010110101101011001011010011101110001101100101110101101010110011011100001101101101101010101101101000111010"
            "11011001011101011010110010110011011110100010101110111000110110110100101011100101110111000101011100101110001101"
            "1"
        )

        candidates = transform_candidates(encoded)

        self.assertIn(
            "DUCTF{##TH3 QU0KK4'S AR3 H3LD 1N F4C1LITY #11911!}",
            {candidate.value for candidate in candidates},
        )


if __name__ == "__main__":
    unittest.main()

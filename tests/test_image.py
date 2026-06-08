from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeflag.image import analyze_image_stego_hints, analyze_magic_extension_mismatch
from tests.png_fixtures import png_with_extra_compressed_idat, png_with_rgb_lsb_payload, png_with_text_and_trailing_data


class ImageAnalysisTest(unittest.TestCase):
    def test_magic_extension_mismatch_detects_png_named_jpg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "out.jpg"
            image.write_bytes(png_with_text_and_trailing_data("flag{wrong_extension}"))

            summary = analyze_magic_extension_mismatch(image)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["declared_extension"], "jpg")
        self.assertEqual(summary["actual_format"], "png")
        self.assertEqual(summary["expected_extensions"], ["png"])
        self.assertIn("extension_mismatch", summary["hints"])

    def test_png_stego_hints_extract_text_chunks_and_trailing_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "hint.png"
            image.write_bytes(
                png_with_text_and_trailing_data(
                    "flag{png_text_chunk}",
                    trailing=b"\nsecret-after-iend",
                )
            )

            summary = analyze_image_stego_hints(image)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["format"], "png")
        self.assertIn("tEXt", [chunk["type"] for chunk in summary["chunks"]])
        self.assertEqual(summary["text_chunks"][0]["keyword"], "Comment")
        self.assertIn("flag{png_text_chunk}", summary["text_chunks"][0]["text_preview"])
        self.assertEqual(summary["trailing_data"]["length"], len(b"\nsecret-after-iend"))
        self.assertIn("secret-after-iend", summary["trailing_data"]["ascii_preview"])

    def test_jpeg_stego_hints_extract_comment_segments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "comment.jpg"
            comment = b"flag{jpeg_comment}"
            app1 = b"Exif\x00\x00x"
            image.write_bytes(
                b"\xff\xd8"
                + b"\xff\xfe" + (len(comment) + 2).to_bytes(2, "big") + comment
                + b"\xff\xe1" + (len(app1) + 2).to_bytes(2, "big") + app1
                + b"\xff\xd9"
            )

            summary = analyze_image_stego_hints(image)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["format"], "jpeg")
        self.assertIn("flag{jpeg_comment}", summary["comments"][0]["text_preview"])
        self.assertIn("APP1", summary["app_markers"])

    def test_jpeg_stego_hints_record_markers_and_trailing_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "tail.jpg"
            app0 = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            image.write_bytes(
                b"\xff\xd8"
                + b"\xff\xe0" + (len(app0) + 2).to_bytes(2, "big") + app0
                + b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00"
                + b"\x11\x22\x33"
                + b"\xff\xd9"
                + b"flag{after_eoi}"
            )

            summary = analyze_image_stego_hints(image)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["format"], "jpeg")
        self.assertIn("APP0", summary["app_markers"])
        self.assertEqual(summary["markers"][-1]["type"], "EOI")
        self.assertEqual(summary["trailing_data"]["length"], len(b"flag{after_eoi}"))
        self.assertIn("flag{after_eoi}", summary["trailing_data"]["ascii_preview"])

    def test_png_stego_hints_extract_independent_compressed_idat_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "extra-idat.png"
            image.write_bytes(png_with_extra_compressed_idat("flag{extra_idat_stream}"))

            summary = analyze_image_stego_hints(image)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["format"], "png")
        self.assertIn("idat_payloads", summary)
        self.assertIn("flag{extra_idat_stream}", summary["idat_payloads"][0]["text_preview"])

    def test_png_stego_hints_extract_truncated_extra_idat_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "truncated-extra-idat.png"
            image.write_bytes(png_with_extra_compressed_idat("flag{truncated_idat_stream}", truncated_length=True))

            summary = analyze_image_stego_hints(image)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertIn("idat_payloads", summary)
        self.assertIn("flag{truncated_idat_stream}", summary["idat_payloads"][0]["text_preview"])

    def test_png_stego_hints_extract_rgb_lsb_html_entity_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "lsb.png"
            image.write_bytes(png_with_rgb_lsb_payload("&#x66;&#x6c;&#x61;&#x67;&#x7b;png_lsb&#x7d;"))

            summary = analyze_image_stego_hints(image)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertIn("lsb_candidates", summary)
        candidate = summary["lsb_candidates"][0]
        self.assertEqual(candidate["recipe"], "b1,rgb,lsb,xy")
        self.assertIn("html_unescape", candidate["decoders"])
        self.assertIn("flag{png_lsb}", candidate["flag_like_strings"])


if __name__ == "__main__":
    unittest.main()

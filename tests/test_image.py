from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeflag.image import analyze_image_stego_hints
from tests.png_fixtures import png_with_text_and_trailing_data


class ImageAnalysisTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

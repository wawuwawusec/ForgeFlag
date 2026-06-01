from __future__ import annotations

import gzip
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from forgeflag.archive_analysis import analyze_archive


class ArchiveAnalysisTest(unittest.TestCase):
    def test_analyze_archive_summarizes_zip_entries_and_interesting_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "challenge.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("flag.txt", "redacted")
                zf.writestr("notes/readme.md", "hint")

            summary = analyze_archive(archive)

        self.assertEqual(summary["kind"], "zip")
        self.assertEqual(summary["entries"][0]["name"], "flag.txt")
        self.assertIn("flag.txt", summary["interesting_entries"])
        self.assertFalse(summary["encrypted"])

    def test_analyze_archive_summarizes_tar_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = root / "secret.txt"
            payload.write_text("hint", encoding="utf-8")
            archive = root / "challenge.tar"
            with tarfile.open(archive, "w") as tf:
                tf.add(payload, arcname="secret.txt")

            summary = analyze_archive(archive)

        self.assertEqual(summary["kind"], "tar")
        self.assertEqual(summary["entries"][0]["name"], "secret.txt")
        self.assertIn("secret.txt", summary["interesting_entries"])

    def test_analyze_archive_detects_gzip_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "payload.gz"
            with gzip.open(archive, "wb") as gz:
                gz.write(b"flag{inside_gzip}")

            summary = analyze_archive(archive)

        self.assertEqual(summary["kind"], "gzip")
        self.assertEqual(summary["entries"][0]["name"], "payload")


if __name__ == "__main__":
    unittest.main()

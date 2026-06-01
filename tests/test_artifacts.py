from __future__ import annotations

import tempfile
import unittest
import hashlib
from pathlib import Path

from forgeflag.artifacts import ArtifactWorkspace, summarize_artifact_paths
from forgeflag.domain import Challenge, ChallengeCategory
from forgeflag.notebook import SQLiteNotebook


class ArtifactWorkspaceTest(unittest.TestCase):
    def test_register_file_copies_attachment_under_challenge_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "incoming" / "flag note.txt"
            source.parent.mkdir(parents=True)
            source.write_text("flag{workspace_copy}\n", encoding="utf-8")

            artifact = ArtifactWorkspace(root / ".forgeflag" / "artifacts").register_file("forensics-01", source)

            self.assertEqual(artifact.challenge_id, "forensics-01")
            self.assertEqual(artifact.original_path, str(source.resolve()))
            self.assertEqual(artifact.workspace_path.parent, root / ".forgeflag" / "artifacts" / "forensics-01")
            self.assertTrue(artifact.workspace_path.is_file())
            self.assertEqual(artifact.workspace_path.read_text(encoding="utf-8"), "flag{workspace_copy}\n")

    def test_summarize_artifact_paths_reports_file_metadata_and_missing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            present = root / "present.bin"
            data = b"present artifact"
            present.write_bytes(data)
            missing = root / "missing.bin"

            summary = summarize_artifact_paths((str(present), str(missing)))

        self.assertEqual(summary[0]["name"], "present.bin")
        self.assertTrue(summary[0]["exists"])
        self.assertEqual(summary[0]["size_bytes"], len(data))
        self.assertEqual(summary[0]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(summary[1]["name"], "missing.bin")
        self.assertFalse(summary[1]["exists"])
        self.assertIsNone(summary[1]["sha256"])


class NotebookAttachmentTest(unittest.TestCase):
    def test_challenge_attachment_paths_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="forensics-02",
                    category=ChallengeCategory.FORENSICS,
                    attachment_paths=("/tmp/artifact-one.bin", "/tmp/artifact-two.bin"),
                )
            )

            loaded = notebook.get_challenge("forensics-02")

        self.assertEqual(loaded.attachment_paths, ("/tmp/artifact-one.bin", "/tmp/artifact-two.bin"))


if __name__ == "__main__":
    unittest.main()

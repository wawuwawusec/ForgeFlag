from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import ToolResult
from forgeflag.notebook import SQLiteNotebook
from forgeflag.tool_compression import compressed_tool_summary, with_compressed_summary


class ToolCompressionTest(unittest.TestCase):
    def test_compressed_tool_summary_extracts_flags_errors_and_interesting_lines(self) -> None:
        stdout = "\n".join(
            [
                "noise line",
                "GET /index HTTP/1.1",
                "Host: example.test",
                "flag{compressed_summary}",
                "another noise line",
            ]
        )
        result = ToolResult(
            tool="tshark",
            target="/tmp/capture.pcap",
            status="success",
            evidence=["returncode=0"],
            raw={"stdout": stdout, "stderr": "warning: truncated capture"},
        )

        summary = compressed_tool_summary(result)

        self.assertEqual(summary["tool"], "tshark")
        self.assertEqual(summary["status"], "success")
        self.assertEqual(summary["flags"], ["flag{compressed_summary}"])
        self.assertIn("warning: truncated capture", summary["errors"])
        self.assertIn("GET /index HTTP/1.1", summary["interesting_lines"])
        self.assertLessEqual(len(json.dumps(summary, ensure_ascii=False)), 4096)

    def test_notebook_add_tool_result_persists_compressed_summary_without_dropping_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "notebook.sqlite"
            notebook = SQLiteNotebook(db)
            notebook.add_tool_result(
                "tool-compress",
                ToolResult(
                    tool="strings",
                    target="/tmp/blob.bin",
                    status="success",
                    raw={"stdout": "hello\nflag{stored_summary}\n" + ("A" * 5000)},
                ),
            )
            conn = sqlite3.connect(db)
            try:
                row = conn.execute("select raw_json from tool_runs where challenge_id = ?", ("tool-compress",)).fetchone()
            finally:
                conn.close()

        raw = json.loads(row[0])
        self.assertIn("compressed_summary", raw)
        self.assertIn("flag{stored_summary}", raw["stdout"])
        self.assertEqual(raw["compressed_summary"]["flags"], ["flag{stored_summary}"])
        self.assertLess(len(json.dumps(raw["compressed_summary"])), len(raw["stdout"]))

    def test_notebook_add_tool_result_promotes_compressed_summary_to_observation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_tool_result(
                "tool-observation",
                ToolResult(
                    tool="ffuf",
                    target="http://127.0.0.1:8080/",
                    status="success",
                    raw={"stdout": '{"url":"http://127.0.0.1:8080/admin","status":200}'},
                ),
            )

            observations = notebook.observations_for("tool-observation")

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].source, "ffuf")
        self.assertEqual(observations[0].kind, "tool_summary")
        self.assertIn("ffuf success", observations[0].summary)
        self.assertEqual(observations[0].evidence["tool"], "ffuf")
        self.assertIn("admin", " ".join(observations[0].evidence["interesting_lines"]))

    def test_with_compressed_summary_preserves_existing_summary(self) -> None:
        result = ToolResult(
            tool="ffuf",
            target="http://127.0.0.1:8080/",
            status="success",
            raw={"stdout": "new data", "compressed_summary": {"tool": "ffuf", "flags": ["flag{old}"]}},
        )

        updated = with_compressed_summary(result)

        self.assertIs(updated, result)
        self.assertEqual(updated.raw["compressed_summary"]["flags"], ["flag{old}"])


if __name__ == "__main__":
    unittest.main()

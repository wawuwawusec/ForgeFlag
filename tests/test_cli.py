from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from forgeflag.cli import main
from forgeflag.domain import Challenge, ChallengeCategory, LLMConfig, RunConfig
from forgeflag.notebook import SQLiteNotebook


class CliTest(unittest.TestCase):
    def test_add_challenge_registers_attachment_in_artifact_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "downloaded" / "evidence.txt"
            source.parent.mkdir()
            source.write_text("flag{cli_artifact}\n", encoding="utf-8")
            db = root / ".forgeflag" / "notebook.sqlite"

            with redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        "--db",
                        str(db),
                        "add-challenge",
                        "forensics-cli",
                        "--category",
                        "forensics",
                        "--attachment",
                        str(source),
                    ]
                )
            challenge = SQLiteNotebook(db).get_challenge("forensics-cli")
            self.assertEqual(exit_code, 0)
            self.assertEqual(len(challenge.attachment_paths), 1)
            registered = Path(challenge.attachment_paths[0])
            self.assertTrue(registered.is_file())
            self.assertEqual(registered.parent, db.parent / "artifacts" / "forensics-cli")
            self.assertEqual(registered.read_text(encoding="utf-8"), "flag{cli_artifact}\n")

    def test_report_command_prints_latest_replay_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            notebook = SQLiteNotebook(db)
            notebook.add_challenge(Challenge(challenge_id="reported", category=ChallengeCategory.MISC))
            notebook.record_run(
                "reported",
                "flag_found",
                {
                    "challenge_id": "reported",
                    "status": "flag_found",
                    "replay_report": {"flags": [{"flag": "flag{reported}", "path": []}]},
                },
            )

            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(["--db", str(db), "report", "reported"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["flags"][0]["flag"], "flag{reported}")

    def test_run_command_passes_llm_options_to_manager_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            notebook = SQLiteNotebook(db)
            notebook.add_challenge(Challenge(challenge_id="llm-cli", category=ChallengeCategory.MISC))
            captured: dict[str, RunConfig] = {}

            class FakeManager:
                def __init__(self, notebook: SQLiteNotebook, config: RunConfig) -> None:
                    captured["config"] = config

                def run_challenge(self, challenge_id: str) -> dict[str, object]:
                    return {"challenge_id": challenge_id, "status": "completed"}

            output = io.StringIO()
            with (
                redirect_stdout(output),
                patch("forgeflag.cli.Manager", FakeManager),
                patch(
                    "forgeflag.cli.LLMConfig.from_env",
                    return_value=LLMConfig(provider="disabled"),
                ),
            ):
                exit_code = main(
                    [
                        "--db",
                        str(db),
                        "run",
                        "llm-cli",
                        "--llm-provider",
                        "openai",
                        "--llm-model",
                        "gpt-4.1",
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["config"].llm_config.provider, "openai")
        self.assertEqual(captured["config"].llm_config.model, "gpt-4.1")

    def test_run_command_accepts_zhipu_llm_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            notebook = SQLiteNotebook(db)
            notebook.add_challenge(Challenge(challenge_id="glm-cli", category=ChallengeCategory.MISC))
            captured: dict[str, RunConfig] = {}

            class FakeManager:
                def __init__(self, notebook: SQLiteNotebook, config: RunConfig) -> None:
                    captured["config"] = config

                def run_challenge(self, challenge_id: str) -> dict[str, object]:
                    return {"challenge_id": challenge_id, "status": "completed"}

            output = io.StringIO()
            with (
                redirect_stdout(output),
                patch("forgeflag.cli.Manager", FakeManager),
                patch("forgeflag.cli.LLMConfig.from_env", return_value=LLMConfig(provider="disabled")),
            ):
                exit_code = main(
                    [
                        "--db",
                        str(db),
                        "run",
                        "glm-cli",
                        "--llm-provider",
                        "zhipu",
                        "--llm-model",
                        "glm-4.7",
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["config"].llm_config.provider, "zhipu")
        self.assertEqual(captured["config"].llm_config.model, "glm-4.7")


if __name__ == "__main__":
    unittest.main()

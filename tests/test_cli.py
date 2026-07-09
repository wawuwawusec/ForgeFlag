from __future__ import annotations

import io
import hashlib
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

    def test_artifacts_command_lists_registered_attachment_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "evidence.bin"
            data = b"artifact bytes"
            source.write_bytes(data)
            db = root / ".forgeflag" / "notebook.sqlite"
            with redirect_stdout(io.StringIO()):
                main(
                    [
                        "--db",
                        str(db),
                        "add-challenge",
                        "artifact-cli",
                        "--category",
                        "misc",
                        "--attachment",
                        str(source),
                    ]
                )

            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(["--db", str(db), "artifacts", "artifact-cli"])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["challenge_id"], "artifact-cli")
        self.assertEqual(payload["artifacts"][0]["name"], "evidence.bin")
        self.assertTrue(payload["artifacts"][0]["exists"])
        self.assertEqual(payload["artifacts"][0]["size_bytes"], len(data))
        self.assertEqual(payload["artifacts"][0]["sha256"], hashlib.sha256(data).hexdigest())

    def test_artifacts_command_reports_missing_registered_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            missing = root / "missing.bin"
            SQLiteNotebook(db).add_challenge(
                Challenge(
                    challenge_id="missing-artifact",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(missing),),
                )
            )

            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(["--db", str(db), "artifacts", "missing-artifact"])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertFalse(payload["artifacts"][0]["exists"])
        self.assertIsNone(payload["artifacts"][0]["size_bytes"])
        self.assertIsNone(payload["artifacts"][0]["sha256"])

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
                        "glm-5.1",
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["config"].llm_config.provider, "zhipu")
        self.assertEqual(captured["config"].llm_config.model, "glm-5.1")

    def test_catalog_command_lists_recommended_projects(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(["catalog", "--category", "traffic"])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload)
        self.assertTrue(all("traffic" in row["categories"] for row in payload))
        self.assertIn("Wireshark", {row["name"] for row in payload})

    def test_hints_command_lists_recommended_analysis_hints_by_category(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(["hints", "--category", "traffic"])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload)
        self.assertTrue(all(row["category"] == "traffic" for row in payload))
        self.assertIn("traffic-http-webshell-delimited-flag", {row["id"] for row in payload})
        self.assertIn("traffic-data-uri-image", {row["id"] for row in payload})
        self.assertIn("solver_supported", {row["status"] for row in payload})

        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(["hints", "--category", "crypto"])

        crypto_payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(all(row["category"] == "crypto" for row in crypto_payload))
        self.assertIn("crypto-python-random-prime-offset", {row["id"] for row in crypto_payload})

    def test_doctor_command_reports_health_without_leaking_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / ".forgeflag" / "notebook.sqlite"
            db.parent.mkdir(parents=True)
            latest = db.parent / "capability-benchmark-latest.json"
            latest.write_text(
                json.dumps(
                    {
                        "totals": {"cases": 1, "passed": 1, "failed": 0},
                        "readiness": {
                            "status": "ready",
                            "summary": "Release gate is green.",
                            "coverage": {"hard_evidence": True, "ui_flow": True, "heldout_manifest": True},
                        },
                    }
                ),
                encoding="utf-8",
            )
            wrappers = [{"name": "file", "available": True, "source": "host"}]
            profiles = [{"name": "forgeflag-sagemath", "available": True}]

            output = io.StringIO()
            with (
                redirect_stdout(output),
                patch("forgeflag.health.ToolRunner.inventory", return_value=wrappers),
                patch("forgeflag.health.docker_profile_inventory", return_value=profiles),
                patch(
                    "forgeflag.health.LLMConfig.from_env",
                    return_value=LLMConfig(provider="openai", model="gpt-4.1", api_key="sk-secret"),
                ),
            ):
                exit_code = main(["--db", str(db), "doctor"])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["core_readiness"]["status"], "ready")
        self.assertEqual(payload["diagnostic_bundle"]["llm"]["provider"], "openai")
        self.assertNotIn("sk-secret", output.getvalue())
        self.assertIn("notebook", {check["id"] for check in payload["checks"]})
        self.assertIn("tools", {check["id"] for check in payload["checks"]})

    def test_agents_command_lists_subagent_roster(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(["agents"])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["coordinator"]["id"], "forgeflag-manager")
        self.assertEqual(payload["coordinator"]["team_type"], "manager")
        self.assertIn("benchmark status", payload["coordinator"]["deliverables"])
        self.assertEqual(payload["subagent_work_policy"]["max_parallel"], 1)
        self.assertTrue(payload["subagent_work_policy"]["prefer_local_verification"])
        self.assertIn("ChallengeTriageAgent", {row["name"] for row in payload["agents"]})
        self.assertIn("BrowserPlayerQAAgent", {row["name"] for row in payload["agents"]})
        self.assertIn("EvidenceJudgeAgent", {row["name"] for row in payload["agents"]})
        browser_agent = next(row for row in payload["agents"] if row["name"] == "BrowserPlayerQAAgent")
        self.assertEqual(browser_agent["team_type"], "enabling")
        self.assertEqual(browser_agent["reports_to"], "forgeflag-manager")


if __name__ == "__main__":
    unittest.main()

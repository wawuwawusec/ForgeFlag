from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import LLMConfig
from forgeflag.health import system_health


class HealthTest(unittest.TestCase):
    def test_system_health_marks_missing_python_dependencies_as_core_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / ".forgeflag" / "notebook.sqlite"
            db.parent.mkdir(parents=True)
            (db.parent / "capability-benchmark-latest.json").write_text(
                '{"totals":{"cases":1,"passed":1,"failed":0},"readiness":{"status":"ready"}}',
                encoding="utf-8",
            )

            def fake_find_spec(name: str):
                return None if name == "z3" else object()

            with (
                patch("forgeflag.health.importlib.util.find_spec", side_effect=fake_find_spec),
                patch("forgeflag.health.ToolRunner.inventory", return_value=[{"name": "file", "available": True}]),
                patch("forgeflag.health.docker_profile_inventory", return_value=[]),
                patch("forgeflag.health.LLMConfig.from_env", return_value=LLMConfig(provider="disabled")),
            ):
                payload = system_health(db)

        dependency_check = next(check for check in payload["checks"] if check["id"] == "python_dependencies")
        self.assertEqual(dependency_check["status"], "error")
        self.assertIn("z3-solver", dependency_check["details"]["missing_packages"])
        self.assertEqual(payload["core_readiness"]["status"], "blocked")
        self.assertIn("python_dependencies", payload["core_readiness"]["blocking_checks"])

    def test_optional_missing_tool_wrappers_limit_commercial_readiness_not_core_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / ".forgeflag" / "notebook.sqlite"
            db.parent.mkdir(parents=True)
            (db.parent / "capability-benchmark-latest.json").write_text(
                '{"totals":{"cases":1,"passed":1,"failed":0},"readiness":{"status":"ready"}}',
                encoding="utf-8",
            )
            wrappers = [
                {"name": "file", "available": True, "source": "host"},
                {"name": "strings", "available": True, "source": "host"},
                {"name": "tshark", "available": True, "source": "host"},
                {"name": "ROPgadget", "available": False, "source": "missing"},
            ]

            with (
                patch("forgeflag.health.ToolRunner.inventory", return_value=wrappers),
                patch("forgeflag.health.docker_profile_inventory", return_value=[]),
                patch("forgeflag.health.LLMConfig.from_env", return_value=LLMConfig(provider="openai", model="gpt-4.1", api_key="sk-test")),
            ):
                payload = system_health(db)

        tool_check = next(check for check in payload["checks"] if check["id"] == "tools")
        self.assertEqual(tool_check["status"], "warning")
        self.assertEqual(tool_check["details"]["core_missing"], [])
        self.assertEqual(tool_check["details"]["optional_missing"], ["ROPgadget"])
        self.assertEqual(payload["core_readiness"]["status"], "ready")
        self.assertEqual(payload["commercial_readiness"]["status"], "limited")

    def test_missing_core_tool_wrapper_blocks_core_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / ".forgeflag" / "notebook.sqlite"
            db.parent.mkdir(parents=True)
            (db.parent / "capability-benchmark-latest.json").write_text(
                '{"totals":{"cases":1,"passed":1,"failed":0},"readiness":{"status":"ready"}}',
                encoding="utf-8",
            )
            wrappers = [
                {"name": "file", "available": False, "source": "missing"},
                {"name": "strings", "available": True, "source": "host"},
            ]

            with (
                patch("forgeflag.health.ToolRunner.inventory", return_value=wrappers),
                patch("forgeflag.health.docker_profile_inventory", return_value=[]),
                patch("forgeflag.health.LLMConfig.from_env", return_value=LLMConfig(provider="openai", model="gpt-4.1", api_key="sk-test")),
            ):
                payload = system_health(db)

        tool_check = next(check for check in payload["checks"] if check["id"] == "tools")
        self.assertEqual(tool_check["status"], "error")
        self.assertEqual(tool_check["details"]["core_missing"], ["file"])
        self.assertEqual(payload["core_readiness"]["status"], "blocked")
        self.assertIn("tools", payload["core_readiness"]["blocking_checks"])


if __name__ == "__main__":
    unittest.main()

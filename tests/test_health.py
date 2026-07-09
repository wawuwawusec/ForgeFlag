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


if __name__ == "__main__":
    unittest.main()

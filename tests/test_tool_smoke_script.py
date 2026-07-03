from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


class ToolSmokeScriptTest(unittest.TestCase):
    def test_list_mode_reports_wrappers_and_catalog(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-tool-smoke"

        completed = subprocess.run([str(script), "--list"], capture_output=True, check=False, text=True)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertIn("wrappers", payload)
        self.assertIn("catalog", payload)
        wrapper_names = {row["name"] for row in payload["wrappers"]}
        self.assertIn("stegseek", wrapper_names)
        self.assertIn("objdump", wrapper_names)
        self.assertIn("readelf", wrapper_names)
        self.assertIn("radare2", wrapper_names)
        self.assertIn("foremost", wrapper_names)
        self.assertIn("yara", wrapper_names)
        self.assertGreaterEqual(len(payload["wrappers"]), 18)
        self.assertGreaterEqual(payload["catalog"]["total"], 90)

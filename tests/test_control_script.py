from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ControlScriptTest(unittest.TestCase):
    def test_status_removes_invalid_web_pid_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_control_script(Path(tmp))
            state = root / ".forgeflag"
            state.mkdir()
            (state / "web.pid").write_text("pid=12345\n", encoding="utf-8")

            completed = subprocess.run(
                [str(root / "scripts" / "forgeflag-control"), "status"],
                cwd=root,
                env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("web=stopped", completed.stdout)
            self.assertFalse((state / "web.pid").exists())

    def test_stop_web_terminates_pid_without_screen_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_control_script(Path(tmp))
            state = root / ".forgeflag"
            state.mkdir()
            sleeper = subprocess.Popen(["/bin/sh", "-c", "sleep 30"])
            self.addCleanup(lambda: sleeper.poll() is None and sleeper.kill())
            (state / "web.pid").write_text(f"{sleeper.pid}\n", encoding="utf-8")

            completed = subprocess.run(
                [str(root / "scripts" / "forgeflag-control"), "stop"],
                cwd=root,
                env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                capture_output=True,
                text=True,
                check=False,
            )

            sleeper.poll()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Web UI stopped", completed.stdout)
            self.assertIsNotNone(sleeper.returncode)
            self.assertFalse((state / "web.pid").exists())


def _copy_control_script(tmp_root: Path) -> Path:
    scripts = tmp_root / "scripts"
    scripts.mkdir()
    shutil.copy2(ROOT / "scripts" / "forgeflag-control", scripts / "forgeflag-control")
    return tmp_root


if __name__ == "__main__":
    unittest.main()

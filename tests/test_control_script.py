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

    def test_gate_runs_full_capability_benchmark_without_start(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_control_script(Path(tmp))
            state = root / ".forgeflag"
            state.mkdir()
            benchmark = root / "scripts" / "forgeflag-capability-benchmark"
            benchmark.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$PWD/gate.args\"\n",
                encoding="utf-8",
            )
            benchmark.chmod(0o755)

            completed = subprocess.run(
                [
                    str(root / "scripts" / "forgeflag-control"),
                    "gate",
                    "--no-start",
                    "--url",
                    "http://127.0.0.1:9999",
                    "--timeout",
                    "9",
                ],
                cwd=root,
                env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("ForgeFlag release gate", completed.stdout)
            args = (root / "gate.args").read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                args,
                [
                    "--url",
                    "http://127.0.0.1:9999",
                    "--manifest",
                    str(state / "heldout-platform-manifest.json"),
                    "--timeout",
                    "9",
                    "--output",
                    str(state / "capability-benchmark-latest.json"),
                    "--history",
                    str(state / "capability-benchmark-history.jsonl"),
                ],
            )

    def test_gate_llm_requires_configured_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_control_script(Path(tmp))
            (root / ".forgeflag").mkdir()
            benchmark = root / "scripts" / "forgeflag-capability-benchmark"
            benchmark.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
            benchmark.chmod(0o755)
            env = {**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
            for name in (
                "FORGEFLAG_LLM_PROVIDER",
                "FORGEFLAG_LLM_MODEL",
                "FORGEFLAG_LLM_API_KEY",
                "OPENAI_API_KEY",
                "ZAI_API_KEY",
                "ZHIPU_API_KEY",
                "ZHIPUAI_API_KEY",
                "BIGMODEL_API_KEY",
            ):
                env.pop(name, None)

            completed = subprocess.run(
                [
                    str(root / "scripts" / "forgeflag-control"),
                    "gate",
                    "--no-start",
                    "--llm",
                ],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("LLM gate requested but runtime is not configured", completed.stderr)

    def test_gate_llm_appends_llm_flag_when_runtime_is_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_control_script(Path(tmp))
            (root / ".forgeflag").mkdir()
            benchmark = root / "scripts" / "forgeflag-capability-benchmark"
            benchmark.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$PWD/gate.args\"\n",
                encoding="utf-8",
            )
            benchmark.chmod(0o755)

            completed = subprocess.run(
                [
                    str(root / "scripts" / "forgeflag-control"),
                    "gate",
                    "--no-start",
                    "--llm",
                ],
                cwd=root,
                env={
                    **os.environ,
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "FORGEFLAG_LLM_PROVIDER": "zhipu",
                    "ZAI_API_KEY": "zai-test",
                },
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            args = (root / "gate.args").read_text(encoding="utf-8").splitlines()
            self.assertEqual(args[-1], "--llm")

    def test_doctor_runs_cli_health_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_control_script(Path(tmp))
            venv_bin = root / ".venv" / "bin"
            venv_bin.mkdir(parents=True)
            (root / ".venv" / ".forgeflag-installed").write_text("ok\n", encoding="utf-8")
            fake_python = venv_bin / "python"
            fake_python.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$PWD/doctor.args\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)

            completed = subprocess.run(
                [str(root / "scripts" / "forgeflag-control"), "doctor"],
                cwd=root,
                env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            args = (root / "doctor.args").read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                args,
                [
                    "-m",
                    "forgeflag.cli",
                    "--db",
                    str(root / ".forgeflag" / "notebook.sqlite"),
                    "doctor",
                    "--format",
                    "text",
                ],
            )

    def test_doctor_forwards_machine_readable_strict_gate_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_control_script(Path(tmp))
            venv_bin = root / ".venv" / "bin"
            venv_bin.mkdir(parents=True)
            (root / ".venv" / ".forgeflag-installed").write_text("ok\n", encoding="utf-8")
            fake_python = venv_bin / "python"
            fake_python.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$PWD/doctor.args\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)

            completed = subprocess.run(
                [
                    str(root / "scripts" / "forgeflag-control"),
                    "doctor",
                    "--format",
                    "json",
                    "--strict",
                    "commercial",
                ],
                cwd=root,
                env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            args = (root / "doctor.args").read_text(encoding="utf-8").splitlines()
            self.assertEqual(args[-5:], ["doctor", "--format", "json", "--strict", "commercial"])

    def test_doctor_strict_gate_keeps_default_text_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _copy_control_script(Path(tmp))
            venv_bin = root / ".venv" / "bin"
            venv_bin.mkdir(parents=True)
            (root / ".venv" / ".forgeflag-installed").write_text("ok\n", encoding="utf-8")
            fake_python = venv_bin / "python"
            fake_python.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$PWD/doctor.args\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)

            completed = subprocess.run(
                [str(root / "scripts" / "forgeflag-control"), "doctor", "--strict"],
                cwd=root,
                env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            args = (root / "doctor.args").read_text(encoding="utf-8").splitlines()
            self.assertEqual(args[-4:], ["doctor", "--format", "text", "--strict"])


def _copy_control_script(tmp_root: Path) -> Path:
    scripts = tmp_root / "scripts"
    scripts.mkdir()
    shutil.copy2(ROOT / "scripts" / "forgeflag-control", scripts / "forgeflag-control")
    return tmp_root


if __name__ == "__main__":
    unittest.main()

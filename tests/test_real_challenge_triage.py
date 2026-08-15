import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook


def _manager_with_attachment(challenge_id: str, category: ChallengeCategory, attachment: Path) -> tuple[Manager, SQLiteNotebook]:
    notebook = SQLiteNotebook(Path(tempfile.mkdtemp()) / "nb.sqlite")
    notebook.add_challenge(
        Challenge(
            challenge_id=challenge_id,
            category=category,
            attachment_paths=(str(attachment.resolve()),),
        )
    )
    return Manager(notebook, config=RunConfig()), notebook


def _write_zip(path: Path) -> None:
    import zipfile

    source = (
        "from pickle import _Unpickler as py_unpickler\n"
        "class SafePyUnpickler(py_unpickler):\n"
        "    def find_class(self, module_name, global_name):\n"
        "        exit(1)\n"
        "inp = input('Pickle bytes: ')\n"
    )
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("src/chall.py", source)
        zf.writestr("ctf.xinetd", "service chall { server = /chall }\n")
        zf.writestr("docker-compose.yml", "services: { chall: {} }\n")


class ArchiveSourceTriageTest(unittest.TestCase):
    def test_misc_solver_reports_pickle_and_service_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "chall.zip"
            _write_zip(archive)
            manager, notebook = _manager_with_attachment("misc-pickle", ChallengeCategory.MISC, archive)
            summary = manager.run_challenge("misc-pickle")

            self.assertEqual(summary["status"], "completed")
            evidence = [
                finding.evidence
                for finding in notebook.findings_for("misc-pickle")
                if finding.solver == "MiscSolver"
            ]
            self.assertTrue(evidence)
            markers = evidence[0].get("source_markers")
            self.assertIn("pickle_module", markers)
            self.assertIn("restricted_unpickler", markers)
            self.assertIn("xinetd_service", markers)


class LuaArtifactTriageTest(unittest.TestCase):
    def test_reverse_solver_recognizes_lua_source_vm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "chal.lua"
            artifact.write_text(
                'local bit = require("bit")\n'
                'local ffi = require("ffi")\n'
                "local function check(x) return bit.bxor(x, 1) end\n",
                encoding="utf-8",
            )
            manager, notebook = _manager_with_attachment("rev-lua", ChallengeCategory.REVERSE, artifact)
            summary = manager.run_challenge("rev-lua")

            self.assertEqual(summary["status"], "completed")
            lua_findings = [
                finding
                for finding in notebook.findings_for("rev-lua")
                if finding.evidence.get("artifact_type") == "lua_source_vm"
            ]
            self.assertTrue(lua_findings)
            self.assertIn("z3 constraint solve", lua_findings[0].evidence["strategy"])

    def test_reverse_solver_recognizes_luajit_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "dump.lua"
            artifact.write_bytes(b"\x1bLJ\x02" + b"\x00" * 16)
            manager, notebook = _manager_with_attachment("rev-luajit", ChallengeCategory.REVERSE, artifact)
            manager.run_challenge("rev-luajit")

            bytecode_findings = [
                finding
                for finding in notebook.findings_for("rev-luajit")
                if finding.evidence.get("artifact_type") == "luajit_bytecode"
            ]
            self.assertTrue(bytecode_findings)
            self.assertEqual(bytecode_findings[0].evidence["luajit_version"], "0x02")


if __name__ == "__main__":
    unittest.main()

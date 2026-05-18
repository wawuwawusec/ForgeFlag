from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, IDAMCPConfig, RunConfig
from forgeflag.ida import IDAAnalysis, IDAToolCall, build_ida_adapter
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.safety import ScopePolicy
from forgeflag.solvers.pwn import PwnSolver
from forgeflag.solvers.reverse import ReverseSolver
from forgeflag.solvers.base import SolverContext


class IDAMCPConfigTest(unittest.TestCase):
    def test_ida_mcp_config_reads_safe_defaults_from_environment(self) -> None:
        config = IDAMCPConfig.from_env(
            {
                "FORGEFLAG_IDA_MCP_ENABLED": "true",
                "FORGEFLAG_IDA_MCP_COMMAND": "ida-mcp --toolsets=core,functions --read-only",
                "FORGEFLAG_IDA_MCP_TIMEOUT_SECONDS": "17",
            }
        )

        self.assertTrue(config.enabled)
        self.assertEqual(config.command, ("ida-mcp", "--toolsets=core,functions", "--read-only"))
        self.assertEqual(config.timeout_seconds, 17)
        self.assertTrue(config.read_only)

    def test_ida_adapter_is_disabled_by_default(self) -> None:
        adapter = build_ida_adapter(IDAMCPConfig.from_env({}))

        self.assertFalse(adapter.enabled)


class FakeIDAAdapter:
    enabled = True

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def analyze_binary(self, path: str, mode: str) -> IDAAnalysis:
        self.calls.append((path, mode))
        return IDAAnalysis(
            status="success",
            tool_calls=(
                IDAToolCall(
                    name="open_idb",
                    status="success",
                    evidence={"path": path},
                ),
                IDAToolCall(
                    name="list_functions",
                    status="success",
                    evidence={"functions": ["main", "check_flag"]},
                ),
            ),
            function_names=("main", "check_flag"),
            strings=("flag{ida_mcp_candidate}",),
        )


class IDASolverIntegrationTest(unittest.TestCase):
    def test_reverse_solver_uses_ida_adapter_for_registered_binary(self) -> None:
        adapter = FakeIDAAdapter()
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "rev.bin"
            binary.write_bytes(b"fake")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="rev-ida",
                category=ChallengeCategory.REVERSE,
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            result = ReverseSolver(ida_adapter=adapter).solve(
                SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy())
            )
            finding = notebook.findings_for("rev-ida")[0]

        self.assertEqual(result.status, "flag_candidate")
        self.assertEqual(result.flag_candidates, ("flag{ida_mcp_candidate}",))
        self.assertEqual(adapter.calls, [(str(binary.resolve()), "reverse")])
        self.assertEqual(finding.finding, "Analyzed binary with IDA MCP")
        self.assertEqual(finding.evidence["ida_mcp"]["function_names"], ["main", "check_flag"])

    def test_pwn_solver_uses_ida_adapter_for_registered_binary(self) -> None:
        adapter = FakeIDAAdapter()
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "pwn"
            binary.write_bytes(b"fake")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="pwn-ida",
                category=ChallengeCategory.PWN,
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            PwnSolver(ida_adapter=adapter).solve(
                SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy())
            )
            finding = notebook.findings_for("pwn-ida")[0]

        self.assertEqual(adapter.calls, [(str(binary.resolve()), "pwn")])
        self.assertEqual(finding.finding, "Analyzed pwn binary with IDA MCP")
        self.assertIn("check_flag", finding.evidence["ida_mcp"]["function_names"])

    def test_manager_passes_enabled_ida_adapter_to_reverse_and_pwn_solvers(self) -> None:
        class RecordingIDAAdapter(FakeIDAAdapter):
            pass

        adapter = RecordingIDAAdapter()
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "rev.bin"
            binary.write_bytes(b"fake")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="manager-rev",
                    category=ChallengeCategory.REVERSE,
                    attachment_paths=(str(binary),),
                )
            )

            summary = Manager(notebook, RunConfig(), ida_adapter=adapter).run_challenge("manager-rev")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(adapter.calls, [(str(binary.resolve()), "reverse")])


if __name__ == "__main__":
    unittest.main()

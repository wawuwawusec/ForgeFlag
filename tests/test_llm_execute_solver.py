import tempfile
import unittest
from pathlib import Path
from unittest import mock

from forgeflag.domain import Challenge, ChallengeCategory, LLMConfig, RunConfig
from forgeflag.llm import LLMResponse
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers import LLMExecuteSolver
from forgeflag.solvers.llm import LLMProvider


class FakeExecuteProvider:
    name = "zhipu"
    model = "glm-test"
    enabled = True

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[str] = []

    def generate(self, instructions: str, prompt: str) -> LLMResponse:
        self.calls.append(prompt)
        content = self.responses.pop(0) if self.responses else ""
        return LLMResponse(content=content, raw={}, usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})


def _context_with_attachment(challenge_id: str = "exec-01", content: bytes = b"CTF{hidden_in_file}"):
    import importlib

    from forgeflag.solvers.base import SolverContext

    tmp = tempfile.mkdtemp()
    artifact = Path(tmp) / "handout.txt"
    artifact.write_bytes(content)
    notebook = SQLiteNotebook(Path(tmp) / "nb.sqlite")
    challenge = Challenge(
        challenge_id=challenge_id,
        category=ChallengeCategory.MISC,
        attachment_paths=(str(artifact),),
    )
    notebook.add_challenge(challenge)
    return SolverContext(challenge=challenge, notebook=notebook, scope=None, observations=()), notebook, artifact


class LLMExecuteSolverTest(unittest.TestCase):
    def test_disabled_provider_short_circuits(self) -> None:
        class Disabled:
            name, model, enabled = "zhipu", None, False

            def generate(self, instructions, prompt):
                raise AssertionError("should not be called")

        context, _, _ = _context_with_attachment()
        result = LLMExecuteSolver(Disabled()).solve(context)
        self.assertEqual(result.status, "disabled")

    def test_successful_script_returns_flag_candidates(self) -> None:
        provider = FakeExecuteProvider(
            ["```python\nprint(open('handout.txt').read())\n```"]
        )
        sandbox_output = mock.Mock(returncode=0)
        sandbox_output.stdout = b"CTF{hidden_in_file}\n"
        sandbox_output.stderr = b""
        context, notebook, _ = _context_with_attachment()
        with mock.patch("shutil.which", return_value="/usr/bin/docker"), \
             mock.patch("subprocess.run", return_value=sandbox_output):
            result = LLMExecuteSolver(provider).solve(context)
        self.assertEqual(result.status, "flag_candidate")
        self.assertIn("CTF{hidden_in_file}", result.flag_candidates)
        findings = [f for f in notebook.findings_for("exec-01") if f.solver == "LLMExecuteSolver"]
        self.assertTrue(findings)
        self.assertIn("handout.txt", findings[0].evidence["script"])

    def test_revision_loop_recovers_from_failure(self) -> None:
        provider = FakeExecuteProvider(
            [
                "```python\nopen('nonexistent')\n```",
                "```python\nprint(open('handout.txt').read())\n```",
            ]
        )
        failed = mock.Mock(returncode=1)
        failed.stdout = b""
        failed.stderr = b"FileNotFoundError: nonexistent"
        ok = mock.Mock(returncode=0)
        ok.stdout = b"CTF{hidden_in_file}\n"
        ok.stderr = b""
        context, _, _ = _context_with_attachment()
        with mock.patch("shutil.which", return_value="/usr/bin/docker"), \
             mock.patch("subprocess.run", side_effect=[failed, ok]):
            result = LLMExecuteSolver(provider).solve(context)
        self.assertEqual(result.status, "flag_candidate")
        self.assertIn("previous attempt", provider.calls[1])

    def test_network_imports_are_rejected(self) -> None:
        self.assertEqual(_extract_script_guard("```python\nimport socket\n```"), "")

    def test_no_docker_degrades_gracefully(self) -> None:
        provider = FakeExecuteProvider(["```python\nprint('x')\n```"])
        context, _, _ = _context_with_attachment()
        with mock.patch("shutil.which", return_value=None):
            result = LLMExecuteSolver(provider).solve(context)
        self.assertEqual(result.status, "sandbox_unavailable")


def _extract_script_guard(content: str) -> str:
    from forgeflag.solvers.llm_execute import _extract_code

    return _extract_code(content)


class ManagerIntegrationTest(unittest.TestCase):
    def test_manager_includes_execute_solver_and_token_ledger(self) -> None:
        provider = FakeExecuteProvider(["```python\nprint('no flag')\n```"])
        sandbox_ok = mock.Mock(returncode=0)
        sandbox_ok.stdout = b"no flag\n"
        sandbox_ok.stderr = b""
        tmp = tempfile.mkdtemp()
        artifact = Path(tmp) / "handout.txt"
        artifact.write_bytes(b"data")
        notebook = SQLiteNotebook(Path(tmp) / "nb.sqlite")
        notebook.add_challenge(
            Challenge(
                challenge_id="mgr-exec",
                category=ChallengeCategory.MISC,
                attachment_paths=(str(artifact),),
            )
        )
        manager = Manager(notebook, solvers=[LLMExecuteSolver(provider)])
        with mock.patch("shutil.which", return_value="/usr/bin/docker"), \
             mock.patch("subprocess.run", return_value=sandbox_ok):
            summary = manager.run_challenge("mgr-exec")
        self.assertIn("LLMExecuteSolver", [s["solver"] for s in summary["solvers"]])
        self.assertGreater(summary["token_usage"]["total_tokens"], 0)


if __name__ == "__main__":
    unittest.main()


class ProviderOutageTest(unittest.TestCase):
    def test_provider_exception_degrades_cleanly(self) -> None:
        class ExplodingProvider:
            name, model, enabled = "zhipu", "glm-x", True

            def generate(self, instructions, prompt):
                raise RuntimeError("LLM HTTP 429 rate limit")

        context, notebook, _ = _context_with_attachment(challenge_id="exec-outage")
        result = LLMExecuteSolver(ExplodingProvider()).solve(context)
        self.assertEqual(result.status, "provider_unavailable")
        findings = [f for f in notebook.findings_for("exec-outage") if f.solver == "LLMExecuteSolver"]
        self.assertTrue(findings)
        self.assertIn("429", findings[0].evidence["error"])

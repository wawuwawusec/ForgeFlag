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

    def test_verification_round_collects_alternative_candidates(self) -> None:
        provider = FakeExecuteProvider([
            "```python\nprint('DUCTF{n3ar_miss}')\n```",
            "```python\nprint('DUCTF{recovered_correctly}')\n```",
        ])
        first = mock.Mock(returncode=0)
        first.stdout = b"DUCTF{n3ar_miss}\n"
        first.stderr = b""
        second = mock.Mock(returncode=0)
        second.stdout = b"DUCTF{recovered_correctly}\n"
        second.stderr = b""
        context, _, _ = _context_with_attachment()
        outputs = [first, second]
        with mock.patch("shutil.which", return_value="/usr/bin/docker"), \
             mock.patch("subprocess.run", side_effect=lambda *a, **k: outputs.pop(0)):
            result = LLMExecuteSolver(provider).solve(context)
        self.assertEqual(result.status, "flag_candidate")
        self.assertIn("DUCTF{n3ar_miss}", result.flag_candidates)
        self.assertIn("DUCTF{recovered_correctly}", result.flag_candidates)

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


class ServiceNetworkPolicyTest(unittest.TestCase):
    def test_network_scripts_allowed_for_service_challenges(self) -> None:
        from forgeflag.solvers.llm_execute import _extract_code

        script = "```python\nimport socket\ns = socket.create_connection(('127.0.0.1', 1337))\nprint(s.recv(4096))\n```"
        self.assertIn("socket.create_connection", _extract_code(script, allow_network=True))
        self.assertEqual("", _extract_code(script, allow_network=False))

    def test_instructions_match_network_policy(self) -> None:
        from forgeflag.solvers.llm_execute import _instructions

        service = _instructions(allow_localhost=True)
        offline = _instructions(allow_localhost=False)
        self.assertIn("IS reachable", service)
        self.assertIn("CHALLENGE_TARGET", service)
        self.assertNotIn("do not import sockets", service)
        self.assertIn("do not import sockets", offline)
        self.assertNotIn("IS reachable", offline)

    def test_service_challenge_prompt_passes_network_scripts(self) -> None:
        provider = FakeExecuteProvider([
            "```python\nfrom pwn import remote\nimport socket\nr = remote('127.0.0.1', 1337)\nprint(r.recvline())\n```",
        ])
        import importlib

        from forgeflag.solvers.base import SolverContext

        tmp = tempfile.mkdtemp()
        artifact = Path(tmp) / "handout"
        artifact.write_bytes(b"data")
        notebook = SQLiteNotebook(Path(tmp) / "nb.sqlite")
        challenge = Challenge(
            challenge_id="svc-01",
            category=ChallengeCategory.PWN,
            title="svc",
            description="nc service",
            attachment_paths=[str(artifact)],
            target="nc://127.0.0.1:1337",
        )
        notebook.add_challenge(challenge)
        context = SolverContext(challenge=challenge, notebook=notebook, scope=None)
        captured: dict[str, str] = {}

        def fake_run(attachments, script, session=None, allow_localhost=False, target=""):
            captured["allow_localhost"] = allow_localhost
            captured["script"] = script
            return {"status": "ok", "returncode": 0, "stdout": "DUCTF{real_service_flag_body}\n", "stderr": ""}

        with mock.patch("forgeflag.solvers.llm_execute._run_in_sandbox", side_effect=fake_run):
            result = LLMExecuteSolver(provider).solve(context)
        self.assertEqual(result.status, "flag_candidate")
        self.assertTrue(captured["allow_localhost"])
        self.assertIn("remote", captured["script"])


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

import tempfile
import unittest
from pathlib import Path

from forgeflag.auto import AutoClientConfig, AutoSolveClient
from forgeflag.domain import Challenge, ChallengeCategory
from forgeflag.llm import LLMResponse, TokenLedger, TrackingLLMProvider, extract_usage
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers import LLMSolver


def _notebook_with_challenge(challenge_id: str = "crypto-01") -> SQLiteNotebook:
    notebook = SQLiteNotebook(Path(tempfile.mkdtemp()) / "nb.sqlite")
    notebook.add_challenge(
        Challenge(challenge_id=challenge_id, category=ChallengeCategory.CRYPTO)
    )
    return notebook


class UsageExtractionTest(unittest.TestCase):
    def test_openai_responses_usage_shape(self) -> None:
        self.assertEqual(
            extract_usage({"usage": {"input_tokens": 120, "output_tokens": 80, "total_tokens": 200}}),
            {"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200},
        )

    def test_chat_completions_usage_shape(self) -> None:
        self.assertEqual(
            extract_usage({"usage": {"prompt_tokens": 30, "completion_tokens": 12, "total_tokens": 42}}),
            {"prompt_tokens": 30, "completion_tokens": 12, "total_tokens": 42},
        )

    def test_missing_total_is_derived(self) -> None:
        self.assertEqual(
            extract_usage({"usage": {"prompt_tokens": 7, "completion_tokens": 5}})["total_tokens"],
            12,
        )

    def test_absent_usage_is_empty(self) -> None:
        self.assertEqual(extract_usage({}), {})
        self.assertEqual(extract_usage({"usage": None}), {})


class TrackingProviderTest(unittest.TestCase):
    def test_tracking_provider_records_into_ledger(self) -> None:
        class FakeProvider:
            name = "zhipu"
            model = "glm-4"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content="ok",
                    raw={},
                    usage={"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
                )

        ledger = TokenLedger()
        provider = TrackingLLMProvider(FakeProvider(), ledger, source="solver")
        ledger.begin("crypto-01")
        provider.generate("instr", "prompt")
        provider.generate("instr", "prompt")

        summary = ledger.summary_for("crypto-01")
        self.assertEqual(summary["calls"], 2)
        self.assertEqual(summary["prompt_tokens"], 20)
        self.assertEqual(summary["completion_tokens"], 8)
        self.assertEqual(summary["total_tokens"], 28)
        self.assertEqual(summary["by_source"]["solver"]["calls"], 2)

    def test_untracked_challenge_reports_zero(self) -> None:
        self.assertEqual(TokenLedger().summary_for("nope")["total_tokens"], 0)


class ManagerTokenUsageTest(unittest.TestCase):
    def test_run_summary_includes_llm_token_usage(self) -> None:
        notebook = _notebook_with_challenge()

        class FakeProvider:
            name = "zhipu"
            model = "glm-4"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content='{"summary":"Try xor."}',
                    raw={},
                    usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
                )

        manager = Manager(notebook, solvers=[LLMSolver(FakeProvider())])
        summary = manager.run_challenge("crypto-01")

        usage = summary["token_usage"]
        self.assertGreaterEqual(usage["calls"], 1)
        self.assertEqual(usage["prompt_tokens"], 100 * usage["calls"])
        self.assertEqual(usage["total_tokens"], 150 * usage["calls"])
        self.assertIn("solver", usage["by_source"])
        observations = [o for o in notebook.observations_for("crypto-01") if o.kind == "token_usage"]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].evidence["total_tokens"], usage["total_tokens"])

    def test_no_llm_calls_omit_token_usage(self) -> None:
        from forgeflag.solvers import ReconSolver

        notebook = _notebook_with_challenge("web-01")
        notebook.add_challenge(Challenge(challenge_id="web-01", category=ChallengeCategory.WEB))
        manager = Manager(notebook, solvers=[ReconSolver()])
        summary = manager.run_challenge("web-01")
        self.assertNotIn("token_usage", summary)


class AutoClientTokenUsageTest(unittest.TestCase):
    def test_run_all_aggregates_tokens_across_challenges(self) -> None:
        notebook = _notebook_with_challenge("crypto-01")
        notebook.add_challenge(Challenge(challenge_id="crypto-02", category=ChallengeCategory.CRYPTO))

        class FakeManager:
            def __init__(self, nb, config):
                self.notebook = nb

            def run_challenge(self, challenge_id):
                usage = {
                    "calls": 1,
                    "prompt_tokens": 60,
                    "completion_tokens": 40,
                    "total_tokens": 100,
                }
                self.notebook.record_run(challenge_id, "flag_found", {"status": "flag_found"})
                return {
                    "challenge_id": challenge_id,
                    "status": "flag_found",
                    "accepted_flags": ["flag{x}"],
                    "token_usage": usage,
                }

        client = AutoSolveClient(
            notebook,
            config=AutoClientConfig(max_rounds=2, attempts_per_challenge=1),
            manager_factory=lambda nb, cfg: FakeManager(nb, cfg),
        )
        summary = client.run()

        self.assertEqual(summary["token_usage"]["challenges_tracked"], 2)
        self.assertEqual(summary["token_usage"]["calls"], 2)
        self.assertEqual(summary["token_usage"]["prompt_tokens"], 120)
        self.assertEqual(summary["token_usage"]["total_tokens"], 200)
        self.assertEqual(summary["progress"]["crypto-01"]["token_usage"]["total_tokens"], 100)


if __name__ == "__main__":
    unittest.main()

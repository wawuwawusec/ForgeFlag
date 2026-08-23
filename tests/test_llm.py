from __future__ import annotations

import json
import os
import tempfile
import unittest
from email.message import Message
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from forgeflag.domain import DEFAULT_ZHIPU_MODEL, Challenge, ChallengeCategory, Finding, LLMConfig, RunConfig
from forgeflag.llm import AnthropicMessagesProvider, LLMResponse, OpenAIResponsesProvider, ZhipuChatCompletionsProvider
from forgeflag.llm_prompts import category_playbook, prior_failure_patterns
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers.llm import LLMSolver
from forgeflag.solvers.base import SolverContext


def _http_error(status: int, payload: dict[str, object], headers: dict[str, str] | None = None) -> HTTPError:
    message = Message()
    for key, value in (headers or {}).items():
        message[key] = value
    body = BytesIO(json.dumps(payload).encode("utf-8"))
    return HTTPError("https://open.bigmodel.cn/api/paas/v4/chat/completions", status, "error", message, body)


class LLMConfigTest(unittest.TestCase):
    def test_llm_config_reads_openai_environment(self) -> None:
        config = LLMConfig.from_env(
            {
                "FORGEFLAG_LLM_PROVIDER": "openai",
                "FORGEFLAG_LLM_MODEL": "gpt-4.1",
                "OPENAI_API_KEY": "sk-test",
            }
        )

        self.assertEqual(config.provider, "openai")
        self.assertEqual(config.model, "gpt-4.1")
        self.assertEqual(config.api_key, "sk-test")
        self.assertTrue(config.enabled)

    def test_llm_config_reads_zhipu_environment(self) -> None:
        config = LLMConfig.from_env(
            {
                "FORGEFLAG_LLM_PROVIDER": "zhipu",
                "FORGEFLAG_LLM_MODEL": "glm-5.1",
                "ZAI_API_KEY": "zhipu-test",
            }
        )

        self.assertEqual(config.provider, "zhipu")
        self.assertEqual(config.model, "glm-5.1")
        self.assertEqual(config.api_key, "zhipu-test")
        self.assertEqual(config.base_url, "https://open.bigmodel.cn/api/paas/v4")
        self.assertTrue(config.enabled)

    def test_llm_config_defaults_zhipu_to_latest_model(self) -> None:
        config = LLMConfig.from_env(
            {
                "FORGEFLAG_LLM_PROVIDER": "zhipu",
                "ZAI_API_KEY": "zhipu-test",
            }
        )

        self.assertEqual(config.model, DEFAULT_ZHIPU_MODEL)
        self.assertTrue(config.enabled)

    def test_llm_config_defaults_to_disabled_without_provider(self) -> None:
        config = LLMConfig.from_env({})

        self.assertEqual(config.provider, "disabled")
        self.assertFalse(config.enabled)

    def test_llm_config_reads_rate_limit_controls_from_env(self) -> None:
        config = LLMConfig.from_env(
            {
                "FORGEFLAG_LLM_PROVIDER": "zhipu",
                "FORGEFLAG_LLM_MODEL": "glm-5.1",
                "FORGEFLAG_LLM_MAX_RETRIES": "4",
                "FORGEFLAG_LLM_RETRY_INITIAL_SECONDS": "3",
                "FORGEFLAG_LLM_RETRY_MAX_SECONDS": "30",
                "FORGEFLAG_LLM_COOLDOWN_SECONDS": "240",
            }
        )

        self.assertEqual(config.max_retries, 4)
        self.assertEqual(config.retry_initial_seconds, 3)
        self.assertEqual(config.retry_max_seconds, 30)
        self.assertEqual(config.cooldown_seconds, 240)


class OpenAIResponsesProviderTest(unittest.TestCase):
    def test_generate_posts_to_responses_api_and_extracts_output_text(self) -> None:
        response_payload = {
            "output": [
                {
                    "content": [
                        {"type": "output_text", "text": "Try route discovery, then inspect /admin."},
                    ]
                }
            ]
        }
        fake_response = Mock()
        fake_response.__enter__ = Mock(return_value=fake_response)
        fake_response.__exit__ = Mock(return_value=None)
        fake_response.read.return_value = json.dumps(response_payload).encode("utf-8")

        with patch("forgeflag.llm.request.urlopen", return_value=fake_response) as urlopen:
            provider = OpenAIResponsesProvider(
                LLMConfig(provider="openai", model="gpt-4.1", api_key="sk-test", timeout_seconds=12)
            )
            result = provider.generate("You are ForgeFlag.", "Solve this scoped CTF challenge.")

        self.assertEqual(result.content, "Try route discovery, then inspect /admin.")
        request_obj = urlopen.call_args.args[0]
        self.assertEqual(request_obj.full_url, "https://api.openai.com/v1/responses")
        self.assertEqual(request_obj.headers["Authorization"], "Bearer sk-test")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 12)
        body = json.loads(request_obj.data.decode("utf-8"))
        self.assertEqual(body["model"], "gpt-4.1")
        self.assertIn("Solve this scoped CTF challenge.", body["input"])


class ZhipuChatCompletionsProviderTest(unittest.TestCase):
    def test_generate_posts_to_zhipu_chat_completions_and_extracts_message(self) -> None:
        response_payload = {"choices": [{"message": {"content": "先看附件字符串，再判断 solver 顺序。"}}]}
        fake_response = Mock()
        fake_response.__enter__ = Mock(return_value=fake_response)
        fake_response.__exit__ = Mock(return_value=None)
        fake_response.read.return_value = json.dumps(response_payload).encode("utf-8")

        with patch("forgeflag.llm.request.urlopen", return_value=fake_response) as urlopen:
            provider = ZhipuChatCompletionsProvider(
                LLMConfig(provider="zhipu", model="glm-5.1", api_key="zhipu-test", timeout_seconds=13)
            )
            result = provider.generate("You are ForgeFlag.", "Solve this scoped CTF challenge.")

        self.assertEqual(result.content, "先看附件字符串，再判断 solver 顺序。")
        request_obj = urlopen.call_args.args[0]
        self.assertEqual(request_obj.full_url, "https://open.bigmodel.cn/api/paas/v4/chat/completions")
        self.assertEqual(request_obj.headers["Authorization"], "Bearer zhipu-test")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 13)
        body = json.loads(request_obj.data.decode("utf-8"))
        self.assertEqual(body["model"], "glm-5.1")
        self.assertEqual(body["messages"][0], {"role": "system", "content": "You are ForgeFlag."})
        self.assertEqual(body["messages"][1], {"role": "user", "content": "Solve this scoped CTF challenge."})
        self.assertFalse(body["stream"])

    def test_generate_retries_429_with_retry_after_before_succeeding(self) -> None:
        response_payload = {"choices": [{"message": {"content": "连接恢复。"}}]}
        fake_response = Mock()
        fake_response.__enter__ = Mock(return_value=fake_response)
        fake_response.__exit__ = Mock(return_value=None)
        fake_response.read.return_value = json.dumps(response_payload).encode("utf-8")
        rate_limit = _http_error(429, {"error": {"message": "Too Many Requests"}}, {"Retry-After": "2"})

        with (
            patch("forgeflag.llm.request.urlopen", side_effect=[rate_limit, fake_response]) as urlopen,
            patch("forgeflag.llm.time.sleep") as sleep,
        ):
            provider = ZhipuChatCompletionsProvider(
                LLMConfig(
                    provider="zhipu",
                    model="glm-5.1",
                    api_key="zhipu-test",
                    max_retries=2,
                    cooldown_seconds=120,
                )
            )
            result = provider.generate("You are ForgeFlag.", "Solve this scoped CTF challenge.")

        self.assertEqual(result.content, "连接恢复。")
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(2)

    def test_generate_retries_transient_timeout_before_succeeding(self) -> None:
        response_payload = {"choices": [{"message": {"content": "timeout recovered"}}]}
        fake_response = Mock()
        fake_response.__enter__ = Mock(return_value=fake_response)
        fake_response.__exit__ = Mock(return_value=None)
        fake_response.read.return_value = json.dumps(response_payload).encode("utf-8")

        with (
            patch("forgeflag.llm.request.urlopen", side_effect=[TimeoutError("read operation timed out"), fake_response]) as urlopen,
            patch("forgeflag.llm.time.sleep") as sleep,
        ):
            provider = ZhipuChatCompletionsProvider(
                LLMConfig(
                    provider="zhipu",
                    model="glm-5.1",
                    api_key="zhipu-test",
                    max_retries=1,
                    retry_initial_seconds=0,
                )
            )
            result = provider.generate("You are ForgeFlag.", "Solve this scoped CTF challenge.")

        self.assertEqual(result.content, "timeout recovered")
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_not_called()

    def test_generate_enters_cooldown_after_retry_budget_is_exhausted(self) -> None:
        first = _http_error(429, {"error": {"message": "Too Many Requests"}})
        second = _http_error(429, {"error": {"message": "Too Many Requests"}})

        with (
            patch("forgeflag.llm.request.urlopen", side_effect=[first, second]) as urlopen,
            patch("forgeflag.llm.time.sleep"),
            patch("forgeflag.llm.time.monotonic", side_effect=[10, 10, 10, 10, 11]),
        ):
            provider = ZhipuChatCompletionsProvider(
                LLMConfig(
                    provider="zhipu",
                    model="glm-5.1",
                    api_key="zhipu-test",
                    base_url="https://cooldown.test/api/paas/v4",
                    max_retries=1,
                    retry_initial_seconds=1,
                    cooldown_seconds=120,
                )
            )
            with self.assertRaisesRegex(RuntimeError, "rate limit"):
                provider.generate("You are ForgeFlag.", "Solve this scoped CTF challenge.")
            with self.assertRaisesRegex(RuntimeError, "cooling down"):
                provider.generate("You are ForgeFlag.", "Solve this scoped CTF challenge again.")

        self.assertEqual(urlopen.call_count, 2)


class LLMSolverTest(unittest.TestCase):
    def test_category_playbooks_cover_core_ctf_categories(self) -> None:
        expectations = {
            ChallengeCategory.WEB: ("WebSolver", "/robots.txt", "authorized CTF web challenge"),
            ChallengeCategory.CRYPTO: ("CryptoSolver", "RSA"),
            ChallengeCategory.FORENSICS: ("ForensicsSolver", "PNG chunks/IHDR/CRC", "foremost", "yara"),
            ChallengeCategory.TRAFFIC: ("TrafficSolver", "protocol hierarchy"),
            ChallengeCategory.REVERSE: ("ReverseSolver", "IDA/Ghidra/r2", "objdump", "readelf", "radare2", "local artifact analysis"),
            ChallengeCategory.PWN: ("PwnSolver", "checksec", "proof-of-solve harness"),
            ChallengeCategory.MISC: ("MiscSolver", "QR/barcode"),
        }

        for category, required_fragments in expectations.items():
            with self.subTest(category=category.value):
                prompt = category_playbook(category)
                self.assertIn("category_playbook:", prompt)
                self.assertIn("scope_context: ForgeFlag is for local or authorized CTF/lab research", prompt)
                for fragment in required_fragments:
                    self.assertIn(fragment, prompt)

    def test_prior_failure_patterns_include_prng_and_stream_cipher_lessons(self) -> None:
        prompt = prior_failure_patterns(
            ChallengeCategory.CRYPTO,
            "source uses random.seed, LCG next = (a*x+b)%n, MT19937 getrandbits, LFSR taps, and missing key sidecar",
        )

        self.assertIn("prior_failure_patterns:", prompt)
        self.assertIn("Do not accept source literal flags without replay evidence", prompt)
        self.assertIn("LCG", prompt)
        self.assertIn("MT19937", prompt)
        self.assertIn("LFSR", prompt)
        self.assertIn("sidecar", prompt)

    def test_llm_solver_records_strategy_finding_when_provider_is_enabled(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content="Prioritize file triage, then run strings for flag-like tokens.",
                    raw={"id": "fake-response"},
                )

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="llm-01",
                    category=ChallengeCategory.FORENSICS,
                    description="Attachment likely contains an easy flag.",
                )
            )

            summary = Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider())],
            ).run_challenge("llm-01")
            findings = notebook.findings_for("llm-01")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(findings[0].solver, "LLMSolver")
        self.assertEqual(findings[0].finding, "Generated LLM solve strategy")
        self.assertIn("run strings", findings[0].evidence["strategy"])

    def test_llm_solver_prompt_includes_bounded_text_attachment_preview(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def __init__(self) -> None:
                self.prompt = ""

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                self.prompt = prompt
                return LLMResponse(content='{"summary":"Inspect the LFSR source."}', raw={"id": "fake-response"})

        provider = FakeProvider()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "BM.py"
            source.write_text("class lfsr:\\n    def next(self):\\n        return output\\n", encoding="utf-8")
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="llm-attachment-preview",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(source),),
                )
            )

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(provider)],
            ).run_challenge("llm-attachment-preview")

        self.assertIn("attachment_previews:", provider.prompt)
        self.assertIn("BM.py", provider.prompt)
        self.assertIn("class lfsr", provider.prompt)
        self.assertIn("def next", provider.prompt)

    def test_llm_solver_prompt_includes_tail_of_long_text_attachment(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def __init__(self) -> None:
                self.prompt = ""

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                self.prompt = prompt
                return LLMResponse(content='{"summary":"Inspect tail output."}', raw={"id": "fake-response"})

        provider = FakeProvider()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "long_challenge.py"
            source.write_text(
                "class LongChallenge:\\n    pass\\n"
                + ("# filler\\n" * 500)
                + "# ciphertext_tail = 123456789\\n# flag_prefix = flag{\\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="llm-long-attachment-preview",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(source),),
                )
            )

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(provider)],
            ).run_challenge("llm-long-attachment-preview")

        self.assertIn("class LongChallenge", provider.prompt)
        self.assertIn("ciphertext_tail", provider.prompt)
        self.assertIn("[middle omitted", provider.prompt)

    def test_llm_solver_prompt_includes_prior_failure_patterns_from_attachment(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def __init__(self) -> None:
                self.prompt = ""

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                self.prompt = prompt
                return LLMResponse(content='{"summary":"Plan PRNG replay."}', raw={"id": "fake-response"})

        provider = FakeProvider()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "easy_random.py"
            source.write_text(
                "import random\n"
                "seed = 3277\n"
                "x = (a * x + b) % n\n"
                "bits = random.getrandbits(32)  # MT19937 style output\n"
                "# lfsr taps and missing key sidecar are important\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="llm-prior-failure-patterns",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(source),),
                )
            )

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(provider)],
            ).run_challenge("llm-prior-failure-patterns")

        self.assertIn("prior_failure_patterns:", provider.prompt)
        self.assertIn("Do not accept source literal flags without replay evidence", provider.prompt)
        self.assertIn("LCG", provider.prompt)
        self.assertIn("MT19937", provider.prompt)
        self.assertIn("sidecar", provider.prompt)

    def test_llm_solver_records_structured_plan_when_model_returns_json(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content=json.dumps(
                        {
                            "summary": "This looks like a packet capture challenge.",
                            "suggested_solvers": ["TrafficSolver"],
                            "next_actions": ["Run traffic solver first."],
                            "tool_hints": ["tshark_traffic_analysis"],
                        }
                    ),
                    raw={"id": "fake-response"},
                )

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-plan", category=ChallengeCategory.UNKNOWN))

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider())],
            ).run_challenge("llm-plan")
            finding = notebook.findings_for("llm-plan")[0]
            observations = notebook.observations_for("llm-plan")

        self.assertEqual(finding.evidence["plan"]["suggested_solvers"], ["TrafficSolver"])
        self.assertEqual(observations[0].kind, "llm_solver_plan")
        self.assertEqual(observations[0].evidence["suggested_solvers"], ["TrafficSolver"])

    def test_llm_solver_records_operational_plan_fields_when_model_returns_json(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content=json.dumps(
                        {
                            "summary": "Recover PRNG state before accepting a candidate.",
                            "analysis_mode": "prng_stream_replay",
                            "artifact_requirements": ["source file tail", "output sidecar"],
                            "blocked_by_missing_artifacts": ["key"],
                            "manual_replay_needed": ["Run known-seed replay and compare generated bytes."],
                            "risk_notes": ["Source literal flag is only a clue until replay passes."],
                        }
                    ),
                    raw={"id": "fake-response"},
                )

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-operational-plan", category=ChallengeCategory.CRYPTO))

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider())],
            ).run_challenge("llm-operational-plan")
            finding = notebook.findings_for("llm-operational-plan")[0]
            observations = notebook.observations_for("llm-operational-plan")

        plan = finding.evidence["plan"]
        self.assertEqual(plan["analysis_mode"], "prng_stream_replay")
        self.assertEqual(plan["artifact_requirements"], ["source file tail", "output sidecar"])
        self.assertEqual(plan["blocked_by_missing_artifacts"], ["key"])
        self.assertEqual(plan["manual_replay_needed"], ["Run known-seed replay and compare generated bytes."])
        self.assertEqual(plan["risk_notes"], ["Source literal flag is only a clue until replay passes."])
        self.assertEqual(observations[0].evidence["analysis_mode"], "prng_stream_replay")
        self.assertEqual(observations[0].evidence["blocked_by_missing_artifacts"], ["key"])

    def test_llm_solver_parses_planner_v2_markdown_json(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content="""```json
{
  "summary": "PCAP challenge with possible HTTP payload flag.",
  "hypotheses": ["The flag is in a TCP stream.", 3],
  "suggested_solvers": ["TrafficSolver", "TrafficSolver", "UnknownSolver"],
  "next_actions": ["Run tshark flag scan.", "Inspect HTTP streams."],
  "tool_hints": ["tshark_flag_scan", "tshark_http_requests"],
  "expected_evidence": ["flag-like token in packet bytes"],
  "fallback_plan": ["List TCP streams if direct scan misses."]
}
```""",
                    raw={"id": "fake-response"},
                )

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-v2", category=ChallengeCategory.TRAFFIC))

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider())],
            ).run_challenge("llm-v2")
            finding = notebook.findings_for("llm-v2")[0]
            observations = notebook.observations_for("llm-v2")

        plan = finding.evidence["plan"]
        self.assertEqual(plan["summary"], "PCAP challenge with possible HTTP payload flag.")
        self.assertEqual(plan["hypotheses"], ["The flag is in a TCP stream."])
        self.assertEqual(plan["suggested_solvers"], ["TrafficSolver", "UnknownSolver"])
        self.assertEqual(plan["expected_evidence"], ["flag-like token in packet bytes"])
        self.assertEqual(plan["fallback_plan"], ["List TCP streams if direct scan misses."])
        self.assertEqual(finding.next_action, "Run tshark flag scan.")
        self.assertEqual(observations[0].evidence["expected_evidence"], ["flag-like token in packet bytes"])
        self.assertEqual(observations[0].evidence["fallback_plan"], ["List TCP streams if direct scan misses."])

    def test_llm_solver_promotes_model_flag_candidates_into_verifier_flow(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content=json.dumps(
                        {
                            "summary": "Recovered the flag from the provided local artifact preview.",
                            "hypotheses": ["The attachment contains enough arithmetic evidence to solve directly."],
                            "flag_candidates": ["flag{llm_candidate_promotion}"],
                            "expected_evidence": ["candidate derived from local attachment preview"],
                        }
                    ),
                    raw={"id": "fake-response"},
                )

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="llm-promotes-flag",
                    category=ChallengeCategory.MISC,
                    description="Local CTF puzzle whose arithmetic can be solved from the prompt.",
                )
            )

            summary = Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider())],
            ).run_challenge("llm-promotes-flag")
            finding = next(finding for finding in notebook.findings_for("llm-promotes-flag") if finding.solver == "LLMSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{llm_candidate_promotion}"])
        self.assertEqual(finding.evidence["plan"]["flag_candidates"], ["flag{llm_candidate_promotion}"])

    def test_llm_solver_extracts_flag_candidate_from_plain_text_strategy(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content="I replayed the local artifact arithmetic and derived flag{llm_plaintext_candidate}.",
                    raw={"id": "fake-response"},
                )

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-plain-flag", category=ChallengeCategory.MISC))

            summary = Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider())],
            ).run_challenge("llm-plain-flag")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{llm_plaintext_candidate}"])

    def test_llm_solver_falls_back_when_planner_v2_json_is_invalid(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(content="```json\n{\"summary\": \"broken\", \n```", raw={"id": "fake-response"})

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-bad-json", category=ChallengeCategory.MISC))

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider())],
            ).run_challenge("llm-bad-json")
            finding = notebook.findings_for("llm-bad-json")[0]
            observations = notebook.observations_for("llm-bad-json")

        self.assertNotIn("plan", finding.evidence)
        self.assertIn("broken", finding.evidence["strategy"])
        self.assertEqual(finding.confidence, 0.55)
        self.assertFalse(any(observation.kind == "llm_solver_plan" for observation in observations))

    def test_llm_solver_extracts_json_fence_from_explanatory_text(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content='Plan follows:\n```json\n{"summary":"Use misc transforms","suggested_solvers":["MiscSolver"]}\n```',
                    raw={"id": "fake-response"},
                )

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-prose-json", category=ChallengeCategory.MISC))

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider())],
            ).run_challenge("llm-prose-json")
            finding = notebook.findings_for("llm-prose-json")[0]

        self.assertEqual(finding.evidence["plan"]["summary"], "Use misc transforms")
        self.assertEqual(finding.evidence["plan"]["suggested_solvers"], ["MiscSolver"])

    def test_llm_solver_ignores_empty_plan_json(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(content="{}", raw={"id": "fake-response"})

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-empty-json", category=ChallengeCategory.MISC))

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider())],
            ).run_challenge("llm-empty-json")
            finding = notebook.findings_for("llm-empty-json")[0]

        self.assertNotIn("plan", finding.evidence)
        self.assertEqual(finding.confidence, 0.55)

    def test_manager_filters_unknown_and_duplicate_llm_solver_suggestions(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content=json.dumps(
                        {
                            "summary": "Try extra solver once.",
                            "suggested_solvers": [
                                "ExtraSolver",
                                "ExtraSolver",
                                "../../BadSolver",
                                "LLMSolver",
                            ],
                        }
                    )
                )

        class ExtraSolver:
            name = "ExtraSolver"
            supported_categories = {ChallengeCategory.TRAFFIC}

            def solve(self, context: SolverContext):
                from forgeflag.domain import Finding, SolverResult

                finding = Finding(
                    challenge_id=context.challenge.challenge_id,
                    solver=self.name,
                    finding="Extra solver ran once",
                    evidence={"ran": True},
                    confidence=0.8,
                )
                context.notebook.add_finding(finding)
                return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-filter", category=ChallengeCategory.MISC))

            summary = Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider()), ExtraSolver()],
            ).run_challenge("llm-filter")

        self.assertEqual([row["solver"] for row in summary["solvers"]], ["LLMSolver", "ExtraSolver"])

    def test_llm_solver_prompt_includes_web_category_playbook(self) -> None:
        class RecordingProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def __init__(self) -> None:
                self.prompt = ""
                self.instructions = ""

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                self.instructions = instructions
                self.prompt = prompt
                return LLMResponse(content="Web planning text.", raw={"id": "fake-response"})

        provider = RecordingProvider()
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="llm-web-prompt",
                    category=ChallengeCategory.WEB,
                    target="http://127.0.0.1:8081",
                    description="A login page with hidden routes.",
                )
            )

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(provider)],
            ).run_challenge("llm-web-prompt")

        self.assertIn("category_playbook:", provider.prompt)
        self.assertIn("scope_context: ForgeFlag is for local or authorized CTF/lab research", provider.prompt)
        self.assertIn("authorized CTF web challenge", provider.prompt)
        self.assertIn("controlled challenge research", provider.instructions)
        self.assertIn("response capture", provider.prompt)
        self.assertIn("/robots.txt", provider.prompt)
        self.assertIn("SQL/NoSQL injection", provider.prompt)
        self.assertIn("suggested_solvers: WebSolver", provider.prompt)

    def test_llm_solver_prompt_includes_traffic_category_playbook(self) -> None:
        class RecordingProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def __init__(self) -> None:
                self.prompt = ""

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                self.prompt = prompt
                return LLMResponse(content="Traffic planning text.", raw={"id": "fake-response"})

        provider = RecordingProvider()
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "capture.pcap"
            pcap.write_bytes(b"pcap")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="llm-traffic-prompt",
                    category=ChallengeCategory.TRAFFIC,
                    attachment_paths=(str(pcap),),
                )
            )

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(provider)],
            ).run_challenge("llm-traffic-prompt")

        self.assertIn("protocol hierarchy", provider.prompt)
        self.assertIn("DNS queries/TXT", provider.prompt)
        self.assertIn("TCP streams", provider.prompt)
        self.assertIn("tshark_flag_scan", provider.prompt)
        self.assertIn("suggested_solvers: TrafficSolver", provider.prompt)

    def test_llm_solver_prompt_includes_retrieved_knowledge_from_prior_writeup(self) -> None:
        class RecordingProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def __init__(self) -> None:
                self.prompt = ""

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                self.prompt = prompt
                return LLMResponse(content="Traffic planning text.", raw={"id": "fake-response"})

        provider = RecordingProvider()
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="old-dns",
                    category=ChallengeCategory.TRAFFIC,
                    title="Old DNS exfil",
                )
            )
            notebook.record_run(
                "old-dns",
                "flag_found",
                {
                    "replay_report": {
                        "writeup": {
                            "title": "Old DNS exfil",
                            "category": "traffic",
                            "markdown": "# Old DNS exfil\n\nReconstruct Base32 DNS labels from query order.",
                        }
                    }
                },
            )
            notebook.add_challenge(
                Challenge(
                    challenge_id="new-dns",
                    category=ChallengeCategory.TRAFFIC,
                    description="PCAP with DNS query labels.",
                )
            )

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(provider)],
            ).run_challenge("new-dns")

            self.assertIn("retrieved_knowledge:", provider.prompt)
            self.assertIn("Old DNS exfil", provider.prompt)
            self.assertIn("Base32 DNS labels", provider.prompt)
            finding = next(finding for finding in notebook.findings_for("new-dns") if finding.solver == "LLMSolver")
            retrieved = finding.evidence["retrieved_knowledge"]
            self.assertTrue(any(item["title"] == "Old DNS exfil" for item in retrieved))
            observations = notebook.observations_for("new-dns")
            knowledge_observation = next(observation for observation in observations if observation.kind == "knowledge_retrieval")
            self.assertTrue(any(item["title"] == "Old DNS exfil" for item in knowledge_observation.evidence["items"]))

    def test_llm_solver_prompt_uses_unknown_category_routing_playbook(self) -> None:
        class RecordingProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def __init__(self) -> None:
                self.prompt = ""

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                self.prompt = prompt
                return LLMResponse(content="Unknown planning text.", raw={"id": "fake-response"})

        provider = RecordingProvider()
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="llm-unknown-prompt",
                    category=ChallengeCategory.UNKNOWN,
                    description="Maybe base32, maybe a PNG.",
                )
            )

            Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(provider)],
            ).run_challenge("llm-unknown-prompt")

        self.assertIn("category_playbook:", provider.prompt)
        self.assertIn("route the challenge", provider.prompt)
        self.assertIn("artifact type", provider.prompt)
        self.assertIn("cheap evidence first", provider.prompt)
        self.assertIn("suggested_solvers:", provider.prompt)

    def test_manager_adds_solver_suggested_by_llm_plan_observation(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content=json.dumps(
                        {
                            "summary": "Use extra solver",
                            "analysis_mode": "traffic_resync",
                            "suggested_solvers": ["ExtraSolver"],
                            "expected_evidence": ["stream payload replay"],
                            "artifact_requirements": ["original pcap"],
                            "blocked_by_missing_artifacts": ["exported TCP stream"],
                            "manual_replay_needed": ["Run stream extraction and verify the candidate."],
                            "risk_notes": ["Do not trust a direct strings hit without packet evidence."],
                        }
                    )
                )

        class ExtraSolver:
            name = "ExtraSolver"
            supported_categories = {ChallengeCategory.TRAFFIC}

            def solve(self, context: SolverContext):
                from forgeflag.domain import Finding, SolverResult

                finding = Finding(
                    challenge_id=context.challenge.challenge_id,
                    solver=self.name,
                    finding="Extra solver ran from LLM plan",
                    evidence={"ran": True},
                    confidence=0.8,
                )
                context.notebook.add_finding(finding)
                return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-dispatch", category=ChallengeCategory.MISC))

            summary = Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider()), ExtraSolver()],
            ).run_challenge("llm-dispatch")
            action_queue = next(
                observation for observation in notebook.observations_for("llm-dispatch")
                if observation.kind == "llm_action_queue"
            )
            trace = [
                observation for observation in notebook.observations_for("llm-dispatch")
                if observation.kind == "solve_trace_step" and observation.source == "ExtraSolver"
            ][0]

        self.assertEqual([row["solver"] for row in summary["solvers"]], ["LLMSolver", "ExtraSolver"])
        self.assertEqual(action_queue.evidence["requested_solvers"], ["ExtraSolver"])
        self.assertEqual(action_queue.evidence["queued_solvers"], ["ExtraSolver"])
        self.assertEqual(action_queue.evidence["unknown_solvers"], [])
        self.assertEqual(action_queue.evidence["analysis_mode"], "traffic_resync")
        self.assertEqual(action_queue.evidence["artifact_requirements"], ["original pcap"])
        self.assertEqual(action_queue.evidence["blocked_by_missing_artifacts"], ["exported TCP stream"])
        self.assertEqual(action_queue.evidence["manual_replay_needed"], ["Run stream extraction and verify the candidate."])
        self.assertEqual(action_queue.evidence["risk_notes"], ["Do not trust a direct strings hit without packet evidence."])
        self.assertEqual(trace.evidence["llm_plan"]["analysis_mode"], "traffic_resync")
        self.assertEqual(trace.evidence["llm_plan"]["artifact_requirements"], ["original pcap"])
        self.assertEqual(trace.evidence["llm_plan"]["blocked_by_missing_artifacts"], ["exported TCP stream"])
        self.assertEqual(trace.evidence["llm_plan"]["manual_replay_needed"], ["Run stream extraction and verify the candidate."])
        self.assertEqual(trace.evidence["llm_plan"]["risk_notes"], ["Do not trust a direct strings hit without packet evidence."])

    def test_manager_records_llm_action_queue_for_manual_guidance_without_solver_suggestion(self) -> None:
        class FakeProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                return LLMResponse(
                    content=json.dumps(
                        {
                            "summary": "The source references a missing output file.",
                            "analysis_mode": "missing_sidecar_replay",
                            "next_actions": ["Locate output.txt or rerun the challenge generator."],
                            "artifact_requirements": ["output.txt"],
                            "blocked_by_missing_artifacts": ["output.txt"],
                            "manual_replay_needed": ["Recreate the local generator output before accepting any flag."],
                            "risk_notes": ["Do not submit the commented flag literal."],
                        }
                    )
                )

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-manual-guidance", category=ChallengeCategory.CRYPTO))

            summary = Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(FakeProvider())],
            ).run_challenge("llm-manual-guidance")
            action_queue = next(
                observation for observation in notebook.observations_for("llm-manual-guidance")
                if observation.kind == "llm_action_queue"
            )

        self.assertEqual(summary["solvers"], [{"solver": "LLMSolver", "status": "ok", "findings": 1}])
        self.assertEqual(action_queue.summary, "LLM provided manual guidance without changing the solver queue")
        self.assertEqual(action_queue.evidence["requested_solvers"], [])
        self.assertEqual(action_queue.evidence["analysis_mode"], "missing_sidecar_replay")
        self.assertEqual(action_queue.evidence["next_actions"], ["Locate output.txt or rerun the challenge generator."])
        self.assertEqual(action_queue.evidence["artifact_requirements"], ["output.txt"])
        self.assertEqual(action_queue.evidence["blocked_by_missing_artifacts"], ["output.txt"])
        self.assertEqual(action_queue.evidence["manual_replay_needed"], ["Recreate the local generator output before accepting any flag."])
        self.assertEqual(action_queue.evidence["risk_notes"], ["Do not submit the commented flag literal."])

    def test_manager_continues_when_runtime_llm_config_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-missing-key", category=ChallengeCategory.MISC))

            summary = Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="zhipu", model="glm-5.1")),
            ).run_challenge("llm-missing-key")
            findings = notebook.findings_for("llm-missing-key")

        self.assertEqual(summary["status"], "completed")
        self.assertIn({"solver": "LLMSolver", "status": "config_error", "findings": 1}, summary["solvers"])
        self.assertIn({"solver": "MiscSolver", "status": "placeholder", "findings": 1}, summary["solvers"])
        self.assertEqual(summary["llm_status"]["enabled"], True)
        self.assertEqual(summary["llm_status"]["status"], "config_error")
        self.assertEqual(summary["llm_status"]["provider"], "zhipu")
        self.assertEqual(summary["llm_status"]["model"], "glm-5.1")
        llm_finding = next(finding for finding in findings if finding.solver == "LLMSolver")
        self.assertEqual(llm_finding.finding, "LLM planning unavailable")
        self.assertIn("ZAI_API_KEY", llm_finding.evidence["error"])

    def test_manager_does_not_report_stale_llm_error_when_llm_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="llm-stale-error", category=ChallengeCategory.MISC))
            notebook.add_finding(
                Finding(
                    challenge_id="llm-stale-error",
                    solver="LLMSolver",
                    finding="LLM planning unavailable",
                    evidence={"error": "The read operation timed out"},
                    confidence=0.2,
                )
            )

            summary = Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="disabled")),
            ).run_challenge("llm-stale-error")

        self.assertEqual(summary["llm_status"]["enabled"], False)
        self.assertEqual(summary["llm_status"]["status"], "disabled")
        self.assertNotIn("error", summary["llm_status"])

    def test_manager_records_post_run_critic_when_llm_run_stalls_without_flag(self) -> None:
        class CriticProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def __init__(self) -> None:
                self.prompts: list[str] = []
                self.instructions: list[str] = []

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                self.instructions.append(instructions)
                self.prompts.append(prompt)
                if "post-run critic" in instructions:
                    return LLMResponse(
                        content=json.dumps(
                            {
                                "summary": "No flag yet; image evidence stopped at metadata only.",
                                "blockers": ["No low-bit-plane or chunk payload extraction was attempted."],
                                "missing_evidence": ["IDAT payload decode result"],
                                "suggested_solvers": ["MiscSolver"],
                                "tool_hints": ["pngcheck", "zlib decompress extra IDAT"],
                                "next_actions": ["Parse PNG chunks and independently decompress suspicious IDAT payloads."],
                                "rerun_reason": "New evidence route may expose embedded flag text.",
                            }
                        ),
                        raw={"id": "critic"},
                    )
                return LLMResponse(content='{"summary":"Initial plan only"}', raw={"id": "plan"})

        class StuckSolver:
            name = "StuckSolver"
            supported_categories = {ChallengeCategory.MISC}

            def solve(self, context: SolverContext):
                from forgeflag.domain import Finding, SolverResult

                finding = Finding(
                    challenge_id=context.challenge.challenge_id,
                    solver=self.name,
                    finding="Stopped after image metadata",
                    evidence={"image_stego": {"text_chunks": []}},
                    confidence=0.72,
                    next_action="Try deeper PNG chunk payload extraction.",
                )
                context.notebook.add_finding(finding)
                return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        provider = CriticProvider()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "stalled.png.txt"
            attachment.write_text("PNG header notes\n" + ("metadata only\n" * 300) + "tail clue: inspect extra IDAT\n", encoding="utf-8")
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="critic-stalled",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(provider), StuckSolver()],
            ).run_challenge("critic-stalled")
            observations = notebook.observations_for("critic-stalled")

        critic = next(observation for observation in observations if observation.kind == "llm_post_run_critic")
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["post_run_critic"]["suggested_solvers"], ["MiscSolver"])
        self.assertEqual(critic.evidence["missing_evidence"], ["IDAT payload decode result"])
        self.assertIn("Parse PNG chunks", critic.evidence["next_actions"][0])
        self.assertEqual(len(provider.prompts), 3)
        # third call is the reviewer judging the trajectory digest
        self.assertIn("[StuckSolver]", provider.prompts[2])
        self.assertIn("controlled challenge research", provider.instructions[1])
        self.assertIn("run_status: completed", provider.prompts[1])
        self.assertIn("attachment_previews:", provider.prompts[1])
        self.assertIn("tail clue: inspect extra IDAT", provider.prompts[1])
        self.assertIn("category_playbook:", provider.prompts[1])
        self.assertIn("prior_failure_patterns:", provider.prompts[1])

    def test_manager_skips_post_run_critic_after_flag_found(self) -> None:
        class CountingProvider:
            name = "fake"
            model = "fake-model"
            enabled = True

            def __init__(self) -> None:
                self.calls = 0

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
                self.calls += 1
                return LLMResponse(content='{"summary":"Initial plan only"}')

        class FlagSolver:
            name = "FlagSolver"
            supported_categories = {ChallengeCategory.MISC}

            def solve(self, context: SolverContext):
                from forgeflag.domain import Finding, SolverResult

                finding = Finding(
                    challenge_id=context.challenge.challenge_id,
                    solver=self.name,
                    finding="Recovered flag",
                    evidence={"flag_candidates": ["flag{critic_skip}"]},
                    confidence=0.9,
                )
                context.notebook.add_finding(finding)
                return SolverResult(self.name, context.challenge.challenge_id, "flag_candidate", (finding,), ("flag{critic_skip}",))

        provider = CountingProvider()
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="critic-solved", category=ChallengeCategory.MISC))

            summary = Manager(
                notebook,
                RunConfig(llm_config=LLMConfig(provider="fake", model="fake-model", api_key="unused")),
                solvers=[LLMSolver(provider), FlagSolver()],
            ).run_challenge("critic-solved")
            observations = notebook.observations_for("critic-solved")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(provider.calls, 1)
        self.assertFalse(any(observation.kind == "llm_post_run_critic" for observation in observations))


if __name__ == "__main__":
    unittest.main()


class AnthropicMessagesProviderTest(unittest.TestCase):
    def test_generate_posts_messages_api_and_extracts_usage(self) -> None:
        response_payload = {
            "content": [{"type": "text", "text": "flag{from_coding_plan}"}],
            "usage": {"input_tokens": 120, "output_tokens": 30},
        }
        fake_response = Mock()
        fake_response.__enter__ = Mock(return_value=fake_response)
        fake_response.__exit__ = Mock(return_value=None)
        fake_response.read.return_value = json.dumps(response_payload).encode("utf-8")

        with patch("forgeflag.llm.request.urlopen", return_value=fake_response) as urlopen:
            provider = AnthropicMessagesProvider(
                LLMConfig(provider="anthropic", model="glm-4.6", api_key="plan-key", base_url="https://open.bigmodel.cn/api/anthropic", timeout_seconds=12)
            )
            result = provider.generate("You are ForgeFlag.", "Solve this scoped CTF challenge.")

        self.assertIn("flag{from_coding_plan}", result.content)
        self.assertEqual(result.usage["total_tokens"], 150)
        request_obj = urlopen.call_args[0][0]
        self.assertEqual(request_obj.full_url, "https://open.bigmodel.cn/api/anthropic/v1/messages")
        self.assertEqual(request_obj.headers.get("X-api-key"), "plan-key")
        self.assertEqual(request_obj.headers.get("Anthropic-version"), "2023-06-01")

    def test_requires_key_and_model(self) -> None:
        with self.assertRaises(ValueError):
            AnthropicMessagesProvider(LLMConfig(provider="anthropic", model="glm-4.6"))
        with self.assertRaises(ValueError):
            AnthropicMessagesProvider(LLMConfig(provider="anthropic", api_key="k"))


class AnthropicEnvConfigTest(unittest.TestCase):
    def test_env_reads_anthropic_key_and_default_base_url(self) -> None:
        config = LLMConfig.from_env(
            {
                "FORGEFLAG_LLM_PROVIDER": "anthropic",
                "FORGEFLAG_LLM_MODEL": "glm-4.6",
                "ANTHROPIC_API_KEY": "plan-key",
            }
        )
        self.assertEqual(config.api_key, "plan-key")
        self.assertEqual(config.base_url, "https://open.bigmodel.cn/api/anthropic")

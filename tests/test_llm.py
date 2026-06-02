from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from forgeflag.domain import DEFAULT_ZHIPU_MODEL, Challenge, ChallengeCategory, LLMConfig, RunConfig
from forgeflag.llm import LLMResponse, OpenAIResponsesProvider, ZhipuChatCompletionsProvider
from forgeflag.llm_prompts import category_playbook
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers.llm import LLMSolver
from forgeflag.solvers.base import SolverContext


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


class LLMSolverTest(unittest.TestCase):
    def test_category_playbooks_cover_core_ctf_categories(self) -> None:
        expectations = {
            ChallengeCategory.WEB: ("WebSolver", "/robots.txt"),
            ChallengeCategory.CRYPTO: ("CryptoSolver", "RSA"),
            ChallengeCategory.FORENSICS: ("ForensicsSolver", "PNG chunks/IHDR/CRC"),
            ChallengeCategory.TRAFFIC: ("TrafficSolver", "protocol hierarchy"),
            ChallengeCategory.REVERSE: ("ReverseSolver", "IDA/Ghidra/r2"),
            ChallengeCategory.PWN: ("PwnSolver", "checksec"),
            ChallengeCategory.MISC: ("MiscSolver", "QR/barcode"),
        }

        for category, required_fragments in expectations.items():
            with self.subTest(category=category.value):
                prompt = category_playbook(category)
                self.assertIn("category_playbook:", prompt)
                for fragment in required_fragments:
                    self.assertIn(fragment, prompt)

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

            def generate(self, instructions: str, prompt: str) -> LLMResponse:
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
                return LLMResponse(content='{"summary":"Use extra solver","suggested_solvers":["ExtraSolver"]}')

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

        self.assertEqual([row["solver"] for row in summary["solvers"]], ["LLMSolver", "ExtraSolver"])

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
        llm_finding = next(finding for finding in findings if finding.solver == "LLMSolver")
        self.assertEqual(llm_finding.finding, "LLM planning unavailable")
        self.assertIn("ZAI_API_KEY", llm_finding.evidence["error"])


if __name__ == "__main__":
    unittest.main()

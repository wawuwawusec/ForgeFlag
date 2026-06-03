from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import LLMConfig
from forgeflag.webapp import create_handler


class WebAppApiTest(unittest.TestCase):
    def test_create_challenge_payload_decodes_uploaded_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            payload = {
                "challenge_id": "webui-01",
                "category": "forensics",
                "attachments": [
                    {
                        "name": "flag.txt",
                        "content_base64": base64.b64encode(b"flag{web_ui_upload}\n").decode("ascii"),
                    }
                ],
            }
            handler_cls = create_handler(db)

            response = handler_cls.handle_create_challenge(payload)
            challenge = handler_cls.notebook.get_challenge("webui-01")

            self.assertEqual(response["status"], "ok")
            self.assertEqual(challenge.category.value, "forensics")
            self.assertEqual(len(challenge.attachment_paths), 1)
            self.assertEqual(Path(challenge.attachment_paths[0]).read_text(encoding="utf-8"), "flag{web_ui_upload}\n")

    def test_artifacts_endpoint_returns_registered_attachment_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            content = b"web artifact bytes"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge(
                {
                    "challenge_id": "webui-artifacts",
                    "category": "misc",
                    "attachments": [
                        {
                            "name": "sample.bin",
                            "content_base64": base64.b64encode(content).decode("ascii"),
                        }
                    ],
                }
            )

            payload = handler_cls.handle_artifacts("webui-artifacts")

        self.assertEqual(payload["challenge_id"], "webui-artifacts")
        self.assertEqual(payload["artifacts"][0]["name"], "sample.bin")
        self.assertTrue(payload["artifacts"][0]["exists"])
        self.assertEqual(payload["artifacts"][0]["size_bytes"], len(content))
        self.assertEqual(payload["artifacts"][0]["sha256"], hashlib.sha256(content).hexdigest())

    def test_run_challenge_payload_returns_summary_with_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge(
                {
                    "challenge_id": "webui-run",
                    "category": "forensics",
                    "attachments": [
                        {
                            "name": "flag.txt",
                            "content_base64": base64.b64encode(b"flag{web_ui_run}\n").decode("ascii"),
                        }
                    ],
                }
            )

            summary = handler_cls.handle_run_challenge("webui-run", {})

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{web_ui_run}"])

    def test_summary_endpoint_returns_latest_run_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge({"challenge_id": "webui-summary", "category": "misc"})
            handler_cls.notebook.record_run(
                "webui-summary",
                "flag_found",
                {
                    "challenge_id": "webui-summary",
                    "status": "flag_found",
                    "accepted_flags": ["flag{persisted_summary}"],
                    "solvers": [{"solver": "MiscSolver", "status": "ok", "findings": 1}],
                    "observations": 3,
                },
            )

            payload = handler_cls.handle_summary("webui-summary")

        self.assertEqual(payload["status"], "flag_found")
        self.assertEqual(payload["accepted_flags"], ["flag{persisted_summary}"])
        self.assertEqual(payload["solvers"][0]["solver"], "MiscSolver")

    def test_summary_endpoint_returns_not_run_for_new_challenge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge({"challenge_id": "webui-not-run", "category": "misc"})

            payload = handler_cls.handle_summary("webui-not-run")

        self.assertEqual(payload["challenge_id"], "webui-not-run")
        self.assertEqual(payload["status"], "not_run")
        self.assertEqual(payload["accepted_flags"], [])

    def test_challenge_list_includes_latest_run_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge({"challenge_id": "webui-list-status", "category": "misc"})
            handler_cls.notebook.record_run(
                "webui-list-status",
                "flag_found",
                {
                    "challenge_id": "webui-list-status",
                    "status": "flag_found",
                    "accepted_flags": ["flag{list_status}"],
                    "rejected_flags": [],
                },
            )

            rows = handler_cls.handle_list_challenges()

        row = next(item for item in rows if item["challenge_id"] == "webui-list-status")
        self.assertEqual(row["latest_status"], "flag_found")
        self.assertEqual(row["accepted_flags"], ["flag{list_status}"])
        self.assertEqual(row["accepted_flag_count"], 1)

    def test_delete_challenge_removes_notebook_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge(
                {
                    "challenge_id": "webui-delete",
                    "category": "misc",
                    "attachments": [
                        {
                            "name": "delete.txt",
                            "content_base64": base64.b64encode(b"flag{delete_me}\n").decode("ascii"),
                        }
                    ],
                }
            )
            handler_cls.notebook.record_run("webui-delete", "completed", {"challenge_id": "webui-delete", "status": "completed"})

            response = handler_cls.handle_delete_challenge("webui-delete")
            rows = handler_cls.handle_list_challenges()

        self.assertEqual(response["status"], "deleted")
        self.assertEqual(response["challenge_id"], "webui-delete")
        self.assertFalse(any(row["challenge_id"] == "webui-delete" for row in rows))
        self.assertGreaterEqual(response["deleted"]["challenges"], 1)

    def test_clear_challenges_removes_all_notebook_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge({"challenge_id": "webui-clear-a", "category": "misc"})
            handler_cls.handle_create_challenge({"challenge_id": "webui-clear-b", "category": "web"})

            response = handler_cls.handle_clear_challenges()
            rows = handler_cls.handle_list_challenges()

        self.assertEqual(response["status"], "cleared")
        self.assertEqual(rows, [])
        self.assertGreaterEqual(response["deleted"]["challenges"], 2)

    def test_index_contains_category_workspace_controls(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('id="categoryFilters"', html)
        self.assertIn("分类工作台", html)
        self.assertIn("categoryCounts", html)
        self.assertIn('id="statusFilters"', html)
        self.assertIn("状态筛选", html)
        self.assertIn("function renderStatusFilters", html)
        self.assertIn("function statusMatches", html)
        self.assertIn("function renderChallengeGroups", html)
        self.assertIn("function statusLabel", html)
        self.assertIn("function tagChips", html)
        self.assertIn("accepted_flag_count", html)
        self.assertIn("category-group", html)
        self.assertIn('data-tab="catalog"', html)
        self.assertIn('data-tab="artifacts"', html)
        self.assertIn('id="deleteBtn"', html)
        self.assertIn('id="clearBtn"', html)
        self.assertIn("function deleteSelectedChallenge", html)
        self.assertIn("function clearChallenges", html)
        self.assertIn("function setRunState", html)
        self.assertIn('id="actionToast"', html)
        self.assertIn("function setButtonBusy", html)
        self.assertIn("function flashButton", html)
        self.assertIn("async function withButtonFeedback", html)
        self.assertIn("button.is-busy", html)

    def test_index_renders_human_readable_result_tabs(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('class="result-view"', html)
        self.assertIn("function renderSummary", html)
        self.assertIn("function renderFindings", html)
        self.assertIn("function renderReport", html)
        self.assertIn("function renderWriteupReport", html)
        self.assertIn('data-tab="report">Write-up</button>', html)
        self.assertLess(html.index('data-tab="summary"'), html.index('data-tab="report"'))
        self.assertLess(html.index('data-tab="report"'), html.index('data-tab="agent"'))
        self.assertNotIn('data-tab="report">Report</button>', html)
        self.assertIn("function tabIntro", html)
        self.assertIn("总览本题最近一次运行状态", html)
        self.assertIn("按答题者视角串起 LLM 规划", html)
        self.assertIn("每个 solver 产出的发现", html)
        self.assertIn("跨 solver 共享的线索池", html)
        self.assertIn("确认上传附件是否已进入工作区", html)
        self.assertIn("只保留解题思路和复现步骤", html)
        self.assertIn("本机和 Docker 中可用的工具", html)
        self.assertIn("推荐集成的 CTF 项目目录", html)
        self.assertIn("解题思路", html)
        self.assertIn("复现步骤", html)
        self.assertNotIn('const writeupSectionOrder = ["结论"', html)
        self.assertNotIn("Write-up Markdown", html)
        self.assertNotIn("关键证据", html)
        self.assertIn("查看调试 JSON", html)
        self.assertIn("推荐 CTF 工具目录", html)
        self.assertIn("Docker install", html)
        self.assertIn("host/docker", html)
        self.assertIn("function renderToolGroups", html)
        self.assertIn("tool-group", html)
        self.assertIn("查看调试 JSON", html)
        self.assertIn("function loadLatestSummary", html)
        self.assertIn("/summary", html)

    def test_index_contains_agent_timeline_view(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('data-tab="agent"', html)
        self.assertIn("function loadAgentView", html)
        self.assertIn("function renderAgentView", html)
        self.assertIn("Agent 解题过程", html)
        self.assertIn("LLM 规划", html)
        self.assertIn("行动队列", html)
        self.assertIn("知识检索", html)
        self.assertIn("Post-run Critic", html)
        self.assertIn("卡点、缺失证据和下一轮建议", html)
        self.assertIn("工具摘要", html)
        self.assertIn("SolveTrace", html)
        self.assertIn("function renderActionQueue", html)
        self.assertIn("function renderPostRunCritic", html)

    def test_project_catalog_endpoint_lists_recommended_projects(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        payload = handler_cls.handle_project_catalog()

        self.assertIn("pwntools", {row["name"] for row in payload})
        self.assertIn("CyberChef", {row["name"] for row in payload})

    def test_tools_endpoint_groups_wrappers_and_recommended_catalog(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        payload = handler_cls.handle_tools()

        self.assertIn("wrappers", payload)
        self.assertIn("catalog", payload)
        self.assertIn("counts", payload)
        self.assertIn("host_wrappers", payload["counts"])
        self.assertIn("docker_wrappers", payload["counts"])
        self.assertIn("missing_wrappers", payload["counts"])
        self.assertEqual(
            payload["counts"]["wrappers"],
            payload["counts"]["host_wrappers"] + payload["counts"]["docker_wrappers"] + payload["counts"]["missing_wrappers"],
        )
        self.assertEqual(payload["runtime_smoke"]["docker_build_command"], "scripts/forgeflag-control docker-build")
        self.assertEqual(payload["runtime_smoke"]["docker_smoke_command"], "scripts/forgeflag-control docker-smoke")
        self.assertIn("file", {row["name"] for row in payload["wrappers"]})
        self.assertIn("Burp Suite Community", {row["name"] for row in payload["catalog"]})

    def test_run_button_loads_findings_after_summary(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('await loadTab("findings")', html)

    def test_index_contains_llm_runtime_controls(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('id="llmEnabled"', html)
        self.assertIn('id="llmApiKey"', html)
        self.assertIn('id="llmSaveConfig"', html)
        self.assertIn('id="llmTestBtn"', html)
        self.assertIn('id="llmRememberKey"', html)
        self.assertIn('id="llmConfigStatus"', html)
        self.assertIn('<option value="zhipu">智谱 GLM</option>', html)
        self.assertIn("大模型分析", html)

    def test_run_challenge_payload_can_enable_llm_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge({"challenge_id": "llm-web-run", "category": "misc"})
            captured = {}

            class FakeManager:
                def __init__(self, notebook, config):
                    captured["config"] = config

                def run_challenge(self, challenge_id: str):
                    return {"status": "ok", "challenge_id": challenge_id}

            with patch("forgeflag.webapp.Manager", FakeManager):
                summary = handler_cls.handle_run_challenge(
                    "llm-web-run",
                    {
                        "llm_enabled": True,
                        "llm_provider": "openai",
                        "llm_model": "gpt-4.1",
                        "llm_api_key": "sk-web-ui",
                        "llm_base_url": "https://api.openai.com/v1",
                        "llm_timeout_seconds": 9,
                    },
                )

        self.assertEqual(summary["status"], "ok")
        llm_config = captured["config"].llm_config
        self.assertTrue(llm_config.enabled)
        self.assertEqual(llm_config.provider, "openai")
        self.assertEqual(llm_config.model, "gpt-4.1")
        self.assertEqual(llm_config.api_key, "sk-web-ui")
        self.assertEqual(llm_config.timeout_seconds, 9)

    def test_run_challenge_payload_can_enable_zhipu_glm_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge({"challenge_id": "glm-web-run", "category": "misc"})
            captured = {}

            class FakeManager:
                def __init__(self, notebook, config):
                    captured["config"] = config

                def run_challenge(self, challenge_id: str):
                    return {"status": "ok", "challenge_id": challenge_id}

            with patch("forgeflag.webapp.Manager", FakeManager):
                handler_cls.handle_run_challenge(
                    "glm-web-run",
                    {
                        "llm_enabled": True,
                        "llm_provider": "zhipu",
                        "llm_model": "glm-5.1",
                        "llm_api_key": "zhipu-web-ui",
                    },
                )

        llm_config = captured["config"].llm_config
        self.assertTrue(llm_config.enabled)
        self.assertEqual(llm_config.provider, "zhipu")
        self.assertEqual(llm_config.model, "glm-5.1")
        self.assertEqual(llm_config.api_key, "zhipu-web-ui")
        self.assertEqual(llm_config.base_url, "https://open.bigmodel.cn/api/paas/v4")

    def test_zhipu_web_config_defaults_to_latest_model_when_blank(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge({"challenge_id": "glm-default-web-run", "category": "misc"})
            captured = {}

            class FakeManager:
                def __init__(self, notebook, config):
                    captured["config"] = config

                def run_challenge(self, challenge_id: str):
                    return {"status": "ok", "challenge_id": challenge_id}

            with patch("forgeflag.webapp.Manager", FakeManager), patch(
                "forgeflag.webapp.LLMConfig.from_env", return_value=LLMConfig(provider="disabled")
            ):
                handler_cls.handle_run_challenge(
                    "glm-default-web-run",
                    {
                        "llm_enabled": True,
                        "llm_provider": "zhipu",
                        "llm_api_key": "zhipu-web-ui",
                    },
                )

        llm_config = captured["config"].llm_config
        self.assertEqual(llm_config.provider, "zhipu")
        self.assertEqual(llm_config.model, "glm-5.1")

    def test_llm_test_endpoint_uses_runtime_config_without_returning_key(self) -> None:
        class FakeProvider:
            name = "zhipu"
            model = "glm-5.1"
            enabled = True

            def generate(self, instructions: str, prompt: str):
                from forgeflag.llm import LLMResponse

                return LLMResponse(content="GLM test ok", raw={"request_id": "fake"})

        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        with patch("forgeflag.webapp.build_llm_provider", return_value=FakeProvider()):
            response = handler_cls.handle_test_llm(
                {
                    "llm_enabled": True,
                    "llm_provider": "zhipu",
                    "llm_model": "glm-5.1",
                    "llm_api_key": "sensitive-token",
                }
            )

        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["provider"], "zhipu")
        self.assertEqual(response["model"], "glm-5.1")
        self.assertEqual(response["content_sample"], "GLM test ok")
        self.assertNotIn("api_key", response)
        self.assertNotIn("sensitive-token", json.dumps(response))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def test_index_contains_category_workspace_controls(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('id="categoryFilters"', html)
        self.assertIn("分类工作台", html)
        self.assertIn("categoryCounts", html)
        self.assertIn('data-tab="catalog"', html)
        self.assertIn('data-tab="artifacts"', html)

    def test_index_renders_human_readable_result_tabs(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('class="result-view"', html)
        self.assertIn("function renderSummary", html)
        self.assertIn("function renderFindings", html)
        self.assertIn("function renderReport", html)
        self.assertIn("推荐 CTF 工具目录", html)
        self.assertIn("查看原始 JSON", html)

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
                        "llm_model": "glm-4.7",
                        "llm_api_key": "zhipu-web-ui",
                    },
                )

        llm_config = captured["config"].llm_config
        self.assertTrue(llm_config.enabled)
        self.assertEqual(llm_config.provider, "zhipu")
        self.assertEqual(llm_config.model, "glm-4.7")
        self.assertEqual(llm_config.api_key, "zhipu-web-ui")
        self.assertEqual(llm_config.base_url, "https://open.bigmodel.cn/api/paas/v4")

    def test_llm_test_endpoint_uses_runtime_config_without_returning_key(self) -> None:
        class FakeProvider:
            name = "zhipu"
            model = "glm-4.7"
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
                    "llm_model": "glm-4.7",
                    "llm_api_key": "sensitive-token",
                }
            )

        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["provider"], "zhipu")
        self.assertEqual(response["model"], "glm-4.7")
        self.assertEqual(response["content_sample"], "GLM test ok")
        self.assertNotIn("api_key", response)
        self.assertNotIn("sensitive-token", json.dumps(response))


if __name__ == "__main__":
    unittest.main()

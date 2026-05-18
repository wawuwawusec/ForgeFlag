from __future__ import annotations

import base64
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

    def test_index_contains_llm_runtime_controls(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('id="llmEnabled"', html)
        self.assertIn('id="llmApiKey"', html)
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


if __name__ == "__main__":
    unittest.main()

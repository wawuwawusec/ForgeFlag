from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import Finding, LLMConfig
from forgeflag.webapp import create_handler
from forgeflag.platform_utils import script_invocation


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

    def test_create_challenge_payload_generates_missing_challenge_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)

            response = handler_cls.handle_create_challenge({"category": "crypto", "title": "RSA Warmup!!"})
            challenge = handler_cls.notebook.get_challenge(response["challenge_id"])

        self.assertRegex(response["challenge_id"], r"^crypto-\d{8}-\d{6}-rsa-warmup$")
        self.assertEqual(challenge.challenge_id, response["challenge_id"])
        self.assertEqual(challenge.title, "RSA Warmup!!")

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

    def test_summary_endpoint_returns_not_found_for_missing_challenge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)

            payload = handler_cls.handle_summary("unknown-unsaved-challenge")

        self.assertEqual(payload["challenge_id"], "unknown-unsaved-challenge")
        self.assertEqual(payload["status"], "not_found")
        self.assertEqual(payload["proof_status"], "not_found")
        self.assertFalse(payload["proof"]["verified"])

    def test_report_endpoint_builds_writeup_for_no_flag_solver_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge(
                {
                    "challenge_id": "webui-gcm-guidance",
                    "category": "crypto",
                    "title": "GCM nonce reuse",
                }
            )
            handler_cls.notebook.add_finding(
                Finding(
                    challenge_id="webui-gcm-guidance",
                    solver="CryptoSolver",
                    finding="Identified crypto primitive misuse pattern",
                    evidence={
                        "pattern": "aes_gcm_nonce_reuse",
                        "source_lines": ["AES-GCM nonce reused across ciphertext/tag pairs"],
                    },
                    confidence=0.72,
                    next_action="Collect nonce, AAD, ciphertexts, and tags; solve GHASH equations.",
                )
            )
            handler_cls.notebook.record_run(
                "webui-gcm-guidance",
                "completed",
                {
                    "challenge_id": "webui-gcm-guidance",
                    "status": "completed",
                    "accepted_flags": [],
                    "rejected_flags": [],
                },
            )

            payload = handler_cls.handle_report("webui-gcm-guidance")

        self.assertEqual(payload["challenge_id"], "webui-gcm-guidance")
        self.assertEqual(payload["flags"], [])
        self.assertIn("writeup", payload)
        self.assertEqual(payload["writeup"]["solve_script"]["filename"], "solve_webui_gcm_guidance.py")
        self.assertIn("AES-GCM nonce reuse", payload["writeup"]["solve_script"]["content"])

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

    def test_challenge_list_surfaces_pwn_proof_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge({"challenge_id": "webui-pwn-plan", "category": "pwn"})
            handler_cls.notebook.record_run(
                "webui-pwn-plan",
                "exploit_plan",
                {
                    "challenge_id": "webui-pwn-plan",
                    "status": "exploit_plan",
                    "proof_status": "exploit_plan",
                    "proof": {
                        "label": "Exploit plan only",
                        "verified": False,
                        "summary": "Exploit plan exists but no replay transcript has verified shell, command execution, or flag retrieval.",
                    },
                    "accepted_flags": [],
                    "rejected_flags": [],
                },
            )

            rows = handler_cls.handle_list_challenges()

        row = next(item for item in rows if item["challenge_id"] == "webui-pwn-plan")
        self.assertEqual(row["latest_status"], "exploit_plan")
        self.assertEqual(row["proof_status"], "exploit_plan")
        self.assertEqual(row["proof"]["label"], "Exploit plan only")
        self.assertFalse(row["proof"]["verified"])

    def test_legacy_pwn_completed_run_derives_proof_status_from_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            handler_cls = create_handler(db)
            handler_cls.handle_create_challenge({"challenge_id": "webui-legacy-pwn", "category": "pwn"})
            handler_cls.notebook.add_finding(
                Finding(
                    challenge_id="webui-legacy-pwn",
                    solver="PwnSolver",
                    finding="Analyzed pwn binary artifact",
                    evidence={"exploit_plan": {"workflow": "ftp_heap_format_string"}},
                    confidence=0.6,
                    next_action="Replay exploit harness.",
                )
            )
            handler_cls.notebook.record_run(
                "webui-legacy-pwn",
                "completed",
                {
                    "challenge_id": "webui-legacy-pwn",
                    "status": "completed",
                    "accepted_flags": [],
                    "rejected_flags": [],
                },
            )

            summary = handler_cls.handle_summary("webui-legacy-pwn")
            rows = handler_cls.handle_list_challenges()

        row = next(item for item in rows if item["challenge_id"] == "webui-legacy-pwn")
        self.assertEqual(summary["status"], "exploit_plan")
        self.assertEqual(summary["proof_status"], "exploit_plan")
        self.assertEqual(row["latest_status"], "exploit_plan")
        self.assertEqual(row["proof"]["label"], "Exploit plan only")

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
        self.assertIn("function reconcileSelectedChallenge", html)
        self.assertIn("reconcileSelectedChallenge(challenges);", html)
        self.assertIn("function draftChallengeSummary", html)
        self.assertIn("当前 ID 尚未保存", html)
        self.assertIn("请先保存题目或从列表选择已有题目", html)
        self.assertIn("openChallengeGroups", html)
        self.assertIn("state.openChallengeGroups[category]", html)
        self.assertIn('details.addEventListener("toggle"', html)
        self.assertIn("const shouldOpen = groupOpenState(category, selectedInGroup)", html)
        self.assertIn("function statusLabel", html)
        self.assertIn("function proofLabel", html)
        self.assertIn("function isSolvedStatus", html)
        self.assertIn('status === "exploit_verified"', html)
        self.assertIn("proof_status", html)
        self.assertIn("exploit_verified", html)
        self.assertIn("exploit_plan", html)
        self.assertIn("function tagChips", html)
        self.assertIn("accepted_flag_count", html)
        self.assertIn("category-group", html)
        self.assertIn('data-tab="catalog"', html)
        self.assertIn('data-tab="artifacts"', html)
        self.assertIn('id="deleteBtn"', html)
        self.assertIn('id="clearBtn"', html)
        self.assertIn('id="generateIdBtn"', html)
        self.assertIn("function generateChallengeId", html)
        self.assertIn("function ensureChallengeId", html)
        self.assertIn("idTouched", html)
        self.assertIn("自动生成", html)
        self.assertIn("function deleteSelectedChallenge", html)
        self.assertIn("function clearChallenges", html)
        self.assertIn("function setRunState", html)
        self.assertIn('id="actionToast"', html)
        self.assertIn("function setButtonBusy", html)
        self.assertIn("function flashButton", html)
        self.assertIn("async function withButtonFeedback", html)
        self.assertIn("button.is-busy", html)
        self.assertIn('state.activeStatus = "all";', html)

    def test_index_renders_human_readable_result_tabs(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('class="result-view"', html)
        self.assertIn("function renderSummary", html)
        self.assertIn("证明状态", html)
        self.assertIn("proof && proof.summary", html)
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
        self.assertIn("Exploit 脚本", html)
        self.assertIn("Solve 脚本", html)
        self.assertIn("writeup-code", html)
        self.assertNotIn('const writeupSectionOrder = ["结论"', html)
        self.assertNotIn("Write-up Markdown", html)
        self.assertNotIn("关键证据", html)
        self.assertIn("查看调试 JSON", html)
        self.assertIn("推荐 CTF 工具目录", html)
        self.assertIn("推荐分析提示", html)
        self.assertIn("traffic-data-uri-image", html)
        self.assertNotIn('show(challenges, "raw");', html)
        self.assertIn('show({}, "summary");', html)
        self.assertIn("forensics-bmp-quickstego-braille", html)
        self.assertIn("Docker install", html)
        self.assertIn("host/docker", html)
        self.assertIn("function renderToolGroups", html)
        self.assertIn("tool-group", html)
        self.assertIn("function renderAntSwordEvidence", html)
        self.assertIn("AntSword 流量恢复", html)
        self.assertIn("查看调试 JSON", html)
        self.assertIn("function loadLatestSummary", html)
        self.assertIn("/summary", html)
        self.assertIn('data-tab="benchmark"', html)
        self.assertIn('data-tab="health"', html)
        self.assertIn("function renderBenchmark", html)
        self.assertIn("function renderSystemHealth", html)
        self.assertIn("function renderBenchmarkReadiness", html)
        self.assertIn("function renderBenchmarkHistory", html)
        self.assertIn("/api/capability-benchmark", html)
        self.assertIn("/api/system-health", html)
        self.assertIn("商业化健康检查", html)
        self.assertIn("Commercial readiness", html)
        self.assertIn("Diagnostic bundle", html)
        self.assertIn("Support summary", html)
        self.assertIn("实战就绪度", html)
        self.assertIn("角色 Backlog", html)
        self.assertIn("Benchmark history", html)
        self.assertIn("最新能力评测", html)

    def test_index_uses_modern_workbench_shell(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn("ForgeFlag Workbench", html)
        self.assertIn("Challenge queue", html)
        self.assertIn("Evidence rail", html)
        self.assertIn("Run control", html)
        self.assertIn('class="app-shell"', html)
        self.assertIn('class="topbar"', html)
        self.assertIn('class="sidebar-panel queue-column"', html)
        self.assertIn('class="content-panel mission-column"', html)
        self.assertIn("run-card", html)
        self.assertIn("--surface-raised", html)
        self.assertIn("--shadow-soft", html)
        self.assertIn("@media (max-width: 1280px)", html)
        self.assertIn("@media (max-width: 900px)", html)

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
        self.assertIn("分析模式", html)
        self.assertIn("缺失附件/证据", html)
        self.assertIn("人工复现", html)
        self.assertIn("风险提示", html)
        self.assertIn("artifact_requirements", html)
        self.assertIn("blocked_by_missing_artifacts", html)
        self.assertIn("manual_replay_needed", html)
        self.assertIn("risk_notes", html)
        self.assertIn("行动队列缺失证据", html)
        self.assertIn("行动队列人工复现", html)
        self.assertIn("工具摘要", html)
        self.assertIn("SolveTrace", html)
        self.assertIn("function renderActionQueue", html)
        self.assertIn("function renderPostRunCritic", html)
        self.assertIn("/api/agents", html)
        self.assertIn("Agent 身份配置", html)
        self.assertIn("function renderAgentGapCard", html)
        self.assertIn("Gap 卡片", html)
        self.assertIn("负责人角色", html)
        self.assertIn("缺失证据", html)
        self.assertIn("下一步动作", html)
        self.assertIn("团队类型", html)
        self.assertIn("汇报给", html)
        self.assertIn("协作节奏", html)
        self.assertIn("success_metrics", html)
        self.assertIn("deliverables", html)
        self.assertIn("Subagent 工作机制", html)
        self.assertIn("429 熔断", html)
        self.assertIn("function renderAgentRoster", html)

    def test_agents_endpoint_exposes_subagent_roster(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        payload = handler_cls.handle_agents()

        self.assertEqual(payload["coordinator"]["id"], "forgeflag-manager")
        self.assertEqual(payload["coordinator"]["team_type"], "manager")
        self.assertIn("held-out pass rate", payload["coordinator"]["success_metrics"])
        self.assertEqual(payload["subagent_work_policy"]["mode"], "conservative")
        self.assertEqual(payload["subagent_work_policy"]["max_parallel"], 1)
        self.assertIn("WebExploitAgent", {row["name"] for row in payload["agents"]})
        self.assertIn("TrafficAgent", {row["name"] for row in payload["agents"]})
        self.assertIn("BrowserPlayerQAAgent", {row["name"] for row in payload["agents"]})
        traffic_agent = next(row for row in payload["agents"] if row["name"] == "TrafficAgent")
        self.assertEqual(traffic_agent["team_type"], "stream-aligned")
        self.assertEqual(traffic_agent["reports_to"], "forgeflag-manager")

    def test_project_catalog_endpoint_lists_recommended_projects(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        payload = handler_cls.handle_project_catalog()

        self.assertIn("pwntools", {row["name"] for row in payload})
        self.assertIn("CyberChef", {row["name"] for row in payload})

    def test_analysis_hints_endpoint_filters_recommended_patterns(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        payload = handler_cls.handle_analysis_hints("traffic")

        self.assertTrue(payload)
        self.assertTrue(all(row["category"] == "traffic" for row in payload))
        self.assertIn("traffic-http-webshell-delimited-flag", {row["id"] for row in payload})
        self.assertIn("traffic-data-uri-image", {row["id"] for row in payload})

        crypto_payload = handler_cls.handle_analysis_hints("crypto")
        self.assertIn("crypto-python-random-prime-offset", {row["id"] for row in crypto_payload})

        web_payload = handler_cls.handle_analysis_hints("web")
        self.assertIn("web-php-pack-procfs", {row["id"] for row in web_payload})
        self.assertIn("web-loopback-alias-ssrf", {row["id"] for row in web_payload})
        self.assertIn("web-python-class-pollution", {row["id"] for row in web_payload})
        self.assertIn("web-h3-h1-request-smuggling", {row["id"] for row in web_payload})

        pwn_payload = handler_cls.handle_analysis_hints("pwn")
        self.assertIn("pwn-ret2win-escaped-bytes", {row["id"] for row in pwn_payload})
        self.assertIn("pwn-int16-hp-overflow", {row["id"] for row in pwn_payload})
        self.assertIn("pwn-heap-off-by-one-overlap", {row["id"] for row in pwn_payload})
        self.assertIn("pwn-suffix-retaddr-alignment", {row["id"] for row in pwn_payload})
        self.assertIn("pwn-uaf-uninitialized-list-next", {row["id"] for row in pwn_payload})
        self.assertIn("pwn-ret2vdso-vm-artifact-check", {row["id"] for row in pwn_payload})

        reverse_payload = handler_cls.handle_analysis_hints("reverse")
        self.assertIn("reverse-pe-stack-xor-key-check", {row["id"] for row in reverse_payload})

    def test_tools_endpoint_groups_wrappers_and_recommended_catalog(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        payload = handler_cls.handle_tools()

        self.assertIn("wrappers", payload)
        self.assertIn("catalog", payload)
        self.assertIn("analysis_hints", payload)
        self.assertIn("docker_profiles", payload)
        self.assertIn("counts", payload)
        self.assertIn("host_wrappers", payload["counts"])
        self.assertIn("docker_wrappers", payload["counts"])
        self.assertIn("missing_wrappers", payload["counts"])
        self.assertIn("docker_profiles", payload["counts"])
        self.assertEqual(
            payload["counts"]["wrappers"],
            payload["counts"]["host_wrappers"] + payload["counts"]["docker_wrappers"] + payload["counts"]["missing_wrappers"],
        )
        self.assertEqual(payload["runtime_smoke"]["docker_build_command"], script_invocation("forgeflag-control", "docker-build"))
        self.assertEqual(payload["runtime_smoke"]["docker_smoke_command"], script_invocation("forgeflag-control", "docker-smoke"))
        self.assertIn("file", {row["name"] for row in payload["wrappers"]})
        hint_ids = {row["id"] for row in payload["analysis_hints"]}
        self.assertIn("traffic-data-uri-image", hint_ids)
        self.assertIn("forensics-registry-wifi", hint_ids)
        self.assertIn("forensics-vmdk-bitlocker-fvestats", hint_ids)
        self.assertIn("forensics-bmp-quickstego-braille", hint_ids)
        self.assertIn("web-php-pack-procfs", hint_ids)
        self.assertIn("web-loopback-alias-ssrf", hint_ids)
        self.assertIn("web-python-class-pollution", hint_ids)
        self.assertIn("web-h3-h1-request-smuggling", hint_ids)
        self.assertIn("pwn-ret2win-escaped-bytes", hint_ids)
        self.assertIn("pwn-int16-hp-overflow", hint_ids)
        self.assertIn("pwn-heap-off-by-one-overlap", hint_ids)
        self.assertIn("reverse-pe-stack-xor-key-check", hint_ids)
        self.assertIn("pwn-suffix-retaddr-alignment", hint_ids)
        self.assertIn("pwn-uaf-uninitialized-list-next", hint_ids)
        self.assertIn("pwn-ret2vdso-vm-artifact-check", hint_ids)
        profile_names = {row["name"] for row in payload["docker_profiles"]}
        self.assertIn("forgeflag-volatility", profile_names)
        self.assertIn("forgeflag-sagemath", profile_names)
        self.assertIn("forgeflag-ghidra-headless", profile_names)
        self.assertTrue(all("docker build" in row["build_command"] for row in payload["docker_profiles"]))
        self.assertIn("Burp Suite Community", {row["name"] for row in payload["catalog"]})

    def test_tools_page_renders_heavyweight_profile_section(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn("Heavyweight profiles", html)
        self.assertIn("docker_profiles", html)

    def test_capability_benchmark_endpoint_reads_latest_scorecard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / ".forgeflag" / "notebook.sqlite"
            db.parent.mkdir(parents=True)
            latest = db.parent / "capability-benchmark-latest.json"
            latest.write_text(
                json.dumps(
                    {
                        "benchmark": "forgeflag-capability",
                        "totals": {"cases": 2, "passed": 1, "failed": 1},
                        "rates": {"case_pass_rate": 0.5},
                        "readiness": {
                            "status": "blocked",
                            "summary": "Failures remain.",
                            "coverage": {"hard_evidence": True, "ui_flow": False, "heldout_manifest": True},
                            "warnings": ["1 failed case needs replay."],
                            "next_actions": ["Run browser-smoke."],
                        },
                        "roles": {"WebExploitAgent": {"total": 1, "passed": 0}},
                        "backlog": [
                            {
                                "challenge_id": "heldout-web",
                                "category": "web",
                                "suite": "manifest:heldout",
                                "owner_roles": ["WebExploitAgent"],
                                "next_action": "replay heldout-web",
                            }
                        ],
                        "backlog_by_role": {"WebExploitAgent": {"total": 1, "categories": {"web": 1}, "suites": {"manifest:heldout": 1}}},
                    }
                ),
                encoding="utf-8",
            )
            history = db.parent / "capability-benchmark-history.jsonl"
            history.write_text(
                "\n".join(
                    [
                        json.dumps({"recorded_at": "2026-06-13T10:00:00Z", "scorecard": {"totals": {"cases": 1, "passed": 1, "failed": 0}}}),
                        json.dumps({"recorded_at": "2026-06-13T11:00:00Z", "scorecard": {"totals": {"cases": 2, "passed": 1, "failed": 1}}}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            handler_cls = create_handler(db)

            payload = handler_cls.handle_capability_benchmark()

        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["scorecard"]["totals"]["failed"], 1)
        self.assertEqual(payload["scorecard"]["readiness"]["status"], "blocked")
        self.assertEqual(payload["scorecard"]["backlog"][0]["challenge_id"], "heldout-web")
        self.assertEqual(len(payload["history"]), 2)
        self.assertEqual(payload["history"][-1]["scorecard"]["totals"]["failed"], 1)
        self.assertIn(script_invocation("forgeflag-capability-benchmark", "--output"), payload["refresh_command"])
        self.assertIn("--history", payload["refresh_command"])

    def test_capability_benchmark_endpoint_handles_missing_scorecard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / ".forgeflag" / "notebook.sqlite"
            db.parent.mkdir(parents=True)
            handler_cls = create_handler(db)

            payload = handler_cls.handle_capability_benchmark()

        self.assertEqual(payload["status"], "missing")
        self.assertIn("capability-benchmark-latest.json", payload["path"])
        self.assertIn(script_invocation("forgeflag-capability-benchmark", "--output"), payload["refresh_command"])
        self.assertEqual(payload["history"], [])

    def test_system_health_endpoint_reports_ready_when_commercial_gate_is_green(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / ".forgeflag" / "notebook.sqlite"
            db.parent.mkdir(parents=True)
            latest = db.parent / "capability-benchmark-latest.json"
            latest.write_text(
                json.dumps(
                    {
                        "totals": {"cases": 3, "passed": 3, "failed": 0},
                        "readiness": {
                            "status": "ready",
                            "summary": "Release gate is green.",
                            "coverage": {"hard_evidence": True, "ui_flow": True, "heldout_manifest": True},
                        },
                    }
                ),
                encoding="utf-8",
            )
            handler_cls = create_handler(db)
            wrappers = [
                {"name": "file", "available": True, "source": "host"},
                {"name": "tshark", "available": True, "source": "host"},
            ]
            profiles = [{"name": "forgeflag-sagemath", "available": True}]

            with (
                patch("forgeflag.health.ToolRunner.inventory", return_value=wrappers),
                patch("forgeflag.health.docker_profile_inventory", return_value=profiles),
                patch(
                    "forgeflag.health.LLMConfig.from_env",
                    return_value=LLMConfig(provider="openai", model="gpt-4.1", api_key="sk-test"),
                ),
            ):
                payload = handler_cls.handle_system_health()

        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["commercial_readiness"]["status"], "ready")
        self.assertEqual(payload["counts"]["errors"], 0)
        self.assertEqual(payload["counts"]["warnings"], 0)
        self.assertEqual(
            {check["id"] for check in payload["checks"]},
            {"notebook", "python_dependencies", "tools", "docker_profiles", "benchmark", "llm"},
        )
        self.assertIn("commercial-ready", payload["summary"])
        self.assertIn("diagnostic_bundle", payload)
        self.assertEqual(payload["diagnostic_bundle"]["bundle_version"], 1)
        self.assertEqual(payload["diagnostic_bundle"]["readiness"]["status"], "ready")
        self.assertEqual(payload["diagnostic_bundle"]["llm"]["provider"], "openai")
        self.assertEqual(payload["diagnostic_bundle"]["llm"]["api_key_configured"], True)
        self.assertNotIn("sk-test", json.dumps(payload, ensure_ascii=False))
        self.assertTrue(payload["diagnostic_bundle"]["support_summary"])

    def test_system_health_endpoint_surfaces_blockers_and_next_actions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / ".forgeflag" / "notebook.sqlite"
            db.parent.mkdir(parents=True)
            handler_cls = create_handler(db)
            wrappers = [
                {"name": "file", "available": True, "source": "host"},
                {"name": "tshark", "available": False, "source": "missing"},
            ]
            profiles = [{"name": "forgeflag-ghidra-headless", "available": False}]

            with (
                patch("forgeflag.health.ToolRunner.inventory", return_value=wrappers),
                patch("forgeflag.health.docker_profile_inventory", return_value=profiles),
                patch("forgeflag.health.LLMConfig.from_env", return_value=LLMConfig(provider="disabled")),
            ):
                payload = handler_cls.handle_system_health()

        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["commercial_readiness"]["status"], "blocked")
        self.assertGreaterEqual(payload["counts"]["errors"], 1)
        self.assertGreaterEqual(payload["counts"]["warnings"], 1)
        tool_check = next(check for check in payload["checks"] if check["id"] == "tools")
        benchmark_check = next(check for check in payload["checks"] if check["id"] == "benchmark")
        llm_check = next(check for check in payload["checks"] if check["id"] == "llm")
        self.assertEqual(tool_check["status"], "error")
        self.assertIn("missing wrappers: 1", tool_check["summary"])
        self.assertEqual(benchmark_check["status"], "warning")
        self.assertEqual(llm_check["status"], "warning")
        self.assertIn(script_invocation("forgeflag-tool-smoke"), payload["next_actions"])
        self.assertIn("forgeflag-capability-benchmark", " ".join(payload["next_actions"]))

    def test_system_health_distinguishes_core_ready_from_optional_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / ".forgeflag" / "notebook.sqlite"
            db.parent.mkdir(parents=True)
            latest = db.parent / "capability-benchmark-latest.json"
            latest.write_text(
                json.dumps(
                    {
                        "totals": {"cases": 52, "passed": 52, "failed": 0},
                        "readiness": {
                            "status": "ready",
                            "summary": "Release gate is green.",
                            "coverage": {"hard_evidence": True, "ui_flow": True, "heldout_manifest": True},
                        },
                    }
                ),
                encoding="utf-8",
            )
            handler_cls = create_handler(db)
            wrappers = [
                {"name": "file", "available": True, "source": "host"},
                {"name": "tshark", "available": True, "source": "host"},
            ]
            profiles = [{"name": "forgeflag-sagemath", "available": False}]

            with (
                patch("forgeflag.health.ToolRunner.inventory", return_value=wrappers),
                patch("forgeflag.health.docker_profile_inventory", return_value=profiles),
                patch("forgeflag.health.LLMConfig.from_env", return_value=LLMConfig(provider="disabled")),
            ):
                payload = handler_cls.handle_system_health()

        self.assertEqual(payload["status"], "limited")
        self.assertEqual(payload["commercial_readiness"]["status"], "limited")
        self.assertEqual(payload["core_readiness"]["status"], "ready")
        self.assertEqual(payload["core_readiness"]["blocking_checks"], [])
        self.assertEqual(payload["core_readiness"]["warning_checks"], [])
        self.assertIn("core-ready", payload["core_readiness"]["summary"])
        self.assertEqual(payload["diagnostic_bundle"]["core_readiness"]["status"], "ready")

    def test_run_button_loads_findings_after_summary(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('await loadTab("findings")', html)

    def test_index_contains_llm_runtime_controls(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('id="llmEnabled"', html)
        self.assertIn('id="llmApiKey"', html)
        self.assertIn('id="llmSavedKeySelect"', html)
        self.assertIn('id="llmSaveConfig"', html)
        self.assertIn('id="llmClearSavedKeys"', html)
        self.assertIn('id="llmTestBtn"', html)
        self.assertNotIn('id="llmRememberKey"', html)
        self.assertIn('id="llmConfigStatus"', html)
        self.assertIn('<option value="zhipu">智谱 GLM</option>', html)
        self.assertIn("大模型分析", html)
        self.assertIn("API Key 会保存到本浏览器", html)
        self.assertIn("llm_api_key: payload.llm_api_key", html)
        self.assertIn('$("llmApiKey").value = saved.llm_api_key || "";', html)
        self.assertIn("配置已保存到本浏览器（含 Key）", html)
        self.assertNotIn("delete saved.llm_api_key", html)
        self.assertIn("function ensureLLMReady", html)
        self.assertIn("function renderLLMStatus", html)
        self.assertIn("大模型运行状态", html)
        self.assertIn("LLM 请求失败", html)
        self.assertIn("if (!ensureLLMReady()) return false;", html)
        self.assertIn("if (!ensureLLMReady()) return {status:\"blocked\", reason:\"missing_llm_config\"};", html)
        self.assertIn("请先填写并保存大模型 API Key", html)
        self.assertIn("function upsertSavedLLMKey", html)
        self.assertIn("function renderSavedLLMKeyOptions", html)
        self.assertIn("function applySavedLLMKey", html)
        self.assertIn("function clearSavedLLMKeys", html)
        self.assertIn("crypto-rsa-modular-low-exponent-root", html)
        self.assertIn("crypto-lfsr-berlekamp-massey", html)
        self.assertIn("crypto-prng-stream-replay", html)
        self.assertIn("llm_saved_keys: upsertSavedLLMKey(previous, payload)", html)
        self.assertIn("option.value = String(index);", html)
        self.assertIn("maskLLMKey", html)
        self.assertIn('$("llmSavedKeySelect").onchange', html)
        self.assertIn('$("llmClearSavedKeys").onclick', html)
        self.assertIn("选择已保存 Key", html)
        self.assertIn('<form class="llm-settings" id="llmSettings" hidden autocomplete="off" onsubmit="return false;">', html)
        self.assertIn('id="llmSaveConfig" type="button"', html)
        self.assertIn('id="llmClearSavedKeys" type="button"', html)
        self.assertIn('id="llmTestBtn" type="button"', html)

    def test_health_tab_renders_core_readiness_separately(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn("core_readiness", html)
        self.assertIn("Core solving readiness", html)
        self.assertIn("核心解题能力", html)

    def test_index_uses_hacker_ops_workbench_theme(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn("data-theme=\"forgeflag-hacker-ops\"", html)
        self.assertIn("signal-field", html)
        self.assertIn("ops-orbit", html)
        self.assertIn("Mission console", html)
        self.assertIn("Evidence rail", html)
        self.assertIn("--matrix-green", html)
        self.assertIn("--phosphor", html)
        self.assertIn("repeating-linear-gradient(90deg, rgba(0, 255, 171, .07) 0 1px, transparent 1px 120px)", html)
        self.assertNotIn("data-theme=\"forgeflag-light-future\"", html)
        self.assertNotIn("linear-gradient(135deg, #f8fbff 0%, #eef8f7 46%, #f6f3ff 100%)", html)
        self.assertIn('activeButton.scrollIntoView({block:"nearest", inline:"center"});', html)

    def test_index_uses_three_zone_commercial_console_layout(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('class="sidebar-panel queue-column"', html)
        self.assertIn('class="content-panel mission-column"', html)
        self.assertIn('class="evidence-rail"', html)
        self.assertIn("Challenge queue", html)
        self.assertIn("Evidence rail", html)
        self.assertIn("grid-template-columns: minmax(260px, 320px) minmax(520px, 1fr) minmax(300px, 380px)", html)
        self.assertIn('body { margin: 0; min-height: 100vh; height: 100vh; overflow: hidden; display: grid; grid-template-rows: auto minmax(0, 1fr); font-size: 14px;', html)
        self.assertIn("height: 100%", html)
        self.assertIn(".app-shell {", html)
        self.assertIn("overflow: hidden", html)
        self.assertIn(".content-panel { display: grid; grid-template-rows: minmax(200px, 34vh) minmax(320px, 1fr);", html)
        self.assertIn(".run-panel { display: grid; gap: 12px; padding: 16px; min-height: 0; overflow: auto;", html)
        self.assertIn('class="workspace-stack" aria-label="Challenge analysis workspace"', html)
        self.assertIn(".workspace-stack { min-height: 0; overflow: hidden; display: grid; grid-template-rows: auto minmax(0, 1fr);", html)
        self.assertIn(".workspace-stack .tabs { position: sticky; top: 0; z-index: 2;", html)
        self.assertIn(".tabs button { background: transparent; color: #a9bbc8; border-color: transparent; border-radius: 6px; white-space: nowrap; box-shadow: none; font-size: 14px;", html)
        self.assertIn(".result-view { display: flex; flex-direction: column; gap: 12px; min-height: 0; overflow: auto;", html)
        self.assertIn(".workspace-stack .result-view { padding: 12px; min-height: 0; overflow: auto;", html)
        self.assertIn(".result-card { position: relative; overflow: visible;", html)
        self.assertIn("flex: 0 0 auto;", html)
        self.assertIn(".queue-workspace { height: 100%; overflow: auto;", html)
        self.assertIn(".panel-section.queue-workspace { min-height: 0; overflow: auto;", html)
        self.assertIn("@media (max-width: 1280px) { .app-shell { grid-template-columns: minmax(220px, 260px) minmax(420px, 1fr) minmax(240px, 300px);", html)
        self.assertIn("@media (max-width: 900px) { body { height: auto; overflow: visible; display: block; }", html)
        self.assertIn("body { height: auto; overflow: visible; display: block; }", html)
        self.assertIn(".panel-section.queue-workspace { height: min(640px, calc(100vh - 96px)); }", html)
        self.assertIn(".evidence-rail { min-width: 0; overflow: auto;", html)

    def test_web_handler_has_favicon_route(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        source = handler_cls.do_GET.__code__.co_consts

        self.assertIn("/favicon.ico", source)

    def test_index_contains_pwn_environment_helper(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn('id="pwnEnvironmentPanel"', html)
        self.assertIn("Pwn 本地环境", html)
        self.assertIn("function renderPwnEnvironmentPanel", html)
        self.assertIn("function selectedChallenge", html)
        self.assertIn("function shellQuote", html)
        self.assertIn("forgeflag-ctf:latest", html)
        self.assertIn("--platform linux/amd64", html)
        self.assertIn("在 ForgeFlag 项目根目录执行", html)
        self.assertNotIn("cd /Users/", html)
        self.assertIn("socat TCP-LISTEN:31337,reuseaddr,fork EXEC:", html)
        self.assertIn("tcp://127.0.0.1:31337", html)
        self.assertIn("Active probe", html)
        self.assertIn("renderPwnEnvironmentPanel();", html)
        self.assertIn('].join("\\n");', html)
        self.assertNotIn('].join("\\\\n");', html)
        self.assertIn("function copyTextFromElement", html)
        self.assertIn('data-copy-target="pwnEnterCommand"', html)
        self.assertIn('id="pwnExploitTemplate"', html)
        self.assertIn("pwntools exploit template", html)
        self.assertIn("from pwn import *", html)
        self.assertIn("--remote", html)
        self.assertIn("args.host", html)
        self.assertIn("cyclic_find", html)
        self.assertIn("DEBUG = not args.remote", html)
        self.assertIn("TEST_FLAG = b'flag{forgeflag_local_pwn_test}'", html)
        self.assertIn("def debugf():", html)
        self.assertIn("def Add(size, content):", html)
        self.assertIn("def proof():", html)
        self.assertIn("cat flag", html)
        self.assertIn("local test flag", html)
        self.assertIn("function downloadExploitTemplate", html)
        self.assertIn('id="pwnDownloadExploitBtn"', html)
        self.assertIn("下载 exploit.py", html)
        self.assertIn("new Blob", html)
        self.assertIn("exploit.py", html)

    def test_index_renders_classical_crypto_evidence_summary(self) -> None:
        handler_cls = create_handler(Path("/tmp/forgeflag-test.sqlite"))

        html = handler_cls.render_index()

        self.assertIn("renderClassicalCryptoEvidence", html)
        self.assertIn("renderRsaRecoveryEvidence", html)
        self.assertIn("renderWebRouteEvidence", html)
        self.assertIn("renderWebSourceEvidence", html)
        self.assertIn("renderToolSampleEvidence", html)
        self.assertIn("renderTransformRecipeEvidence", html)
        self.assertIn("renderPwnExploitEvidence", html)
        self.assertIn("renderArchiveImageEvidence", html)
        self.assertIn("renderJpegStegoEvidence", html)
        self.assertIn("rsa_recovery", html)
        self.assertIn("rsa.method", html)
        self.assertIn("single_byte_xor", html)
        self.assertIn("repeating_key_xor", html)
        self.assertIn("followed_urls", html)
        self.assertIn("transform_candidates", html)
        self.assertIn("bug_class_hints", html)
        self.assertIn("source_samples", html)
        self.assertIn("routes_by_attachment", html)
        self.assertIn("tool_samples", html)
        self.assertIn("image_stego", html)
        self.assertIn("lsb_candidates", html)
        self.assertIn("jpeg_stego_tools", html)
        self.assertIn("Pwn 利用路线", html)
        self.assertIn("steghide_info", html)
        self.assertIn("stegseek_crack", html)

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

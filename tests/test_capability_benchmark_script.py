from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from unittest import mock


class CapabilityBenchmarkScriptTest(unittest.TestCase):
    def test_list_mode_describes_suites_metrics_and_manifest_schema(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-capability-benchmark"

        completed = subprocess.run([sys.executable, str(script), "--list"], capture_output=True, check=False, text=True)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["benchmark"], "forgeflag-capability")
        suite_names = {suite["name"] for suite in payload["suites"]}
        self.assertTrue({"smoke", "medium", "hard", "browser-smoke"}.issubset(suite_names))
        self.assertIn("flag_success_rate", payload["metrics"])
        self.assertIn("evidence_score_rate", payload["metrics"])
        self.assertIn("ui_flow_rate", payload["metrics"])
        self.assertIn("role_attribution_coverage", payload["metrics"])
        self.assertIn("role_backlog_count", payload["metrics"])
        self.assertIn("readiness_status", payload["metrics"])
        self.assertIn("manifest_schema", payload)
        self.assertIn("challenge_id", payload["manifest_schema"]["required_case_fields"])

    def test_scorecard_summarizes_api_browser_and_hard_results(self) -> None:
        module = _load_script_module()
        smoke_rows = [
            {"challenge_id": "smoke-web", "category": "web", "ok": True},
            {"challenge_id": "smoke-pwn", "category": "pwn", "ok": False},
        ]
        hard_rows = [
            {"challenge_id": "hard-a", "category": "crypto", "ok": True, "score": 4, "max_score": 4},
            {"challenge_id": "hard-b", "category": "web", "ok": False, "score": 2, "max_score": 5},
        ]
        browser_output = "\n".join(
            [
                "ForgeFlag browser player benchmark: 6/7 passed",
                "Profile results:",
                "- deterministic: 6/7",
                "Category results:",
                "- web: 1/1",
                "- pwn: 0/1",
                "Agent results:",
                "- ChallengeTriageAgent: 6/7",
                "Case results:",
                "- FAIL [pwn/deterministic] browser-pwn expected flag{browser_pwn}",
            ]
        )

        suites = [
            module.summarize_json_rows("smoke", smoke_rows, returncode=1, command=["smoke"]),
            module.summarize_json_rows("hard", hard_rows, returncode=1, command=["hard"]),
            module.summarize_browser_scorecard("browser-smoke", browser_output, returncode=1, command=["browser"]),
        ]
        scorecard = module.build_scorecard(suites)

        self.assertEqual(scorecard["totals"]["cases"], 11)
        self.assertEqual(scorecard["totals"]["passed"], 8)
        self.assertEqual(scorecard["totals"]["failed"], 3)
        self.assertEqual(scorecard["totals"]["hard_score"], 6)
        self.assertEqual(scorecard["totals"]["hard_max_score"], 9)
        self.assertEqual(scorecard["categories"]["pwn"]["passed"], 0)
        self.assertNotIn("deterministic", scorecard["categories"])
        self.assertEqual(scorecard["suites"][2]["ui_passed"], 6)
        self.assertIn("smoke-pwn", scorecard["failures"][0]["challenge_id"])
        self.assertEqual(scorecard["roles"]["WebExploitAgent"]["total"], 3)
        self.assertEqual(scorecard["roles"]["WebExploitAgent"]["passed"], 2)
        self.assertEqual(scorecard["roles"]["BinaryAgent"]["total"], 2)
        self.assertEqual(scorecard["roles"]["BinaryAgent"]["passed"], 0)
        self.assertEqual(scorecard["roles"]["CryptoMathAgent"]["hard_score"], 4)
        self.assertEqual(scorecard["roles"]["CryptoMathAgent"]["hard_max_score"], 4)
        self.assertEqual(scorecard["roles"]["BrowserPlayerQAAgent"]["ui_total"], 7)
        self.assertEqual(scorecard["roles"]["BrowserPlayerQAAgent"]["ui_passed"], 6)
        self.assertIn("BinaryAgent", scorecard["failures"][0]["owner_roles"])
        self.assertEqual(scorecard["backlog"][0]["challenge_id"], "smoke-pwn")
        self.assertIn("BinaryAgent", scorecard["backlog"][0]["owner_roles"])
        self.assertIn("replay", scorecard["backlog"][0]["next_action"])
        self.assertEqual(scorecard["backlog_by_role"]["BinaryAgent"]["total"], 2)
        self.assertEqual(scorecard["backlog_by_role"]["WebExploitAgent"]["total"], 1)
        self.assertEqual(scorecard["readiness"]["status"], "blocked")
        self.assertIn("3 failed", " ".join(scorecard["readiness"]["warnings"]))
        self.assertIn("backlog", " ".join(scorecard["readiness"]["warnings"]))

    def test_scorecard_marks_smoke_only_result_as_limited_not_battle_ready(self) -> None:
        module = _load_script_module()
        smoke_rows = [
            {"challenge_id": "smoke-web", "category": "web", "ok": True},
            {"challenge_id": "smoke-crypto", "category": "crypto", "ok": True},
        ]

        scorecard = module.build_scorecard([module.summarize_json_rows("smoke", smoke_rows, returncode=0, command=["smoke"])])

        self.assertEqual(scorecard["totals"]["failed"], 0)
        self.assertEqual(scorecard["readiness"]["status"], "limited")
        self.assertFalse(scorecard["readiness"]["coverage"]["hard_evidence"])
        self.assertFalse(scorecard["readiness"]["coverage"]["ui_flow"])
        self.assertFalse(scorecard["readiness"]["coverage"]["heldout_manifest"])
        self.assertIn("hard", " ".join(scorecard["readiness"]["next_actions"]))
        self.assertIn("browser", " ".join(scorecard["readiness"]["next_actions"]))
        self.assertIn("held-out", " ".join(scorecard["readiness"]["next_actions"]))

    def test_scorecard_marks_full_clean_result_ready(self) -> None:
        module = _load_script_module()
        hard_rows = [
            {"challenge_id": "hard-crypto", "category": "crypto", "ok": True, "score": 4, "max_score": 4},
        ]
        heldout_rows = [
            {"challenge_id": "heldout-traffic", "category": "traffic", "ok": True, "score": 2, "max_score": 2},
        ]
        browser_output = "\n".join(
            [
                "ForgeFlag browser player benchmark: 1/1 passed",
                "Category results:",
                "- web: 1/1",
                "Case results:",
                "- PASS [web/deterministic] browser-web flag{browser_web}",
            ]
        )

        suites = [
            module.summarize_json_rows("hard", hard_rows, returncode=0, command=["hard"]),
            module.summarize_json_rows("manifest:heldout-platform-manifest", heldout_rows, returncode=0, command=["manifest"]),
            module.summarize_browser_scorecard("browser-smoke", browser_output, returncode=0, command=["browser"]),
        ]
        scorecard = module.build_scorecard(suites)

        self.assertEqual(scorecard["readiness"]["status"], "ready")
        self.assertTrue(scorecard["readiness"]["coverage"]["hard_evidence"])
        self.assertTrue(scorecard["readiness"]["coverage"]["ui_flow"])
        self.assertTrue(scorecard["readiness"]["coverage"]["heldout_manifest"])
        self.assertEqual(scorecard["readiness"]["next_actions"], [])

    def test_manifest_only_skips_default_suites(self) -> None:
        module = _load_script_module()
        manifest = Path(__file__).resolve().parents[1] / ".forgeflag" / "heldout-platform-manifest.json"
        manifest.parent.mkdir(exist_ok=True)
        if not manifest.exists():
            manifest.write_text('{"cases": []}', encoding="utf-8")
        manifest_summary = {
            "name": "manifest:heldout-platform-manifest",
            "kind": "json_rows",
            "command": ["manifest", str(manifest)],
            "returncode": 0,
            "cases": 1,
            "passed": 1,
            "failed": 0,
            "categories": {"crypto": {"passed": 1, "total": 1}},
            "hard_score": 1,
            "hard_max_score": 1,
            "failures": [],
            "stderr": "",
        }

        with (
            mock.patch.object(sys, "argv", ["forgeflag-capability-benchmark", "--manifest-only", "--manifest", str(manifest)]),
            mock.patch.object(module, "run_suite", side_effect=AssertionError("default suites should be skipped")),
            mock.patch.object(module, "run_manifest", return_value=manifest_summary) as run_manifest,
            mock.patch("builtins.print") as print_mock,
        ):
            rc = module.main()

        self.assertEqual(rc, 0)
        run_manifest.assert_called_once()
        printed = json.loads(print_mock.call_args.args[0])
        self.assertEqual(printed["totals"]["cases"], 1)
        self.assertEqual(printed["suites"][0]["name"], "manifest:heldout-platform-manifest")

    def test_manifest_score_rows_include_owner_roles_from_category(self) -> None:
        module = _load_script_module()
        row = module.score_manifest_case(
            {"challenge_id": "heldout-web", "category": "web", "expected_flag": "flag{x}", "required_evidence": ["YAML"]},
            {"status": "completed", "accepted_flags": []},
            [{"solver": "WebSolver", "evidence": {"note": "YAML"}}],
            {"sections": []},
        )

        self.assertEqual(row["owner_roles"], ["WebExploitAgent"])
        self.assertFalse(row["ok"])
        self.assertEqual(row["missing_evidence"], [])

    def test_manifest_missing_attachment_becomes_backlog_instead_of_crashing(self) -> None:
        module = _load_script_module()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "heldout.json"
            manifest.write_text(
                json.dumps(
                    {
                        "cases": [
                            {
                                "challenge_id": "heldout-missing-artifact",
                                "category": "traffic",
                                "attachments": ["/tmp/forgeflag-heldout/missing/capture.pcap"],
                                "expected_flag": "flag{missing}",
                                "required_evidence": ["tcp_streams"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            summary = module.run_manifest(manifest, "http://127.0.0.1:1", keep=True)

        self.assertEqual(summary["cases"], 1)
        self.assertEqual(summary["passed"], 0)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["failures"][0]["status"], "missing_attachment")
        self.assertIn("/tmp/forgeflag-heldout/missing/capture.pcap", summary["failures"][0]["missing_evidence"])
        self.assertEqual(summary["failures"][0]["owner_roles"], ["TrafficAgent"])

    def test_manifest_api_request_timeout_flows_to_run_challenge(self) -> None:
        module = _load_script_module()
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "artifact.txt"
            artifact.write_text("local artifact", encoding="utf-8")
            manifest = Path(tmp) / "heldout.json"
            manifest.write_text(
                json.dumps(
                    {
                        "cases": [
                            {
                                "challenge_id": "heldout-timeout",
                                "category": "misc",
                                "attachments": [str(artifact)],
                                "expected_flag": "flag{timeout}",
                                "required_evidence": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.object(module, "delete_challenge"),
                mock.patch.object(module, "create_challenge"),
                mock.patch.object(module, "get_json", side_effect=[[], {}]),
                mock.patch.object(module, "run_challenge", return_value={"status": "completed", "accepted_flags": ["flag{timeout}"]}) as run_challenge,
            ):
                summary = module.run_manifest(manifest, "http://127.0.0.1:1", keep=True, request_timeout=123)

        self.assertEqual(summary["passed"], 1)
        run_challenge.assert_called_once()
        self.assertEqual(run_challenge.call_args.args[2], 123)

    def test_manifest_score_accepts_local_replay_flag_and_evidence(self) -> None:
        module = _load_script_module()
        row = module.score_manifest_case(
            {
                "challenge_id": "heldout-web-replay",
                "category": "web",
                "expected_flag": "flag{real_replay}",
                "required_evidence": ["YAML", "/bin/getflag"],
            },
            {"status": "completed", "accepted_flags": []},
            [{"solver": "WebSolver", "evidence": {"note": "YAML source sink"}}],
            {"sections": []},
            {
                "status": "success",
                "accepted_flags": ["flag{real_replay}"],
                "stdout": "proof used /bin/getflag and returned flag{real_replay}",
                "stderr": "",
            },
        )

        self.assertTrue(row["ok"])
        self.assertEqual(row["accepted_flags"], ["flag{real_replay}"])
        self.assertEqual(row["matched_evidence"], ["YAML", "/bin/getflag"])
        self.assertEqual(row["missing_evidence"], [])

    def test_manifest_replay_failure_is_scored_as_backlog_evidence(self) -> None:
        module = _load_script_module()
        row = module.score_manifest_case(
            {
                "challenge_id": "heldout-web-replay-fail",
                "category": "web",
                "expected_flag": "flag{real_replay}",
                "required_evidence": ["local replay"],
            },
            {"status": "completed", "accepted_flags": []},
            [],
            {},
            {
                "status": "failed",
                "accepted_flags": [],
                "stdout": "",
                "stderr": "connection refused",
            },
        )

        self.assertFalse(row["ok"])
        self.assertEqual(row["status"], "completed+replay_failed")
        self.assertIn("local replay", row["missing_evidence"])
        self.assertEqual(row["owner_roles"], ["WebExploitAgent"])

    def test_main_can_write_scorecard_output_file(self) -> None:
        module = _load_script_module()
        summary = {
            "name": "smoke",
            "kind": "json_rows",
            "command": ["smoke"],
            "returncode": 0,
            "cases": 1,
            "passed": 1,
            "failed": 0,
            "categories": {"crypto": {"passed": 1, "total": 1}},
            "roles": {"CryptoMathAgent": {"passed": 1, "total": 1}},
            "hard_score": 0,
            "hard_max_score": 0,
            "failures": [],
            "stderr": "",
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "scorecard.json"
            with (
                mock.patch.object(sys, "argv", ["forgeflag-capability-benchmark", "--suite", "smoke", "--output", str(output)]),
                mock.patch.object(module, "run_suite", return_value=summary),
                mock.patch("builtins.print") as print_mock,
            ):
                rc = module.main()

            self.assertEqual(rc, 0)
            saved = json.loads(output.read_text(encoding="utf-8"))
            printed = json.loads(print_mock.call_args.args[0])
            self.assertEqual(saved["benchmark"], "forgeflag-capability")
            self.assertEqual(saved["totals"]["cases"], 1)
            self.assertEqual(saved, printed)

    def test_main_can_append_scorecard_history_jsonl(self) -> None:
        module = _load_script_module()
        summary = {
            "name": "smoke",
            "kind": "json_rows",
            "command": ["smoke"],
            "returncode": 0,
            "cases": 2,
            "passed": 1,
            "failed": 1,
            "categories": {"web": {"passed": 0, "total": 1}},
            "roles": {"WebExploitAgent": {"passed": 0, "total": 1}},
            "hard_score": 0,
            "hard_max_score": 0,
            "failures": [{"suite": "smoke", "challenge_id": "smoke-web", "category": "web"}],
            "stderr": "",
        }
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.jsonl"
            with (
                mock.patch.object(sys, "argv", ["forgeflag-capability-benchmark", "--suite", "smoke", "--history", str(history)]),
                mock.patch.object(module, "run_suite", return_value=summary),
                mock.patch("builtins.print"),
            ):
                rc = module.main()

            self.assertEqual(rc, 1)
            records = [json.loads(line) for line in history.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(records), 1)
            self.assertIn("recorded_at", records[0])
            self.assertEqual(records[0]["scorecard"]["totals"]["failed"], 1)
            self.assertEqual(records[0]["scorecard"]["backlog"][0]["challenge_id"], "smoke-web")


def _load_script_module():
    script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-capability-benchmark"
    loader = SourceFileLoader("forgeflag_capability_benchmark_script", str(script))
    spec = spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError("could not load forgeflag-capability-benchmark")
    module = module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


if __name__ == "__main__":
    unittest.main()

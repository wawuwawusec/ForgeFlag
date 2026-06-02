from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import Challenge, ChallengeCategory, Finding, RunConfig, SolverResult, ToolResult
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.solvers.base import SolverContext


class FlagHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"""
        <!doctype html>
        <html>
          <head><title>ForgeFlag Test</title></head>
          <body>
            <a href="/hint">hint</a>
            <form method="post" action="/login">
              <input name="username">
              <input name="password" type="password">
            </form>
            <p>flag{scoped_web_solver}</p>
          </body>
        </html>
        """
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class LinkedFlagHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/flag":
            body = b"flag{linked_web_route}"
        else:
            body = b'<!doctype html><title>Linked</title><a href="/flag">status</a>'
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class ScriptRouteHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/api/options":
            body = b'{"hidden_api":"flag{script_api_route}"}'
            content_type = "application/json"
        else:
            body = b'<!doctype html><title>Script</title><script>fetch("/api/options")</script>'
            content_type = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class PlainTextPortalHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"Portal LFI accepts file:// URLs. Read /opt/tomcat/webapps/ROOT.war for Java handler analysis."
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class WorkflowTest(unittest.TestCase):
    def test_manager_records_recon_and_web_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="web-01",
                    category=ChallengeCategory.WEB,
                    target="http://127.0.0.1:8080",
                    tags=("login",),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("web-01")
            findings = notebook.findings_for("web-01")

        self.assertEqual(summary["status"], "completed")
        self.assertGreaterEqual(len(findings), 2)
        self.assertEqual(findings[0].solver, "ReconSolver")
        self.assertTrue(any(f.solver == "WebSolver" for f in findings))

    def test_unknown_category_still_runs_recon(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="misc-unknown", tags=("rsa",)))

            summary = Manager(notebook, RunConfig()).run_challenge("misc-unknown")
            findings = notebook.findings_for("misc-unknown")

        self.assertEqual(summary["status"], "completed")
        self.assertTrue(any("category=crypto" in f.finding for f in findings))

    def test_all_declared_categories_have_solver_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            categories = [
                ChallengeCategory.WEB,
                ChallengeCategory.PWN,
                ChallengeCategory.REVERSE,
                ChallengeCategory.CRYPTO,
                ChallengeCategory.FORENSICS,
                ChallengeCategory.TRAFFIC,
                ChallengeCategory.MISC,
                ChallengeCategory.INFRA,
            ]
            for category in categories:
                notebook.add_challenge(Challenge(challenge_id=f"{category.value}-01", category=category))
                summary = Manager(notebook, RunConfig()).run_challenge(f"{category.value}-01")
                self.assertEqual(summary["status"], "completed")

                findings = notebook.findings_for(f"{category.value}-01")
                self.assertGreaterEqual(len(findings), 2)

    def test_web_solver_extracts_and_verifies_scoped_flag(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), FlagHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}/"
            with tempfile.TemporaryDirectory() as tmp:
                notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
                notebook.add_challenge(
                    Challenge(
                        challenge_id="web-flag",
                        category=ChallengeCategory.WEB,
                        target=target,
                        tags=("web", "login"),
                    )
                )

                summary = Manager(
                    notebook,
                    RunConfig(active_probe=True, allowed_hosts=("127.0.0.1",)),
                ).run_challenge("web-flag")
                findings = notebook.findings_for("web-flag")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{scoped_web_solver}"])
        self.assertEqual(summary["replay_report"]["flags"][0]["flag"], "flag{scoped_web_solver}")
        self.assertTrue(summary["replay_report"]["flags"][0]["path"])
        self.assertTrue(any(f.finding == "Analyzed scoped HTTP response structure" for f in findings))
        web_finding = next(f for f in findings if f.finding == "Analyzed scoped HTTP response structure")
        self.assertEqual(web_finding.evidence["html"]["title"], "ForgeFlag Test")
        self.assertEqual(web_finding.evidence["html"]["forms"][0]["method"], "post")

    def test_web_solver_follows_scoped_visible_links_for_flags(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), LinkedFlagHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}/"
            with tempfile.TemporaryDirectory() as tmp:
                notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
                notebook.add_challenge(
                    Challenge(
                        challenge_id="web-linked-flag",
                        category=ChallengeCategory.WEB,
                        target=target,
                    )
                )

                summary = Manager(
                    notebook,
                    RunConfig(active_probe=True, allowed_hosts=("127.0.0.1",)),
                ).run_challenge("web-linked-flag")
                findings = notebook.findings_for("web-linked-flag")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{linked_web_route}"])
        linked_finding = next(f for f in findings if f.finding == "Followed scoped visible web links")
        self.assertIn("/flag", linked_finding.evidence["followed_urls"][0])

    def test_web_solver_follows_script_mentioned_routes_for_flags(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), ScriptRouteHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}/"
            with tempfile.TemporaryDirectory() as tmp:
                notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
                notebook.add_challenge(
                    Challenge(
                        challenge_id="web-script-route",
                        category=ChallengeCategory.WEB,
                        target=target,
                    )
                )

                summary = Manager(
                    notebook,
                    RunConfig(active_probe=True, allowed_hosts=("127.0.0.1",)),
                ).run_challenge("web-script-route")
                findings = notebook.findings_for("web-script-route")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{script_api_route}"])
        script_finding = next(f for f in findings if f.finding == "Followed scoped script-mentioned web routes")
        self.assertIn("/api/options", script_finding.evidence["followed_urls"][0])

    def test_web_solver_records_plain_text_response_sample_for_chain_hints(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), PlainTextPortalHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}/portal"
            with tempfile.TemporaryDirectory() as tmp:
                notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
                notebook.add_challenge(
                    Challenge(
                        challenge_id="web-plain-chain",
                        category=ChallengeCategory.WEB,
                        target=target,
                    )
                )

                Manager(
                    notebook,
                    RunConfig(active_probe=True, allowed_hosts=("127.0.0.1",)),
                ).run_challenge("web-plain-chain")
                findings = notebook.findings_for("web-plain-chain")
        finally:
            server.shutdown()
            server.server_close()

        web_finding = next(f for f in findings if f.finding == "Analyzed scoped HTTP response structure")
        self.assertIn("LFI", web_finding.evidence["response_sample"])
        self.assertIn("ROOT.war", web_finding.evidence["response_sample"])
        self.assertIn("LFI", web_finding.evidence["chain_hints"])
        self.assertIn("WAR", web_finding.evidence["chain_hints"])

    def test_web_solver_analyzes_source_routes_and_bug_class_hints_without_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text(
                "from flask import Flask, request, session\n"
                "import jwt, requests\n"
                "app = Flask(__name__)\n"
                "app.config['SECRET_KEY'] = 'dev-secret'\n"
                "@app.route('/api/options')\n"
                "def options(): return {'commands': ['status', 'flag']}\n"
                "@app.route('/fetch')\n"
                "def fetch(): return requests.get(request.args['url']).text\n"
                "@app.route('/download')\n"
                "def download(): return open(request.args['file']).read()\n"
                "def auth(token): return jwt.decode(token, options={'verify_signature': False})\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="web-source-only",
                    category=ChallengeCategory.WEB,
                    attachment_paths=(str(source),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("web-source-only")
            findings = notebook.findings_for("web-source-only")

        self.assertEqual(summary["status"], "completed")
        source_finding = next(f for f in findings if f.finding == "Analyzed web source attachments")
        self.assertIn("/api/options", source_finding.evidence["routes"])
        self.assertIn("/fetch", source_finding.evidence["routes"])
        self.assertIn("api option leakage", source_finding.evidence["bug_class_hints"])
        self.assertIn("SSRF", source_finding.evidence["bug_class_hints"])
        self.assertIn("path traversal", source_finding.evidence["bug_class_hints"])
        self.assertIn("JWT/session", source_finding.evidence["bug_class_hints"])
        self.assertIn("route", source_finding.next_action.lower())

    def test_web_solver_records_scoped_ffuf_route_discovery(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), FlagHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}/"
            with tempfile.TemporaryDirectory() as tmp:
                notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
                notebook.add_challenge(
                    Challenge(
                        challenge_id="web-ffuf",
                        category=ChallengeCategory.WEB,
                        target=target,
                        tags=("web", "route"),
                    )
                )

                with patch(
                    "forgeflag.solvers.web.ctf.ffuf_route_discovery",
                    return_value=ToolResult(
                        tool="ffuf",
                        target=target,
                        status="success",
                        raw={"stdout": '{"results":[{"url":"' + target + 'admin","status":200}]}'},
                    ),
                ):
                    summary = Manager(
                        notebook,
                        RunConfig(active_probe=True, allowed_hosts=("127.0.0.1",)),
                    ).run_challenge("web-ffuf")
                findings = notebook.findings_for("web-ffuf")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(summary["status"], "flag_found")
        ffuf_finding = next(f for f in findings if f.finding == "Ran scoped ffuf route discovery")
        self.assertEqual(ffuf_finding.evidence["tool_status"], "success")
        self.assertIn("admin", ffuf_finding.evidence["tool_sample"])

    def test_manager_observer_injects_prior_solver_observations(self) -> None:
        class ProducerSolver:
            name = "ProducerSolver"
            supported_categories = {ChallengeCategory.MISC}

            def solve(self, context: SolverContext) -> SolverResult:
                finding = Finding(
                    challenge_id=context.challenge.challenge_id,
                    solver=self.name,
                    finding="Recovered archive password candidate",
                    evidence={"candidate": "blue-team"},
                    confidence=0.91,
                    next_action="Try password against nested archive.",
                )
                context.notebook.add_finding(finding)
                return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        class ConsumerSolver:
            name = "ConsumerSolver"
            supported_categories = {ChallengeCategory.MISC}

            def solve(self, context: SolverContext) -> SolverResult:
                finding = Finding(
                    challenge_id=context.challenge.challenge_id,
                    solver=self.name,
                    finding="Consumed injected observations",
                    evidence={"observation_summaries": [observation.summary for observation in context.observations]},
                    confidence=0.8,
                )
                context.notebook.add_finding(finding)
                return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="observer-01", category=ChallengeCategory.MISC))

            summary = Manager(notebook, RunConfig(), solvers=[ProducerSolver(), ConsumerSolver()]).run_challenge(
                "observer-01"
            )
            observations = notebook.observations_for("observer-01")
            consumer = next(f for f in notebook.findings_for("observer-01") if f.solver == "ConsumerSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(observations[0].summary, "Recovered archive password candidate")
        self.assertIn("Recovered archive password candidate", consumer.evidence["observation_summaries"])

    def test_manager_records_solve_trace_steps_for_each_solver(self) -> None:
        class FirstSolver:
            name = "FirstSolver"
            supported_categories = {ChallengeCategory.MISC}

            def solve(self, context: SolverContext) -> SolverResult:
                finding = Finding(
                    challenge_id=context.challenge.challenge_id,
                    solver=self.name,
                    finding="Decoded warmup hint",
                    evidence={"hint": "try binary ascii"},
                    confidence=0.8,
                    next_action="Run the second solver.",
                )
                context.notebook.add_finding(finding)
                return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        class SecondSolver:
            name = "SecondSolver"
            supported_categories = {ChallengeCategory.MISC}

            def solve(self, context: SolverContext) -> SolverResult:
                finding = Finding(
                    challenge_id=context.challenge.challenge_id,
                    solver=self.name,
                    finding="Recovered flag candidate",
                    evidence={"flag_candidates": ["flag{trace_path}"]},
                    confidence=0.9,
                    next_action="Submit flag candidate.",
                )
                context.notebook.add_finding(finding)
                return SolverResult(
                    self.name,
                    context.challenge.challenge_id,
                    "ok",
                    (finding,),
                    ("flag{trace_path}",),
                )

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="trace-01", category=ChallengeCategory.MISC))

            summary = Manager(notebook, RunConfig(), solvers=[FirstSolver(), SecondSolver()]).run_challenge("trace-01")
            trace = [observation for observation in notebook.observations_for("trace-01") if observation.kind == "solve_trace_step"]

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual([step.evidence["step_index"] for step in trace], [1, 2])
        self.assertEqual([step.source for step in trace], ["FirstSolver", "SecondSolver"])
        self.assertEqual(trace[0].evidence["findings"][0]["finding"], "Decoded warmup hint")
        self.assertEqual(trace[1].evidence["flag_candidates"], ["flag{trace_path}"])
        self.assertTrue(trace[1].evidence["made_progress"])


if __name__ == "__main__":
    unittest.main()

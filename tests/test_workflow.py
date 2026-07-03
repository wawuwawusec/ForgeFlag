from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
import zipfile

from forgeflag.agent_roster import AgentRoster, default_agent_roster
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


class HeaderCookieFlagHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"<!doctype html><title>Header Only</title><p>inspect response metadata</p>"
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("X-Flag-Hint", "flag{header_cookie_web}")
        self.send_header("Set-Cookie", "session=flag{header_cookie_web}; HttpOnly; Path=/")
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
        self.assertEqual(findings[0].evidence["ctf_scope"]["category"], "recon")
        self.assertEqual(findings[0].evidence["ctf_scope"]["research_context"], "local_or_authorized_ctf_lab")
        self.assertTrue(any(f.solver == "WebSolver" for f in findings))

    def test_unknown_category_still_runs_recon(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="misc-unknown", tags=("rsa",)))

            summary = Manager(notebook, RunConfig()).run_challenge("misc-unknown")
            findings = notebook.findings_for("misc-unknown")

        self.assertEqual(summary["status"], "completed")
        self.assertTrue(any("category=crypto" in f.finding for f in findings))

    def test_pwn_exploit_plan_is_not_marked_as_solved_without_replay_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "2016-CCTF-pwn3"
            binary.write_bytes(b"\x7fELF fake")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="pwn3-proof",
                    category=ChallengeCategory.PWN,
                    attachment_paths=(str(binary),),
                )
            )

            with (
                patch(
                    "forgeflag.solvers.pwn.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "ELF 32-bit LSB executable, Intel 80386"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.strings_extract",
                    return_value=ToolResult(
                        tool="strings",
                        target=None,
                        status="success",
                        raw={
                            "stdout": (
                                "please enter the name of the file you want to upload:\n"
                                "then, enter the content:\n"
                                "enter the file name you want to get:\n"
                                "%40s\nflag\ntoo young, too simple\nftp>\n"
                                "Connected to ftp.hacker.server\n"
                                "Name (ftp.hacker.server:Rainism):\n"
                                "sysbdmin\nprintf\nstrcpy\nfread\nput_file\nget_file\n"
                            )
                        },
                    ),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.checksec_binary",
                    return_value=ToolResult(tool="checksec", target=None, status="success", raw={"stderr": "Partial RELRO\nNo canary found\nNX enabled\nNo PIE"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="success", raw={"stdout": "Unique gadgets found: 113"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="success", raw={"stdout": ""}),
                ),
            ):
                summary = Manager(notebook, RunConfig()).run_challenge("pwn3-proof")

        self.assertEqual(summary["status"], "exploit_plan")
        self.assertEqual(summary["proof_status"], "exploit_plan")
        self.assertEqual(summary["proof"]["label"], "Exploit plan only")
        self.assertFalse(summary["proof"]["verified"])
        self.assertIn("Run the exploit", summary["proof"]["next_action"])
        self.assertEqual(summary["accepted_flags"], [])

    def test_recon_verifies_flag_like_token_from_challenge_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="text-flag",
                    title="Web prompt pasted from UI",
                    description="The visible challenge prompt includes flag{challenge_text_candidate}.",
                    tags=("ui", "smoke"),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("text-flag")
            findings = notebook.findings_for("text-flag")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{challenge_text_candidate}"])
        self.assertTrue(any(f.finding == "Found flag-like token in challenge text" for f in findings))

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
                if category == ChallengeCategory.PWN:
                    self.assertIn(summary["status"], {"analysis_only", "exploit_plan", "exploit_verified", "flag_found"})
                    self.assertIn("proof_status", summary)
                else:
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
        self.assertEqual(web_finding.evidence["ctf_scope"]["category"], "web")
        self.assertEqual(web_finding.evidence["ctf_scope"]["research_context"], "local_or_authorized_ctf_lab")

    def test_web_solver_extracts_header_cookie_flags(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), HeaderCookieFlagHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}/"
            with tempfile.TemporaryDirectory() as tmp:
                notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
                notebook.add_challenge(
                    Challenge(
                        challenge_id="web-header-cookie-flag",
                        category=ChallengeCategory.WEB,
                        target=target,
                    )
                )

                summary = Manager(
                    notebook,
                    RunConfig(active_probe=True, allowed_hosts=("127.0.0.1",)),
                ).run_challenge("web-header-cookie-flag")
                findings = notebook.findings_for("web-header-cookie-flag")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{header_cookie_web}"])
        web_finding = next(f for f in findings if f.finding == "Analyzed scoped HTTP response structure")
        self.assertIn("X-Flag-Hint", web_finding.evidence["response_headers"])
        self.assertEqual(web_finding.evidence["set_cookie_names"], ["session"])
        self.assertIn("flag{header_cookie_web}", web_finding.evidence["flag_candidates"])

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

    def test_web_solver_analyzes_source_archive_routes_and_yaml_hints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "web-source.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(
                    "challenge/src/index.ts",
                    "import express from 'express';\n"
                    "import YAML from 'yaml';\n"
                    "const app = express();\n"
                    "app.post('/convert', (req, res) => res.send(YAML.parse(req.body)));\n",
                )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="web-source-archive",
                    category=ChallengeCategory.WEB,
                    attachment_paths=(str(archive),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("web-source-archive")
            findings = notebook.findings_for("web-source-archive")

        self.assertEqual(summary["status"], "completed")
        source_finding = next(f for f in findings if f.finding == "Analyzed web source attachments")
        self.assertIn("/convert", source_finding.evidence["routes"])
        self.assertIn("YAML parser", source_finding.evidence["bug_class_hints"])
        self.assertIn("challenge/src/index.ts", source_finding.evidence["source_archive_entries"])

    def test_web_solver_extracts_flag_from_source_archive_flag_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "prisoner-processor.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(
                    "app/src/index.ts",
                    "import { Hono } from 'hono';\n"
                    "import { stringify } from 'yaml';\n"
                    "const SIGNED_PREFIX = 'signed.';\n"
                    "app.post('/convert-to-yaml', (c) => stringify(c.req.json()));\n",
                )
                zf.writestr("flag.txt", "DUCTF{source_archive_flag}\n")
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="web-source-archive-flag",
                    category=ChallengeCategory.WEB,
                    attachment_paths=(str(archive),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("web-source-archive-flag")
            findings = notebook.findings_for("web-source-archive-flag")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["DUCTF{source_archive_flag}"])
        source_finding = next(f for f in findings if f.finding == "Analyzed web source attachments")
        self.assertIn("flag.txt", source_finding.evidence["source_archive_entries"])
        self.assertIn("DUCTF{source_archive_flag}", source_finding.evidence["flag_candidates"])

    def test_web_solver_rejects_placeholder_flag_and_records_prisoner_processor_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "prisoner-processor.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(
                    "prisoner-processor/src/app/src/index.ts",
                    "import { Hono } from 'hono';\n"
                    "import { stringify } from 'yaml';\n"
                    "const SIGNED_PREFIX = 'signed.';\n"
                    "const OUTPUT_YAML_FOLDER = '/app-data/yamls';\n"
                    "const BANNED_STRINGS = ['app', 'src', '.ts', 'bun', 'index'];\n"
                    "const getSignedData = (data: any): any => {\n"
                    "  const signedParams: any = {};\n"
                    "  for (const param in data) if (param.startsWith(SIGNED_PREFIX)) signedParams[param.slice(SIGNED_PREFIX.length)] = data[param];\n"
                    "  return signedParams;\n"
                    "};\n"
                    "const convertJsonToYaml = (data: any, outputFileString: string): boolean => {\n"
                    "  const outputFile = Bun.file(`${OUTPUT_YAML_FOLDER}/${outputFileString}`);\n"
                    "  Bun.write(outputFile, stringify(data));\n"
                    "  return true;\n"
                    "};\n"
                    "app.post('/convert-to-yaml', (c) => {\n"
                    "  const outputPrefix = getSignedData(c.req.json()).outputPrefix ?? 'prisoner';\n"
                    "  return convertJsonToYaml({}, `${outputPrefix}.yaml`);\n"
                    "});\n",
                )
                zf.writestr(
                    "prisoner-processor/src/flag.c",
                    '#include <unistd.h>\nint main(){setuid(6969); system("/bin/getflag");}\n',
                )
                zf.writestr("prisoner-processor/src/flag.txt", "DUCTF{test_flag_real_flag_on_instance}\n")
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="web-prisoner-placeholder",
                    category=ChallengeCategory.WEB,
                    attachment_paths=(str(archive),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("web-prisoner-placeholder")
            findings = notebook.findings_for("web-prisoner-placeholder")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["accepted_flags"], [])
        source_finding = next(f for f in findings if f.finding == "Analyzed web source attachments")
        self.assertNotIn("DUCTF{test_flag_real_flag_on_instance}", source_finding.evidence["flag_candidates"])
        self.assertIn("DUCTF{test_flag_real_flag_on_instance}", source_finding.evidence["rejected_flag_candidates"])
        chain = source_finding.evidence["proof_chain_hints"]
        self.assertIn("prototype pollution via signed.__proto__", chain)
        self.assertIn("Bun null byte path truncation", chain)
        self.assertIn("/proc/self/fd overwrite pivot", chain)
        self.assertIn("YAML-to-TypeScript payload shaping", chain)
        self.assertIn("SUID getflag proof target", chain)

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

    def test_manager_summary_includes_subagent_roster_for_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="agent-roster-run",
                    category=ChallengeCategory.WEB,
                    description="flag{agent_roster_run}",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("agent-roster-run")

        roster = summary["agent_roster"]
        self.assertEqual(roster["coordinator"]["id"], "forgeflag-manager")
        names = {agent["name"] for agent in roster["agents"]}
        self.assertIn("ChallengeTriageAgent", names)
        self.assertIn("WebExploitAgent", names)
        self.assertIn("EvidenceJudgeAgent", names)
        self.assertNotIn("LLMRoutePlannerAgent", names)
        self.assertNotIn("BrowserPlayerQAAgent", names)

    def test_manager_uses_roster_to_filter_solver_queue(self) -> None:
        class FakeRecon:
            name = "ReconSolver"
            supported_categories = {ChallengeCategory.WEB}

            def solve(self, context: SolverContext) -> SolverResult:
                return SolverResult(self.name, context.challenge.challenge_id, "ok")

        class FakeWeb:
            name = "WebSolver"
            supported_categories = {ChallengeCategory.WEB}

            def solve(self, context: SolverContext) -> SolverResult:
                raise AssertionError("disabled WebExploitAgent should remove WebSolver from queue")

        payload = default_agent_roster().to_dict()
        for agent in payload["agents"]:
            if agent["id"] == "web-exploit":
                agent["enabled"] = False
        roster = AgentRoster.from_dict(payload)

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="web-disabled", category=ChallengeCategory.WEB))

            summary = Manager(
                notebook,
                RunConfig(),
                solvers=[FakeRecon(), FakeWeb()],
                agent_roster=roster,
            ).run_challenge("web-disabled")

        self.assertEqual([row["solver"] for row in summary["solvers"]], ["ReconSolver"])

    def test_manager_records_pwn_exploit_writeup_without_flag(self) -> None:
        class FakePwn:
            name = "PwnSolver"
            supported_categories = {ChallengeCategory.PWN}

            def solve(self, context: SolverContext) -> SolverResult:
                finding = Finding(
                    challenge_id=context.challenge.challenge_id,
                    solver=self.name,
                    finding="Found FTP heap format string shell path",
                    evidence={
                        "workflow_guess": "ftp_heap_format_string",
                        "exploit_plan": {
                            "workflow": "ftp_heap_format_string",
                            "login_input": "rxraclhm",
                            "format_offset": 7,
                        },
                    },
                    confidence=0.86,
                )
                context.notebook.add_finding(finding)
                return SolverResult(self.name, context.challenge.challenge_id, "ok", findings=(finding,))

        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="pwn-shell-only",
                    category=ChallengeCategory.PWN,
                    attachment_paths=("/tmp/2016-CCTF-pwn3",),
                )
            )

            summary = Manager(notebook, RunConfig(), solvers=[FakePwn()]).run_challenge("pwn-shell-only")

        self.assertEqual(summary["accepted_flags"], [])
        script = summary["replay_report"]["writeup"]["exploit_script"]["content"]
        self.assertIn("LOGIN_INPUT = b\"rxraclhm\"", script)
        self.assertIn("io.interactive()", script)


if __name__ == "__main__":
    unittest.main()

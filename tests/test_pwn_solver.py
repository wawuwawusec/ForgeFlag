from __future__ import annotations

import tempfile
import socketserver
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import Challenge, ChallengeCategory, ToolResult
from forgeflag.notebook import SQLiteNotebook
from forgeflag.safety import ScopePolicy
from forgeflag.solvers.base import SolverContext
from forgeflag.solvers.pwn import PwnSolver


class PwnSolverTest(unittest.TestCase):
    def test_pwn_solver_triages_binary_with_gadget_tools_and_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "pwn"
            binary.write_bytes(b"fake elf")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="pwn-triage",
                category=ChallengeCategory.PWN,
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            with (
                patch(
                    "forgeflag.solvers.pwn.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "ELF 64-bit"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": "flag{pwn_string}"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.checksec_binary",
                    return_value=ToolResult(tool="checksec", target=None, status="success", raw={"stdout": "NX enabled"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="missing", evidence=["not installed"]),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", evidence=["not installed"]),
                ),
            ):
                result = PwnSolver().solve(
                    SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy())
                )
                finding = notebook.findings_for("pwn-triage")[0]

        self.assertEqual(result.status, "flag_candidate")
        self.assertEqual(result.flag_candidates, ("flag{pwn_string}",))
        self.assertEqual(finding.finding, "Analyzed pwn binary artifact")
        self.assertEqual(finding.evidence["tool_statuses"]["checksec_binary"], "success")
        self.assertEqual(finding.evidence["tool_statuses"]["ropgadget_scan"], "missing")
        self.assertEqual(finding.evidence["tool_statuses"]["ropper_scan"], "missing")

    def test_pwn_solver_interacts_with_scoped_tcp_service_target(self) -> None:
        class PwnBannerHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.sendall(b"pwn service ready\nflag{pwn_tcp_service}\n")

        server = socketserver.TCPServer(("127.0.0.1", 0), PwnBannerHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"127.0.0.1:{server.server_address[1]}"
            with tempfile.TemporaryDirectory() as tmp:
                notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
                challenge = Challenge(
                    challenge_id="pwn-service",
                    category=ChallengeCategory.PWN,
                    target=target,
                )
                notebook.add_challenge(challenge)

                result = PwnSolver().solve(
                    SolverContext(
                        challenge=challenge,
                        notebook=notebook,
                        scope=ScopePolicy(allowed_hosts=("127.0.0.1",), active_probe=True),
                    )
                )
                finding = notebook.findings_for("pwn-service")[0]
                observations = notebook.observations_for("pwn-service")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(result.status, "flag_candidate")
        self.assertEqual(result.flag_candidates, ("flag{pwn_tcp_service}",))
        self.assertEqual(finding.finding, "Interacted with scoped pwn service")
        self.assertEqual(finding.evidence["tool_status"], "success")
        self.assertIn("flag{pwn_tcp_service}", finding.evidence["transcript"])
        self.assertTrue(any(observation.kind == "tool_summary" for observation in observations))

    def test_pwn_solver_identifies_format_string_source_sink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "vuln.c"
            source.write_text(
                "#include <stdio.h>\n"
                "int main(void) { char name[128]; fgets(name, sizeof(name), stdin); printf(name); }\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="pwn-format-source",
                category=ChallengeCategory.PWN,
                attachment_paths=(str(source),),
            )
            notebook.add_challenge(challenge)

            result = PwnSolver().solve(SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy()))
            finding = notebook.findings_for("pwn-format-source")[0]

        self.assertEqual(result.status, "ok")
        self.assertEqual(finding.finding, "Identified pwn source vulnerability pattern")
        self.assertEqual(finding.evidence["pattern"], "format string")
        self.assertIn("printf", finding.evidence["dangerous_calls"])
        self.assertIn("pwntools", finding.next_action)


if __name__ == "__main__":
    unittest.main()

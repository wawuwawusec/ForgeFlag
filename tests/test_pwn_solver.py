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
        self.assertEqual(finding.evidence["ctf_scope"]["category"], "pwn")
        self.assertEqual(finding.evidence["ctf_scope"]["research_context"], "local_or_authorized_ctf_lab")

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
        self.assertEqual(finding.evidence["ctf_scope"]["category"], "pwn")
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
        self.assertEqual(finding.evidence["exploit_plan"]["workflow"], "format_string")
        self.assertIn("%p", finding.evidence["exploit_plan"]["offset_probe"])
        self.assertIn("fmtstr_payload", finding.evidence["exploit_plan"]["payload_template"])
        self.assertIn("pwntools", finding.next_action)

    def test_pwn_solver_identifies_ret2win_source_and_replay_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "ret2win.c"
            source.write_text(
                "#include <stdio.h>\n"
                "void win(void) { puts(\"flag shell\"); }\n"
                "int main(void) { char buf[64]; gets(buf); return 0; }\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="pwn-ret2win-source",
                category=ChallengeCategory.PWN,
                attachment_paths=(str(source),),
            )
            notebook.add_challenge(challenge)

            result = PwnSolver().solve(SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy()))
            finding = notebook.findings_for("pwn-ret2win-source")[0]

        exploit_plan = finding.evidence["exploit_plan"]
        self.assertEqual(result.status, "ok")
        self.assertEqual(finding.finding, "Identified pwn source vulnerability pattern")
        self.assertEqual(finding.evidence["pattern"], "ret2win")
        self.assertIn("gets", finding.evidence["dangerous_calls"])
        self.assertIn("win", finding.evidence["symbols"])
        self.assertEqual(exploit_plan["workflow"], "ret2win")
        self.assertEqual(exploit_plan["symbol"], "win")
        self.assertIn("cyclic", exploit_plan["cyclic_offset"])
        self.assertIn("elf.symbols['win']", exploit_plan["payload_template"])
        self.assertIn("pwntools", exploit_plan["tool_hints"])
        self.assertIn("cyclic", finding.next_action)
        self.assertIn("win", finding.next_action)

    def test_pwn_solver_infers_ret2win_workflow_from_binary_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "ret2win"
            binary.write_bytes(b"\x7fELF fake")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="pwn-ret2win-binary",
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
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": "win\ngets\n/bin/sh"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.checksec_binary",
                    return_value=ToolResult(tool="checksec", target=None, status="success", raw={"stdout": "No PIE\nNX enabled"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="success", raw={"stdout": "pop rdi ; ret"}),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", evidence=["not installed"]),
                ),
            ):
                result = PwnSolver().solve(
                    SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy())
                )
                finding = notebook.findings_for("pwn-ret2win-binary")[0]

        exploit_plan = finding.evidence["exploit_plan"]
        self.assertEqual(result.status, "ok")
        self.assertEqual(finding.evidence["workflow_guess"], "ret2win")
        self.assertEqual(exploit_plan["workflow"], "ret2win")
        self.assertEqual(exploit_plan["symbol"], "win")
        self.assertIn("cyclic", exploit_plan["cyclic_offset"])
        self.assertIn("elf.symbols['win']", exploit_plan["payload_template"])
        self.assertIn("ret2win", finding.hypothesis)
        self.assertIn("cyclic", finding.next_action)

    def test_pwn_solver_infers_cctf_pwn3_format_string_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "2016-CCTF-pwn3"
            binary.write_bytes(b"\x7fELF fake")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="pwn3",
                category=ChallengeCategory.PWN,
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

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
                                "sysbdmin\n"
                                "printf\nstrcpy\nfread\n"
                                "put_file\nget_file\nget_input\n"
                            )
                        },
                    ),
                ),
                patch(
                    "forgeflag.solvers.pwn.ctf.checksec_binary",
                    return_value=ToolResult(
                        tool="checksec",
                        target=None,
                        status="success",
                        raw={"stderr": "Arch: i386-32-little\nNo canary found\nNX enabled\nNo PIE (0x8048000)\n"},
                    ),
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
                result = PwnSolver().solve(
                    SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy())
                )
                finding = notebook.findings_for("pwn3")[0]

        exploit_plan = finding.evidence["exploit_plan"]
        self.assertEqual(result.status, "ok")
        self.assertEqual(finding.evidence["workflow_guess"], "ftp_heap_format_string")
        self.assertEqual(exploit_plan["workflow"], "ftp_heap_format_string")
        self.assertEqual(exploit_plan["login_input"], "rxraclhm")
        self.assertEqual(exploit_plan["format_offset"], 7)
        self.assertIn("printf@got", exploit_plan["overwrite_target"])
        self.assertIn("/bin/sh", exploit_plan["trigger"])
        self.assertIn("format string", finding.hypothesis)


if __name__ == "__main__":
    unittest.main()

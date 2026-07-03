from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import Challenge, ChallengeCategory, ToolResult
from forgeflag.notebook import SQLiteNotebook
from forgeflag.safety import ScopePolicy
from forgeflag.solvers.base import SolverContext
from forgeflag.solvers.reverse import _recover_jmp_table_popcount_body_with_capstone
from forgeflag.solvers.reverse import ReverseSolver


class ReverseSolverTest(unittest.TestCase):
    def test_capstone_helper_recovers_jmp_table_popcount_body_from_binary_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "jmp.bin"
            binary.write_bytes(_synthetic_jmp_table_binary("tAb1ed"))

            self.assertEqual(_recover_jmp_table_popcount_body_with_capstone(str(binary)), "tAb1ed")

    def test_reverse_solver_recovers_jmp_table_popcount_flag_from_objdump(self) -> None:
        body = "tAb1ed"
        disassembly = _synthetic_jmp_table_disassembly(body)
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "jmp_flag"
            binary.write_bytes(b"\x7fELF")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="rev-jmp-table",
                category=ChallengeCategory.REVERSE,
                title="DUCTF jmp flag",
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            with (
                patch(
                    "forgeflag.solvers.reverse.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "ELF 64-bit"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": "Correct! DUCTF{%s}"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.readelf_sections",
                    return_value=ToolResult(tool="readelf", target=None, status="success", raw={"stdout": " .text"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_disassemble",
                    return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": disassembly}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_section_dump",
                    return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.radare2_info",
                    return_value=ToolResult(tool="radare2", target=None, status="missing", evidence=["not installed"]),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="missing", evidence=["not installed"]),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", evidence=["not installed"]),
                ),
            ):
                result = ReverseSolver().solve(
                    SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy())
                )
                finding = notebook.findings_for("rev-jmp-table")[0]

        self.assertEqual(result.status, "flag_candidate")
        self.assertIn("DUCTF{tAb1ed}", result.flag_candidates)
        self.assertEqual(finding.evidence["jmp_table_popcount"]["recovered_body"], body)

    def test_reverse_solver_triages_binary_with_strings_and_gadget_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "rev.bin"
            binary.write_bytes(b"fake elf")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="rev-triage",
                category=ChallengeCategory.REVERSE,
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            with (
                patch(
                    "forgeflag.solvers.reverse.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "ELF 64-bit"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": "check_flag\nmain"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.readelf_sections",
                    return_value=ToolResult(tool="readelf", target=None, status="success", raw={"stdout": " .rodata"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_disassemble",
                    return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": "main:"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_section_dump",
                    return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": "Contents of section .rodata"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.radare2_info",
                    return_value=ToolResult(tool="radare2", target=None, status="missing", evidence=["not installed"]),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="missing", evidence=["not installed"]),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", evidence=["not installed"]),
                ),
            ):
                result = ReverseSolver().solve(
                    SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy())
                )
                finding = notebook.findings_for("rev-triage")[0]

        self.assertEqual(result.status, "ok")
        self.assertEqual(finding.finding, "Analyzed reverse binary artifact")
        self.assertEqual(finding.evidence["tool_statuses"]["strings_extract"], "success")
        self.assertEqual(finding.evidence["tool_statuses"]["readelf_sections"], "success")
        self.assertEqual(finding.evidence["tool_statuses"]["objdump_disassemble"], "success")
        self.assertEqual(finding.evidence["tool_statuses"]["objdump_rodata"], "success")
        self.assertEqual(finding.evidence["tool_statuses"]["radare2_info"], "missing")
        self.assertEqual(finding.evidence["tool_statuses"]["ropgadget_scan"], "missing")
        self.assertEqual(finding.evidence["ctf_scope"]["category"], "reverse")
        self.assertEqual(finding.evidence["ctf_scope"]["research_context"], "local_or_authorized_ctf_lab")
        self.assertIn("check_flag", finding.evidence["tool_samples"]["strings_extract"]["stdout"])

    def test_reverse_solver_recovers_python_vm_perfect_number_sha1_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "vm.py"
            script.write_text(
                "\n".join(
                    [
                        "import hashlib",
                        "class VM:",
                        "    def printflag(self, src):",
                        "        flag_enc = b'\\xca (:\\xda\\x1f\\xea\\xd5q+;\\x8a\\x82\\xeb\\xaa\\t\\x86\\x12\\xec\\x83\\xc3d0'",
                        "        h = hashlib.sha1(str(self.registers[src]).encode()).digest() * 2",
                        "        print(bytes(a^b for a, b in zip(flag_enc, h)))",
                        "program = [",
                        "    'MOV R2 31337',",
                        "    'MOV R5 2410',",
                        "    'CMP R0 R3',",
                        "    'PRINTFLAG R0',",
                        "]",
                    ]
                ),
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="rev-python-vm",
                category=ChallengeCategory.REVERSE,
                title="NUS reverse ASM",
                attachment_paths=(str(script),),
            )
            notebook.add_challenge(challenge)

            with (
                patch(
                    "forgeflag.solvers.reverse.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "Python script"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": "PRINTFLAG"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.readelf_sections",
                    return_value=ToolResult(tool="readelf", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_disassemble",
                    return_value=ToolResult(tool="objdump", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_section_dump",
                    return_value=ToolResult(tool="objdump", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.radare2_info",
                    return_value=ToolResult(tool="radare2", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", raw={"stdout": ""}),
                ),
            ):
                result = ReverseSolver().solve(SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy()))
                finding = notebook.findings_for("rev-python-vm")[0]

        self.assertEqual(result.status, "flag_candidate")
        self.assertEqual(result.flag_candidates, ("grey{p3rf3c7_r3v3r51n6}",))
        self.assertEqual(finding.evidence["python_vm_perfect_number_sha1"]["modulus"], 31337)
        self.assertEqual(finding.evidence["python_vm_perfect_number_sha1"]["remainder"], 2410)

    def test_reverse_solver_recovers_python_vm_sha1_with_decoys_and_long_flag(self) -> None:
        flag = b"grey{p3rf3c7_r3v3r51n6_with_more_than_forty_bytes}"
        perfect = (1 << (61 - 1)) * ((1 << 61) - 1)
        digest = hashlib.sha1(str(perfect).encode()).digest()
        key = (digest * ((len(flag) // len(digest)) + 1))[: len(flag)]
        flag_enc = bytes(a ^ b for a, b in zip(flag, key))
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "vm.py"
            script.write_text(
                "\n".join(
                    [
                        "import hashlib",
                        "flag_enc = " + repr(flag_enc),
                        "program = [",
                        "    'MOV R2 7',",
                        "    'MOV R5 3',",
                        "    'MOV R2 31337',",
                        "    'MOV R5 2410',",
                        "    'PRINTFLAG R0',",
                        "]",
                        "print(hashlib.sha1)",
                    ]
                ),
                encoding="utf-8",
            )

            result = ReverseSolver().solve(
                SolverContext(
                    challenge=Challenge(
                        challenge_id="rev-python-vm-decoys",
                        category=ChallengeCategory.REVERSE,
                        attachment_paths=(str(script),),
                    ),
                    notebook=SQLiteNotebook(Path(tmp) / "notebook.sqlite"),
                    scope=ScopePolicy(),
                )
            )

        self.assertEqual(result.status, "flag_candidate")
        self.assertIn(flag.decode(), result.flag_candidates)

    def test_reverse_solver_recovers_tkinter_grid_constraint_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "endgamemaker.py"
            script.write_text(_synthetic_cagnus_grid_script(), encoding="utf-8")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="rev-grid-cagnus",
                category=ChallengeCategory.REVERSE,
                title="TJCTF cagnus-marlsen",
                attachment_paths=(str(script),),
            )
            notebook.add_challenge(challenge)

            result = ReverseSolver().solve(SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy()))
            finding = notebook.findings_for("rev-grid-cagnus")[0]

        self.assertEqual(result.status, "flag_candidate")
        self.assertIn("tjctf{n1C3_0n3}", result.flag_candidates)
        self.assertEqual(finding.evidence["python_grid_constraints"]["flag_candidates"], ["tjctf{n1C3_0n3}"])

    def test_reverse_solver_recovers_compiled_byte_equality_chain(self) -> None:
        flag = "UMDCTF{shout_out_to_jose}"
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "cmsc430"
            binary.write_bytes(_synthetic_byte_equality_binary(flag))
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="rev-byte-chain",
                category=ChallengeCategory.REVERSE,
                title="UMDCTF cmsc430",
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            with (
                patch(
                    "forgeflag.solvers.reverse.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "ELF 64-bit not stripped"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": "challenge.s\n_flags"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.readelf_sections",
                    return_value=ToolResult(tool="readelf", target=None, status="success", raw={"stdout": ".text"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_disassemble",
                    return_value=ToolResult(
                        tool="objdump",
                        target=None,
                        status="success",
                        raw={"stdout": "Disassembly truncated before validation helpers"},
                    ),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_section_dump",
                    return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.radare2_info",
                    return_value=ToolResult(tool="radare2", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", raw={"stdout": ""}),
                ),
            ):
                result = ReverseSolver().solve(SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy()))
                finding = notebook.findings_for("rev-byte-chain")[0]

        self.assertEqual(result.status, "flag_candidate")
        self.assertEqual(result.flag_candidates, (flag,))
        self.assertEqual(finding.evidence["compiled_byte_equality_chain"]["decoded_text"], flag)

    def test_reverse_solver_recovers_pe_stack_xor_key_check(self) -> None:
        flag = "XCTF{5eacs6y8p1o9gitc9521}"
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "reverseMe.exe"
            binary.write_bytes(_synthetic_pe_stack_xor_binary(flag))
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="rev-pe-stack-xor",
                category=ChallengeCategory.REVERSE,
                title="XCTF reverseMe",
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            with (
                patch(
                    "forgeflag.solvers.reverse.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "PE32 executable"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.strings_extract",
                    return_value=ToolResult(
                        tool="strings",
                        target=None,
                        status="success",
                        raw={"stdout": "please input the key:\nright!!!\nerror!!!"},
                    ),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.readelf_sections",
                    return_value=ToolResult(tool="readelf", target=None, status="error", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_disassemble",
                    return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": "PE disassembly"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_section_dump",
                    return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.radare2_info",
                    return_value=ToolResult(tool="radare2", target=None, status="success", raw={"stdout": "PE32 i386"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", raw={"stdout": ""}),
                ),
            ):
                result = ReverseSolver().solve(SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy()))
                finding = notebook.findings_for("rev-pe-stack-xor")[0]

        self.assertEqual(result.status, "flag_candidate")
        self.assertEqual(result.flag_candidates, (flag,))
        self.assertEqual(finding.evidence["pe_stack_xor_key_check"]["seed"], 0x38)
        self.assertEqual(finding.evidence["pe_stack_xor_key_check"]["decoded_text"], flag)

    def test_reverse_solver_recovers_elf_argv_repeating_xor_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "xor_nodebug"
            binary.write_bytes(b"\x7fELF")
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="reverse-xor-nodebug",
                category=ChallengeCategory.REVERSE,
                title="xor nodebug",
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            with (
                patch(
                    "forgeflag.solvers.reverse.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "ELF 64-bit PIE"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.strings_extract",
                    return_value=ToolResult(
                        tool="strings",
                        target=None,
                        status="success",
                        raw={"stdout": "ptrace\nstrcmp\nstrlen\ndon't trace me:(\nsgu`ttd]{jt\nright\nmain"},
                    ),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.readelf_sections",
                    return_value=ToolResult(tool="readelf", target=None, status="success", raw={"stdout": " .text\n .rodata"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_disassemble",
                    return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": _synthetic_argv_xor_disassembly()}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_section_dump",
                    return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": _synthetic_argv_xor_rodata()}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.radare2_info",
                    return_value=ToolResult(tool="radare2", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", raw={"stdout": ""}),
                ),
            ):
                result = ReverseSolver().solve(SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy()))
                finding = notebook.findings_for("reverse-xor-nodebug")[0]

        self.assertEqual(result.status, "flag_candidate")
        self.assertEqual(result.flag_candidates, ("reverse_xor",))
        recovery = finding.evidence["elf_argv_repeating_xor"]
        self.assertEqual(recovery["recovered_input"], "reverse_xor")
        self.assertEqual(recovery["ciphertext"], "sgu`ttd]{jt")
        self.assertEqual(recovery["key_hex"], "010203050607")

    def test_reverse_solver_recovers_mlvm_pixel_art_flag(self) -> None:
        flag = "irisctf{gameboy}"
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "michaelpaint.bin"
            binary.write_bytes(_synthetic_mlvm_pixel_art_binary())
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            challenge = Challenge(
                challenge_id="rev-cloudvm",
                category=ChallengeCategory.REVERSE,
                title="IrisCTF CloudVM",
                description="michaelpaint MLVM bytecode asks to wrap the image name in irisctf{}",
                attachment_paths=(str(binary),),
            )
            notebook.add_challenge(challenge)

            with (
                patch(
                    "forgeflag.solvers.reverse.ctf.file_identify",
                    return_value=ToolResult(tool="file", target=None, status="success", raw={"stdout": "data"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.strings_extract",
                    return_value=ToolResult(tool="strings", target=None, status="success", raw={"stdout": "michael paint\nWrap the name of this thing in irisctf{}"}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.readelf_sections",
                    return_value=ToolResult(tool="readelf", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_disassemble",
                    return_value=ToolResult(tool="objdump", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.objdump_section_dump",
                    return_value=ToolResult(tool="objdump", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.radare2_info",
                    return_value=ToolResult(tool="radare2", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropgadget_scan",
                    return_value=ToolResult(tool="ROPgadget", target=None, status="missing", raw={"stdout": ""}),
                ),
                patch(
                    "forgeflag.solvers.reverse.ctf.ropper_scan",
                    return_value=ToolResult(tool="ropper", target=None, status="missing", raw={"stdout": ""}),
                ),
            ):
                result = ReverseSolver().solve(SolverContext(challenge=challenge, notebook=notebook, scope=ScopePolicy()))
                finding = notebook.findings_for("rev-cloudvm")[0]

        self.assertEqual(result.status, "flag_candidate")
        self.assertEqual(result.flag_candidates, (flag,))
        self.assertEqual(finding.evidence["mlvm_pixel_art"]["template_label"], "gameboy")
        self.assertIn("RRRRRRRRR", finding.evidence["mlvm_pixel_art"]["rendered_ascii"])


def _synthetic_jmp_table_disassembly(body: str) -> str:
    chars_by_position = {index: char for index, char in enumerate(body)}
    blocks: list[str] = ["/tmp/jmp_flag:\tfile format elf64-x86-64", "Disassembly of section .text:"]
    for char_code in range(128):
        address = 0x1300 + char_code * 0x80
        char = chr(char_code)
        blocks.append(f"    {address:04x}: f3 0f 1e fa                   endbr64")
        if char not in chars_by_position.values():
            blocks.append(f"    {address + 8:04x}: 48 c7 05 00 00 00 00 ff ff ff ff  mov qword ptr [rip], -0x1")
            blocks.append(f"    {address + 0x15:04x}: c3                            ret")
            continue
        position = body.index(char)
        if position:
            mask = (1 << position) - 1
            blocks.append(f"    {address + 0x0f:04x}: 48 ba 00 00 00 00 00 00 00 00  movabs rdx, 0x{mask:x}")
            blocks.append(f"    {address + 0x19:04x}: 48 21 d0                      and    rax,rdx")
        blocks.append(f"    {address + 0x28:04x}: 48 35 00 00 00 02             xor    rax,0x2000000")
        blocks.append(f"    {address + 0x42:04x}: c3                            ret")
    return "\n".join(blocks)


def _synthetic_jmp_table_binary(body: str) -> bytes:
    data = bytearray(b"\x00" * 0x1300)
    for char_code in range(128):
        char = chr(char_code)
        block = bytearray(b"\x90" * 128)
        block[:8] = b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5"
        if char not in body or char == "t":
            block[8:19] = b"\x48\xc7\x05\x00\x00\x00\x00\xff\xff\xff\xff"
            block[19] = 0xC3
        else:
            position = body.index(char)
            mask = (1 << position) - 1
            block[8:15] = b"\x48\x8b\x05\x00\x00\x00\x00"
            block[15:17] = b"\x48\xba"
            block[17:25] = mask.to_bytes(8, "little")
            block[25:28] = b"\x48\x21\xd0"
            block[28:31] = b"\x48\x85\xc0"
            block[31:33] = b"\x75\x10"
            block[33:40] = b"\x48\x8b\x05\x00\x00\x00\x00"
            block[40:42] = b"\x48\x35"
            block[42:46] = (1 << min(position, 31)).to_bytes(4, "little")
            block[46] = 0xC3
        data.extend(block)
    return bytes(data)


def _synthetic_byte_equality_disassembly(text: str) -> str:
    address = 0x1800
    lines = ["Disassembly of section .text:", f"{address:04x} <entry>:"]
    for char in text:
        encoded = ord(char) * 2
        lines.extend(
            [
                f"    {address:04x}: e8 00 00 00 00                call   16fd <read_byte>",
                f"    {address + 5:04x}: 4c 01 fc                      add    rsp,r15",
                f"    {address + 8:04x}: 50                            push   rax",
                f"    {address + 9:04x}: b8 {encoded & 0xff:02x} 00 00 00                mov    eax,0x{encoded:x}",
                f"    {address + 14:04x}: 41 58                         pop    r8",
                f"    {address + 16:04x}: 49 39 c0                      cmp    r8,rax",
                f"    {address + 19:04x}: 49 0f 44 c1                   cmove  rax,r9",
                f"    {address + 23:04x}: 48 83 f8 07                   cmp    rax,0x7",
            ]
        )
        address += 0x20
    return "\n".join(lines)


def _synthetic_byte_equality_binary(text: str) -> bytes:
    data = bytearray(b"\x00" * 0x100)
    for char in text:
        encoded = ord(char) * 2
        data.extend(b"\xe8\x00\x00\x00\x00")
        data.extend(b"\x4c\x01\xfc")
        data.extend(b"\x50")
        data.extend(b"\xb8" + encoded.to_bytes(4, "little"))
        data.extend(b"\x41\x58")
        data.extend(b"\x49\x39\xc0")
        data.extend(b"\x49\x0f\x44\xc1")
        data.extend(b"\x48\x83\xf8\x07")
        data.extend(b"\x90" * 8)
    return bytes(data)


def _synthetic_argv_xor_disassembly() -> str:
    return """
00000000000011e9 <main>:
    1207: e8 84 fe ff ff                call   1090 <ptrace@plt>
    1228: c7 45 a9 01 02 03 05          mov    dword ptr [rbp-0x57],0x5030201
    122f: 66 c7 45 ad 06 07             mov    word ptr [rbp-0x53],0x706
    1235: c6 45 af 00                   mov    byte ptr [rbp-0x51],0x0
    124e: 48 8b 45 a0                   mov    rax,QWORD PTR [rbp-0x60]
    1262: e8 f9 fd ff ff                call   1060 <strlen@plt>
    1281: 31 d1                         xor    ecx,edx
    1288: 83 e0 00                      and    eax,0x0
    12b5: e8 b6 fd ff ff                call   1070 <strcmp@plt>
    12a4: 48 8d 15 6a 0d 00 00          lea    rdx,[rip+0xd6a]        # 2015 <_IO_stdin_used+0x15>
    12ad: 48 89 d6                      mov    rsi,rdx
    12b0: 48 89 c7                      mov    rdi,rax
    12b5: e8 b6 fd ff ff                call   1070 <strcmp@plt>
""".strip()


def _synthetic_argv_xor_rodata() -> str:
    return """
Contents of section .rodata:
 2000 01000200 646f6e27 74207472 61636520  ....don't trace
 2010 6d653a28 00736775 60747464 5d7b6a74  me:(.sgu`ttd]{jt
 2020 00726967 687400                      .right.
""".strip()


def _synthetic_mlvm_pixel_art_binary() -> bytes:
    rows = [
        "                 ",
        "                 ",
        "    RRRRRRRRR    ",
        "   RRRRRRRRRRR   ",
        "   RR       RR   ",
        "   RR RYGBM RR   ",
        "   RR RYGBM RR   ",
        "   RR       RR   ",
        "   RRRRRRRRRRR   ",
        "   RRRWRRRRRRR   ",
        "   RRWWWRRWRRR   ",
        "   RRRWRRRRWRR   ",
        "   RRRRRRRRRRR   ",
        "   RRRRGRGRRRR   ",
        "    RRRRRRRRR    ",
        "                 ",
        "                 ",
    ]
    palette = {" ": 0, "R": 1, "G": 2, "Y": 3, "B": 4, "M": 5, "C": 6, "W": 7}
    canvas = [0] * 512
    for y, row in enumerate(rows):
        for x, char in enumerate(row):
            canvas[y * 16 + x] = palette[char]

    data = bytearray()
    data.extend(b"MLVM")
    data.extend((2).to_bytes(4, "little", signed=True))
    data.extend((0x80).to_bytes(4, "little"))
    data.extend((4).to_bytes(2, "little"))
    data.extend(b"main")
    data.extend((0x90).to_bytes(4, "little"))
    data.extend((5).to_bytes(2, "little"))
    data.extend(b"suSsY")
    data.extend(b"michael paint\x00Wrap the name of this thing in irisctf{}\x00")
    while len(data) < 0x100:
        data.append(0)
    for offset in range(0, 272, 4):
        chunk = canvas[offset : offset + 4]
        if not any(chunk):
            continue
        target = _mlvm_pixel_transform(chunk)
        data.extend(b"\xc1\x00" + offset.to_bytes(4, "little", signed=True))
        data.extend(b"\xc1\x01" + (0).to_bytes(4, "little", signed=True))
        data.extend(b"\xc1\x02" + target.to_bytes(4, "little", signed=True))
        data.extend(b"\xf0\x00\x00\x00\x00\xe1\x00\x00\x00\x00\x02")
    data.extend(b"\xd0Wrap the name of this thing in irisctf{}\xf2")
    return bytes(data)


def _synthetic_pe_stack_xor_binary(flag: str) -> bytes:
    seed = 0x38
    key = _pe_stack_xor_key(seed, len(flag))
    encrypted = bytes(ord(char) ^ key[index] for index, char in enumerate(flag))
    code = bytearray()
    code.extend(b"\xb1\x76\xb0\xd8")
    cl_offsets = {0x11, 0x19}
    al_offsets = {0x14, 0x29}
    for index, value in enumerate(encrypted):
        offset = 0x10 + index
        if offset in cl_offsets:
            code.extend(b"\x88\x4c\x24" + bytes([offset]))
        elif offset in al_offsets:
            code.extend(b"\x88\x44\x24" + bytes([offset]))
        else:
            code.extend(b"\xc6\x44\x24" + bytes([offset, value]))
    code.extend(b"\x8d\x44\x24\x10")
    code.extend(b"\x6a" + bytes([len(flag)]))
    code.extend(b"\x50")
    code.extend(b"\x6a" + bytes([seed]))
    code.extend(b"\xe8\xdd\xfe\xff\xff")
    return b"MZ" + b"\x00" * 0x200 + bytes(code) + b"please input the key:\x00right!!!\x00error!!!\x00"


def _pe_stack_xor_key(seed: int, size: int) -> bytes:
    step = seed * 2 + 0x0A
    value = step * 10 - 9
    out = bytearray()
    for _ in range(size):
        out.append(value & 0xFF)
        value += step
    return bytes(out)


def _mlvm_pixel_transform(chunk: list[int]) -> int:
    value = chunk[0] | (chunk[1] << 8) | (chunk[2] << 16) | (chunk[3] << 24)
    return (value & 0xFF) | (value & 0xFF00) | ((value >> 12) & 0xFF) | ((value >> 12) & 0xFF00)


def _synthetic_cagnus_grid_script() -> str:
    return """
grid = [0]*64
def verify():
    b0 = int(''.join(str(i) for i in grid[0:8]), 2)
    b1 = int(''.join(str(i) for i in grid[8:16]), 2)
    b2 = int(''.join(str(i) for i in grid[16:24]), 2)
    b3 = int(''.join(str(i) for i in grid[24:32]), 2)
    b4 = int(''.join(str(i) for i in grid[32:40]), 2)
    b5 = int(''.join(str(i) for i in grid[40:48]), 2)
    b6 = int(''.join(str(i) for i in grid[48:56]), 2)
    b7 = int(''.join(str(i) for i in grid[56:64]), 2)
    b8 = int(''.join(str(i) for i in grid[0:64:8]), 2)
    b9 = int(''.join(str(i) for i in grid[1:64:8]), 2)
    b10 = int(''.join(str(i) for i in grid[2:64:8]), 2)
    b11 = int(''.join(str(i) for i in grid[3:64:8]), 2)
    b12 = int(''.join(str(i) for i in grid[4:64:8]), 2)
    b13 = int(''.join(str(i) for i in grid[5:64:8]), 2)
    b14 = int(''.join(str(i) for i in grid[6:64:8]), 2)
    b15 = int(''.join(str(i) for i in grid[7:64:8]), 2)
    b16 = int(''.join(str(i) for i in grid[0:64:9]), 2)
    b17 = int(''.join(str(i) for i in grid[7:63:7]), 2)
    touchesgrass = True
    touchesgrass &= grid[1]+grid[10]+grid[62] == 2
    touchesgrass &= (grid[15] > grid[23])
    touchesgrass &= grid[9]+grid[10]+grid[14] == 2
    touchesgrass &= grid[26] << 3 == grid[43]+grid[44]
    touchesgrass &= (grid[32]+grid[33] < grid[1] + grid[62])
    touchesgrass &= (sum(int(i)==int(j) for i,j in [*zip(format(b2,"#010b"),format(b4,"#010b"))][2:]))==3
    touchesgrass &= bin(b6).count('1') == 5
    touchesgrass &= grid[61] + grid[42] + grid[43] == grid[25] + grid[26] + grid[27]
    touchesgrass &= grid[38]+grid[46]+grid[54]+grid[62]+grid[39]+grid[47]+grid[55]+grid[63] == 5
    touchesgrass &= (grid[14]^1!=grid[15])
    touchesgrass &= grid[57] + grid[59] + grid[60] == 3
    touchesgrass &= grid[18] != grid[23]
    touchesgrass &= grid[11]^grid[19]==1
    touchesgrass &= grid[50]==grid[51]
    touchesgrass &= grid[20]^grid[7]==1
    touchesgrass &= (grid[63]>>1 != grid[63]<<1)
    touchesgrass &= (sum(int(i)!=int(j) for i,j in [*zip(format(b9,"#010b"),format(b1,"#010b"))][2:]))==2
    touchesgrass &= grid[57] + grid[58] + grid[59] == 2
    touchesgrass &= grid[37]|grid[38] == grid[2]
    touchesgrass &= grid[4]==grid[48]==grid[49]
    touchesgrass &= grid[17] >=grid[30]
    touchesgrass &= (grid[0] == grid[19])
    touchesgrass &= grid[26] + grid[28] + grid[29] == grid[51] << 1
    touchesgrass &= grid[3] + grid[5] + grid[55] == 1
    touchesgrass &= (grid[30]==grid[34])
    touchesgrass &= sum(grid[14:17]) > grid[56] + grid[30] + grid[47]
    touchesgrass &= grid[7]!=grid[52]
    touchesgrass &= (b16//4)%2==0
    touchesgrass &= grid[8] == grid[9]
    touchesgrass &= (sum(int(i)!=int(j) for i,j in [*zip(format(b16,"#010b"),format(b15,"#010b"))][2:]))==3
    touchesgrass &= grid[6]^grid[56]==0
    touchesgrass &= (sum(grid[30:36])==3)
    touchesgrass &= grid[24]+grid[40] == grid[2]
    touchesgrass &= ~(grid[27]^grid[22])==-1
    touchesgrass &= grid[11]^grid[12]^grid[13]==grid[12]==grid[4]
    touchesgrass &= grid[31] == grid[47]
    touchesgrass &= grid[47]^grid[46] == 1
    touchesgrass &= grid[10] * 2 == grid[25] * 2 + grid[41]
    if touchesgrass:
        return 'tjctf{'+chr(b2)+chr(b9)+chr(b15)+chr(b16)+chr(b7)+chr(b4)+chr(b10)+chr(b12)+'}'
    return False
"""


if __name__ == "__main__":
    unittest.main()

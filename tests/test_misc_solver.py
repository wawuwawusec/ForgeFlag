from __future__ import annotations

import base64
import tempfile
import unittest
import zipfile
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.tools import ctf
from tests.png_fixtures import (
    png_with_extra_compressed_idat,
    png_with_rgb_lsb_payload,
    png_with_text_and_trailing_data,
    png_with_wrong_declared_height,
)


DOUBLEHELIX_FORMAT = (
    (1, 0),
    (0, 2),
    (0, 3),
    (0, 4),
    (1, 4),
    (2, 4),
    (3, 3),
    (4, 2),
    (5, 0),
    (5, 0),
    (4, 2),
    (3, 3),
    (2, 4),
    (1, 4),
    (0, 4),
    (0, 3),
    (0, 2),
    (1, 0),
)


def _doublehelix_script(payload: str, decayed_line_indexes: tuple[int, ...] = (8, 13)) -> str:
    bit_to_pair = {"00": "AT", "01": "CG", "10": "GC", "11": "TA"}
    bits = "".join(str((byte >> bit) & 1) for byte in payload.encode("utf-8") for bit in range(8))
    lines: list[str] = ['require "doublehelix"', ""]
    for index, pair_bits in enumerate(bits[position : position + 2] for position in range(0, len(bits), 2)):
        pair = bit_to_pair[pair_bits.ljust(2, "0")]
        offset, distance = DOUBLEHELIX_FORMAT[index % len(DOUBLEHELIX_FORMAT)]
        line = (" " * offset) + pair[0] + ("-" * distance) + pair[1]
        if index in decayed_line_indexes:
            line = " " * len(line)
        lines.append(line)
    return "\n".join(lines) + "\n"


class MiscSolverTest(unittest.TestCase):
    def test_misc_solver_runs_png_ihdr_analysis_for_image_puzzle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "ihdr.png"
            attachment.write_bytes(png_with_wrong_declared_height(width=2, actual_height=3, declared_height=9))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="ihdr-misc",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("ihdr-misc")
            finding = next(f for f in notebook.findings_for("ihdr-misc") if f.solver == "MiscSolver")

            self.assertEqual(summary["status"], "completed")
            self.assertEqual(finding.finding, "Analyzed misc image artifact")
            self.assertEqual(finding.evidence["ctf_scope"]["category"], "misc")
            self.assertEqual(finding.evidence["ctf_scope"]["research_context"], "local_or_authorized_ctf_lab")
            self.assertEqual(finding.evidence["png_ihdr"]["declared_height"], 9)
            self.assertEqual(finding.evidence["png_ihdr"]["derived_height"], 3)
            self.assertTrue(Path(finding.evidence["png_ihdr"]["repaired_path"]).is_file())

    def test_misc_solver_records_image_stego_hints_and_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "hint.png"
            attachment.write_bytes(png_with_text_and_trailing_data("flag{png_text_chunk}"))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="png-stego-misc",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("png-stego-misc")
            finding = next(f for f in notebook.findings_for("png-stego-misc") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{png_text_chunk}"])
        self.assertEqual(finding.finding, "Analyzed misc image artifact")
        self.assertIn("image_stego", finding.evidence)
        self.assertEqual(finding.evidence["image_stego"]["text_chunks"][0]["keyword"], "Comment")

    def test_misc_solver_decodes_base64_jpeg_comment_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "cat.jpg"
            encoded = base64.b64encode(b"SVIBRG{misc_jpeg_comment_b64}")
            attachment.write_bytes(
                b"\xff\xd8" + b"\xff\xfe" + (len(encoded) + 2).to_bytes(2, "big") + encoded + b"\xff\xd9"
            )
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-jpeg-comment-base64",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-jpeg-comment-base64")
            finding = next(f for f in notebook.findings_for("misc-jpeg-comment-base64") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["SVIBRG{misc_jpeg_comment_b64}"])
        self.assertIn("decoded_image_text_candidates", finding.evidence)
        recipes = {tuple(candidate["recipe"]) for candidate in finding.evidence["decoded_image_text_candidates"]}
        self.assertIn(("base64_decode",), recipes)

    def test_misc_solver_records_magic_extension_mismatch_for_png_named_jpg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "out.jpg"
            attachment.write_bytes(png_with_text_and_trailing_data("flag{misc_wrong_extension}"))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-wrong-extension",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-wrong-extension")
            finding = next(f for f in notebook.findings_for("misc-wrong-extension") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{misc_wrong_extension}"])
        self.assertEqual(finding.evidence["magic_extension_mismatch"]["declared_extension"], "jpg")
        self.assertEqual(finding.evidence["magic_extension_mismatch"]["actual_format"], "png")

    def test_misc_solver_recovers_flag_from_extra_png_idat_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "extra-idat.png"
            attachment.write_bytes(png_with_extra_compressed_idat("flag{extra_idat_stream}"))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="extra-idat-misc",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("extra-idat-misc")
            finding = next(f for f in notebook.findings_for("extra-idat-misc") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{extra_idat_stream}"])
        self.assertIn("idat_payloads", finding.evidence["image_stego"])

    def test_misc_solver_recovers_rgb_lsb_png_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "lsb.png"
            attachment.write_bytes(png_with_rgb_lsb_payload("&#x66;&#x6c;&#x61;&#x67;&#x7b;png_lsb&#x7d;"))
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="png-lsb-misc",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("png-lsb-misc")
            finding = next(f for f in notebook.findings_for("png-lsb-misc") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{png_lsb}"])
        self.assertIn("lsb_candidates", finding.evidence["image_stego"])
        self.assertEqual(finding.evidence["image_stego"]["lsb_candidates"][0]["recipe"], "b1,rgb,lsb,xy")

    def test_misc_solver_recovers_steghide_flag_from_jpeg_with_hint_passphrase(self) -> None:
        original_extract = getattr(ctf, "steghide_extract", None)
        calls: list[str] = []

        def fake_extract(path: str, passphrase: str, output_dir: str, scope=None):
            calls.append(passphrase)
            output = Path(output_dir) / "steghide-payload.txt"
            if passphrase != "diamond":
                return ctf.ToolResult(
                    tool="steghide",
                    target=path,
                    status="error",
                    evidence=["wrong passphrase"],
                    raw={"stdout": "", "stderr": "could not extract any data with that passphrase!"},
                )
            output.write_text("flag{jpeg_steghide_hint}", encoding="utf-8")
            return ctf.ToolResult(
                tool="steghide",
                target=path,
                status="success",
                evidence=["payload extracted"],
                artifacts=[str(output)],
                raw={"stdout": "wrote extracted data", "stderr": ""},
            )

        setattr(ctf, "steghide_extract", fake_extract)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                attachment = root / "out.jpg"
                app0 = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
                attachment.write_bytes(
                    b"\xff\xd8"
                    + b"\xff\xe0" + (len(app0) + 2).to_bytes(2, "big") + app0
                    + b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00"
                    + b"\x11\x22\x33"
                    + b"\xff\xd9"
                )
                notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
                notebook.add_challenge(
                    Challenge(
                        challenge_id="misc-jpeg-steghide",
                        category=ChallengeCategory.MISC,
                        title="King diamond",
                        description="A playing card. Try diamond.",
                        attachment_paths=(str(attachment),),
                    )
                )

                summary = Manager(notebook, RunConfig()).run_challenge("misc-jpeg-steghide")
                finding = next(f for f in notebook.findings_for("misc-jpeg-steghide") if f.solver == "MiscSolver")
        finally:
            if original_extract is None:
                delattr(ctf, "steghide_extract")
            else:
                setattr(ctf, "steghide_extract", original_extract)

        self.assertIn("diamond", calls)
        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{jpeg_steghide_hint}"])
        self.assertEqual(finding.evidence["jpeg_stego_tools"]["steghide_extract"]["status"], "success")

    def test_misc_solver_recovers_stegseek_flag_from_jpeg_hint_wordlist(self) -> None:
        original_extract = getattr(ctf, "steghide_extract", None)
        original_stegseek = getattr(ctf, "stegseek_crack", None)
        wordlists: list[tuple[str, ...]] = []

        def fake_extract(path: str, passphrase: str, output_dir: str, scope=None):
            return ctf.ToolResult(
                tool="steghide",
                target=path,
                status="error",
                evidence=["wrong passphrase"],
                raw={"stdout": "", "stderr": "could not extract any data with that passphrase!"},
            )

        def fake_stegseek(path: str, wordlist: tuple[str, ...], output_dir: str, scope=None):
            wordlists.append(wordlist)
            output = Path(output_dir) / "stegseek-payload.txt"
            output.write_text("flag{jpeg_stegseek_hint}", encoding="utf-8")
            return ctf.ToolResult(
                tool="stegseek",
                target=path,
                status="success",
                evidence=["passphrase found"],
                artifacts=[str(output)],
                raw={"stdout": "Found passphrase: diamond", "stderr": ""},
            )

        setattr(ctf, "steghide_extract", fake_extract)
        setattr(ctf, "stegseek_crack", fake_stegseek)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                attachment = root / "out.jpg"
                app0 = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
                attachment.write_bytes(
                    b"\xff\xd8"
                    + b"\xff\xe0" + (len(app0) + 2).to_bytes(2, "big") + app0
                    + b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00"
                    + b"\x11\x22\x33"
                    + b"\xff\xd9"
                )
                notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
                notebook.add_challenge(
                    Challenge(
                        challenge_id="misc-jpeg-stegseek",
                        category=ChallengeCategory.MISC,
                        title="King diamond",
                        description="A playing card. Try diamond.",
                        attachment_paths=(str(attachment),),
                    )
                )

                summary = Manager(notebook, RunConfig()).run_challenge("misc-jpeg-stegseek")
                finding = next(f for f in notebook.findings_for("misc-jpeg-stegseek") if f.solver == "MiscSolver")
        finally:
            if original_extract is None:
                delattr(ctf, "steghide_extract")
            else:
                setattr(ctf, "steghide_extract", original_extract)
            if original_stegseek is None:
                delattr(ctf, "stegseek_crack")
            else:
                setattr(ctf, "stegseek_crack", original_stegseek)

        self.assertTrue(any("diamond" in wordlist for wordlist in wordlists))
        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{jpeg_stegseek_hint}"])
        self.assertEqual(finding.evidence["jpeg_stego_tools"]["stegseek_crack"]["status"], "success")

    def test_misc_solver_decodes_flag_from_text_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "note.txt"
            attachment.write_text("Jmx0OyEtdm9pZC0tJmd0OyBmbGFnJTdCbWlzY190cmFuc2Zvcm0lN0Q=", encoding="utf-8")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-transform",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-transform")
            finding = next(f for f in notebook.findings_for("misc-transform") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{misc_transform}"])
        self.assertEqual(finding.finding, "Decoded misc transform candidates")
        recipes = {tuple(candidate["recipe"]) for candidate in finding.evidence["transform_candidates"]}
        self.assertIn(("base64_decode", "html_unescape", "url_decode"), recipes)

    def test_misc_solver_decodes_binary_ascii_attachment_with_metadata_noise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "binary.txt"
            attachment.write_text(
                "01100110 01101100 01100001 01100111 01111011 01100011 01101111 "
                "01110010 01110000 01110101 01110011 01011111 01101101 01101001 "
                "01110011 01100011 01111101\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-binary-corpus",
                    category=ChallengeCategory.MISC,
                    title="Corpus Misc binary ASCII",
                    description="Binary ASCII puzzle pattern.",
                    tags=("corpus", "web-smoke"),
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-binary-corpus")
            finding = next(f for f in notebook.findings_for("misc-binary-corpus") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{corpus_misc}"])
        recipes = {tuple(candidate["recipe"]) for candidate in finding.evidence["transform_candidates"]}
        self.assertIn(("binary_ascii_decode",), recipes)

    def test_misc_solver_accepts_ccir476_wrapped_flag_from_text_attachment(self) -> None:
        encoded = (
            "10110100110110110100111010011011010111010011010010110110101011010111001011010010111010011100110110010110110110"
            "10001111000111100110110101010110010111011010100101110111001000111101010101101101010110101110010110101101001011"
            "01101010110101101011001011010011101110001101100101110101101010110011011100001101101101101010101101101000111010"
            "11011001011101011010110010110011011110100010101110111000110110110100101011100101110111000101011100101110001101"
            "1"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "encoding"
            attachment.write_text(encoded, encoding="utf-8")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-ccir476",
                    category=ChallengeCategory.MISC,
                    title="DUCTF intercepted transmission",
                    description="Decode the binary-looking transmission and wrap the decoded message in DUCTF{}.",
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-ccir476")
            finding = next(f for f in notebook.findings_for("misc-ccir476") if f.solver == "MiscSolver")

        expected = "DUCTF{##TH3 QU0KK4'S AR3 H3LD 1N F4C1LITY #11911!}"
        self.assertEqual(summary["status"], "flag_found")
        self.assertIn(expected, summary["accepted_flags"])
        self.assertIn(expected, finding.evidence["flag_candidates"])

    def test_misc_solver_recovers_decayed_doublehelix_ruby_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "dna.rb"
            attachment.write_text(_doublehelix_script('puts"flag{doublehelix_decay}"'), encoding="utf-8")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-decayed-doublehelix",
                    category=ChallengeCategory.MISC,
                    title="DNADecay",
                    description="A damaged doublehelix Ruby source should still decode to the challenge flag.",
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-decayed-doublehelix")
            finding = next(f for f in notebook.findings_for("misc-decayed-doublehelix") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{doublehelix_decay}"])
        self.assertEqual(finding.finding, "Recovered decayed DoubleHelix Ruby source")
        self.assertEqual(finding.evidence["doublehelix_decay"]["ambiguous_positions"], [8, 13])
        self.assertIn("flag{doublehelix_decay}", finding.evidence["flag_candidates"])

    def test_misc_solver_recovers_chef_recipe_with_two_unknown_ingredients(self) -> None:
        recipe = """Chicken Parmi.

Ingredients.
?? dashes pain
?? cups effort
1 cup water
55 g alpha
32 g beta
31 g gamma
34 g delta
29 g epsilon
53 g zeta
20 g eta
14 g theta
3 g iota
15 g kappa
2 g lambda

Method.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add alpha to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add beta to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add gamma to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add delta to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add epsilon to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add zeta to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Remove eta from 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add theta to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Remove iota from 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add kappa to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Remove lambda from 1st mixing bowl.
Add effort to 1st mixing bowl.
Liquefy contents of the mixing bowl.
Pour contents of the mixing bowl into the 1st baking dish.
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "recipe.txt"
            attachment.write_text(recipe, encoding="utf-8")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-chef-recipe",
                    category=ChallengeCategory.MISC,
                    title="Chicken Parmi",
                    description="This recipe produces the flag in flag format.",
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-chef-recipe")
            finding = next(f for f in notebook.findings_for("misc-chef-recipe") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["DUCTF{chef}"])
        self.assertEqual(finding.finding, "Solved Chef-style misc recipe")
        self.assertEqual(finding.evidence["recipe_name"], "Chicken Parmi")
        self.assertIn("Chicken Parmi", finding.evidence["recipe_preamble"])
        self.assertEqual(finding.evidence["unknown_values"], {"pain": 20, "effort": 10})

    def test_misc_solver_records_archive_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "puzzle.zip"
            with zipfile.ZipFile(attachment, "w") as zf:
                zf.writestr("secret.txt", "redacted")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-archive",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-archive")
            finding = next(f for f in notebook.findings_for("misc-archive") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Analyzed misc archive artifact")
        self.assertEqual(finding.evidence["archive"]["kind"], "zip")
        self.assertIn("secret.txt", finding.evidence["archive"]["interesting_entries"])

    def test_misc_solver_extracts_flag_from_interesting_archive_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "nested.zip"
            with zipfile.ZipFile(attachment, "w") as zf:
                zf.writestr("docs/readme.txt", "look in the secret note")
                zf.writestr("secret/flag.txt", "flag{archive_text_preview}")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-archive-flag",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-archive-flag")
            finding = next(f for f in notebook.findings_for("misc-archive-flag") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{archive_text_preview}"])
        self.assertEqual(finding.evidence["archive_text_previews"][0]["name"], "secret/flag.txt")

    def test_misc_solver_records_hash_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "hash.txt"
            attachment.write_text("5d41402abc4b2a76b9719d911017c592", encoding="utf-8")
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-hash",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-hash")
            finding = next(f for f in notebook.findings_for("misc-hash") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Analyzed misc hash candidates")
        self.assertEqual(finding.evidence["hashes"]["candidates"][0]["type"], "md5_or_ntlm")

    def test_misc_solver_identifies_pickle_blacklist_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "sandbox.py"
            attachment.write_text(
                "import pickle\nBLACKLIST = ['os', 'system']\nblob = input('pickle> ')\npickle.loads(bytes.fromhex(blob))\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / ".forgeflag" / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="misc-pickle-sandbox",
                    category=ChallengeCategory.MISC,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("misc-pickle-sandbox")
            finding = next(f for f in notebook.findings_for("misc-pickle-sandbox") if f.solver == "MiscSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Identified misc sandbox serialization pattern")
        self.assertEqual(finding.evidence["pattern"], "pickle blacklist sandbox")
        self.assertIn("blacklist", finding.next_action.lower())


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
import zipfile


class RealCorpusAuditScriptTest(unittest.TestCase):
    def test_audit_parses_ductf_ctfcli_and_emits_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            case_root = root / "ductf2024" / "web" / "co2"
            publish = case_root / "publish"
            publish.mkdir(parents=True)
            (publish / "co2.zip").write_bytes(b"zip bytes")
            (case_root / "ctfcli.yaml").write_text(
                "\n".join(
                    [
                        'id: co2',
                        'name: co2',
                        'category: web',
                        'tags:',
                        '  - easy',
                        'files:',
                        '  - ./publish/co2.zip',
                        'flags:',
                        '  - DUCTF{_cl455_p0lluti0n_ftw_}',
                    ]
                ),
                encoding="utf-8",
            )
            manifest = Path(tmp) / "real-manifest.json"
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"

            completed = subprocess.run(
                [str(script), "--root", str(root), "--emit-manifest", str(manifest)],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["totals"]["cases"], 1)
            self.assertEqual(payload["totals"]["manifest_ready"], 1)
            self.assertEqual(payload["platforms"]["DownUnderCTF 2024"]["manifest_ready"], 1)
            self.assertEqual(payload["categories"]["web"]["manifest_ready"], 1)
            self.assertEqual(payload["cases"][0]["owner_roles"], ["WebExploitAgent"])
            self.assertEqual(payload["cases"][0]["tags"], ["easy"])
            emitted = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(emitted["cases"][0]["challenge_id"], "real-co2")
            self.assertEqual(emitted["cases"][0]["category"], "web")
            self.assertIn("Platform: DownUnderCTF 2024", emitted["cases"][0]["description"])
            self.assertEqual(emitted["cases"][0]["expected_flag"], "DUCTF{_cl455_p0lluti0n_ftw_}")
            self.assertIn(str((publish / "co2.zip").resolve()), emitted["cases"][0]["attachments"])

    def test_audit_parses_htb_readme_and_reports_backlog_for_missing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            case_root = root / "htb2024" / "misc" / "[Easy] Cubicle Riddle"
            case_root.mkdir(parents=True)
            (case_root / "README.md").write_text("Found the flag: HTB{r1ddle_m3_th1s}\n", encoding="utf-8")
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"
            manifest = Path(tmp) / "real-manifest.json"

            completed = subprocess.run(
                [str(script), "--root", str(root), "--emit-manifest", str(manifest)],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["totals"]["cases"], 1)
            self.assertEqual(payload["totals"]["with_oracle_flags"], 1)
            self.assertEqual(payload["totals"]["manifest_ready"], 0)
            self.assertNotIn("HTB{r1ddle_m3_th1s}", payload["cases"][0]["description"])
            self.assertEqual(payload["manager_backlog"][0]["reason"], "missing publish artifacts")

    def test_audit_blocks_manifest_ready_when_artifact_contains_placeholder_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            case_root = root / "ductf2024" / "crypto" / "toy-service"
            publish = case_root / "publish"
            publish.mkdir(parents=True)
            (publish / "server.py").write_text("FLAG = 'DUCTF{dummy_flag}'\n", encoding="utf-8")
            (case_root / "ctfcli.yaml").write_text(
                "\n".join(
                    [
                        "id: toy-service",
                        "name: toy service",
                        "category: crypto",
                        "description: |",
                        "  Recover the real service flag from the oracle.",
                        "tags:",
                        "  - hard",
                        "files:",
                        "  - ./publish/server.py",
                        "flags:",
                        "  - DUCTF{real_service_flag}",
                    ]
                ),
                encoding="utf-8",
            )
            manifest = Path(tmp) / "real-manifest.json"
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"

            completed = subprocess.run(
                [str(script), "--root", str(root), "--emit-manifest", str(manifest)],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["totals"]["manifest_ready"], 0)
            self.assertEqual(payload["cases"][0]["placeholder_flags"], ["DUCTF{dummy_flag}"])
            self.assertEqual(payload["cases"][0]["readiness_reason"], "artifact contains placeholder flags requiring replay oracle")
            emitted = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(emitted["cases"], [])

    def test_audit_blocks_placeholder_flag_inside_zip_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            case_root = root / "ductf2024" / "misc" / "archive-service"
            publish = case_root / "publish"
            publish.mkdir(parents=True)
            with zipfile.ZipFile(publish / "archive.zip", "w") as zf:
                zf.writestr("src/index.js", "const FLAG = 'DUCTF{testflag}'\n")
            (case_root / "ctfcli.yaml").write_text(
                "\n".join(
                    [
                        "id: archive-service",
                        "name: archive service",
                        "category: misc",
                        "files:",
                        "  - ./publish/archive.zip",
                        "flags:",
                        "  - DUCTF{real_archive_flag}",
                    ]
                ),
                encoding="utf-8",
            )
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"

            manifest = Path(tmp) / "real-manifest.json"
            completed = subprocess.run(
                [str(script), "--root", str(root), "--emit-manifest", str(manifest)],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["totals"]["manifest_ready"], 0)
            self.assertEqual(payload["cases"][0]["placeholder_flags"], ["DUCTF{testflag}"])

    def test_audit_parses_tjctf_challenge_yaml_with_flag_file_and_provide(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            case_root = root / "tjctf2024" / "crypto" / "assume"
            case_root.mkdir(parents=True)
            (case_root / "main.sage").write_text("print('challenge')\n", encoding="utf-8")
            (case_root / "log.txt").write_text("ciphertext output\n", encoding="utf-8")
            (case_root / "flag.txt").write_text("tjctf{real_flag_from_metadata}\n", encoding="utf-8")
            (case_root / "challenge.yaml").write_text(
                "\n".join(
                    [
                        "name: assume",
                        "author: samarth",
                        "description: |-",
                        "  assume for the sake of contradiction",
                        "flag:",
                        "  file: ./flag.txt",
                        "provide:",
                        "  - ./main.sage",
                        "  - ./log.txt",
                    ]
                ),
                encoding="utf-8",
            )
            manifest = Path(tmp) / "real-manifest.json"
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"

            completed = subprocess.run(
                [str(script), "--root", str(root), "--emit-manifest", str(manifest)],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["totals"]["cases"], 1)
            self.assertEqual(payload["totals"]["manifest_ready"], 1)
            case = payload["cases"][0]
            self.assertEqual(case["platform"], "TJCTF 2024")
            self.assertEqual(case["category"], "crypto")
            self.assertEqual(case["oracle_flags"], ["tjctf{real_flag_from_metadata}"])
            self.assertNotIn("flag.txt", "\n".join(case["publish_artifacts"]))

    def test_audit_parses_nus_challenge_yml_and_falls_back_to_dist_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            case_root = root / "nus-welcome-ctf-2024" / "forensics" / "Pcap 1"
            dist = case_root / "dist"
            dist.mkdir(parents=True)
            (dist / "baby.pcap").write_bytes(b"pcap bytes")
            (case_root / "solve.txt").write_text("do not include me\n", encoding="utf-8")
            (case_root / "challenge.yml").write_text(
                "\n".join(
                    [
                        "author: glendoodle",
                        "category: Forensics",
                        "description: Find the attempted login.",
                        "files:",
                        "- dist-pcap-1.zip",
                        "flags:",
                        "- grey{ju57_f0110w_7h3_57234m}",
                        "name: PCAP 1",
                    ]
                ),
                encoding="utf-8",
            )
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"
            manifest = Path(tmp) / "real-manifest.json"

            completed = subprocess.run(
                [str(script), "--root", str(root), "--emit-manifest", str(manifest)],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["totals"]["cases"], 1)
            self.assertEqual(payload["totals"]["manifest_ready"], 1)
            case = payload["cases"][0]
            self.assertEqual(case["platform"], "NUS Greyhats Welcome CTF 2024")
            self.assertEqual(case["category"], "forensics")
            self.assertEqual(case["oracle_flags"], ["grey{ju57_f0110w_7h3_57234m}"])
            self.assertEqual(Path(case["publish_artifacts"][0]).name, "baby.pcap")

    def test_audit_maps_competition_specific_pwn_categories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            case_root = root / "nus-welcome-ctf-2024" / "pwn" / "epic-boss-fight"
            dist = case_root / "distribution"
            dist.mkdir(parents=True)
            (dist / "challenge").write_bytes(b"elf")
            (case_root / "challenge.yml").write_text(
                "\n".join(
                    [
                        "category: dojo - pwn",
                        "description: defeat the dragon",
                        "files:",
                        "- challenge",
                        "flags:",
                        "- flag{i_wonder_how_negative_integers_are_shown_in_memory?}",
                        "name: pwn01",
                    ]
                ),
                encoding="utf-8",
            )
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"
            manifest = Path(tmp) / "real-manifest.json"

            completed = subprocess.run(
                [str(script), "--root", str(root), "--emit-manifest", str(manifest)],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["cases"][0]["category"], "pwn")
            self.assertEqual(payload["cases"][0]["owner_roles"], ["BinaryAgent"])

    def test_audit_parses_umdctf_challenge_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            case_root = root / "umdctf2024" / "crypto" / "key-recovery"
            case_root.mkdir(parents=True)
            (case_root / "encrypt.py").write_text("print('encrypt')\n", encoding="utf-8")
            (case_root / "modified.pem").write_text("damaged key\n", encoding="utf-8")
            (case_root / "flag.txt").write_text("UMDCTF{NTRUly_a_n1c3_j0b}\n", encoding="utf-8")
            (case_root / "challenge.yaml").write_text(
                "\n".join(
                    [
                        "name: Key Recovery",
                        "description: recover the private key",
                        "flag:",
                        "  file: flag.txt",
                        "provide:",
                        "  - ./encrypt.py",
                        "  - ./modified.pem",
                    ]
                ),
                encoding="utf-8",
            )
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"
            manifest = Path(tmp) / "real-manifest.json"

            completed = subprocess.run(
                [str(script), "--root", str(root), "--emit-manifest", str(manifest)],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["totals"]["manifest_ready"], 1)
            case = payload["cases"][0]
            self.assertEqual(case["platform"], "UMDCTF 2024")
            self.assertEqual(case["category"], "crypto")
            self.assertEqual(case["oracle_flags"], ["UMDCTF{NTRUly_a_n1c3_j0b}"])
            self.assertNotIn("flag.txt", "\n".join(case["publish_artifacts"]))

    def test_audit_parses_irisctf_readme_with_dist_handout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            case_root = root / "irisctf2024" / "l1pcap"
            dist = case_root / "dist"
            dist.mkdir(parents=True)
            (dist / "l1pcap.zip").write_bytes(b"rf capture archive")
            (case_root / "README.md").write_text(
                "\n".join(
                    [
                        "# l1pcap - Radio Frequency - ? points - ? solves",
                        "",
                        "Analyze the captured home remote signals.",
                        "",
                        "By: skat",
                        "",
                        "Flag: `irisctf{fsk_p4ck3ts_and_wh1t3n1ng_w3re_n0_m4tch_4_u}`",
                    ]
                ),
                encoding="utf-8",
            )
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"

            manifest = Path(tmp) / "real-manifest.json"
            completed = subprocess.run(
                [str(script), "--root", str(root), "--emit-manifest", str(manifest)],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["totals"]["manifest_ready"], 1)
            case = payload["cases"][0]
            self.assertEqual(case["platform"], "IrisCTF 2024")
            self.assertEqual(case["category"], "traffic")
            self.assertEqual(case["owner_roles"], ["TrafficAgent"])
            self.assertEqual(case["oracle_flags"], ["irisctf{fsk_p4ck3ts_and_wh1t3n1ng_w3re_n0_m4tch_4_u}"])
            self.assertNotIn("irisctf{fsk_p4ck3ts", case["description"])
            self.assertEqual(Path(case["publish_artifacts"][0]).name, "l1pcap.zip")
            emitted = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertNotIn("irisctf{fsk_p4ck3ts", emitted["cases"][0]["description"])

    def test_audit_blocks_git_lfs_pointer_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            case_root = root / "irisctf2024" / "birdie"
            dist = case_root / "dist"
            dist.mkdir(parents=True)
            (dist / "birdie.zip").write_text(
                "\n".join(
                    [
                        "version https://git-lfs.github.com/spec/v1",
                        "oid sha256:0123456789abcdef",
                        "size 1337",
                    ]
                ),
                encoding="utf-8",
            )
            (case_root / "README.md").write_text(
                "\n".join(
                    [
                        "# Birdie - Radio Frequency - ? points - ? solves",
                        "Decode the radio exchange.",
                        "Flag: `irisctf{lfs_pointer_should_not_be_ready}`",
                    ]
                ),
                encoding="utf-8",
            )
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"

            completed = subprocess.run([sys.executable, str(script), "--root", str(root)], capture_output=True, check=False, text=True)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["totals"]["manifest_ready"], 0)
            self.assertEqual(payload["cases"][0]["git_lfs_pointer_artifacts"], [str((dist / "birdie.zip").resolve())])
            self.assertEqual(payload["cases"][0]["readiness_reason"], "artifact is a Git LFS pointer; fetch real handout bytes first")

    def test_emitted_manifest_round_robins_ready_cases_across_platforms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heldout-cache"
            ductf_root = root / "ductf2024" / "web" / "co2"
            ductf_root.mkdir(parents=True)
            for name in ("a.zip", "b.zip"):
                (ductf_root / name).write_bytes(b"zip bytes")
            (ductf_root / "ctfcli.yaml").write_text(
                "\n".join(
                    [
                        "id: co2",
                        "name: co2",
                        "category: web",
                        "files:",
                        "  - ./a.zip",
                        "  - ./b.zip",
                        "flags:",
                        "  - DUCTF{co2_flag}",
                    ]
                ),
                encoding="utf-8",
            )
            tj_root = root / "tjctf2024" / "forensics" / "pals"
            tj_root.mkdir(parents=True)
            (tj_root / "pals.png").write_bytes(b"png bytes")
            (tj_root / "challenge.yaml").write_text(
                "\n".join(
                    [
                        "name: pals",
                        "description: palette puzzle",
                        "flag: tjctf{pals_flag}",
                        "provide:",
                        "  - pals.png",
                    ]
                ),
                encoding="utf-8",
            )
            manifest = Path(tmp) / "real-manifest.json"
            script = Path(__file__).resolve().parents[1] / "scripts" / "forgeflag-real-corpus-audit"

            completed = subprocess.run(
                [str(script), "--root", str(root), "--emit-manifest", str(manifest), "--manifest-limit", "2"],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            emitted = json.loads(manifest.read_text(encoding="utf-8"))
            platforms = {case["challenge_id"].split("-")[1] for case in emitted["cases"]}
            self.assertEqual(len(emitted["cases"]), 2)
            self.assertIn("co2", emitted["cases"][0]["challenge_id"])
            self.assertIn("tjctf2024", platforms)


if __name__ == "__main__":
    unittest.main()

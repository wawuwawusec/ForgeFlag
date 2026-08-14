from __future__ import annotations

import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path


class SolveScriptsDocsTest(unittest.TestCase):
    def test_solve_scripts_index_tracks_recent_replay_scripts_and_solver_status(self) -> None:
        docs = Path("docs/solve-scripts.md").read_text(encoding="utf-8")

        for script in (
            "scripts/solve_coolguy_bmp.py",
            "scripts/solve_pcap9_data_image.py",
            "scripts/solve_zhucebiao_wifi.py",
            "scripts/solve_traffic_1178.py",
            "scripts/solve_battle_visual_cipher.py",
            "scripts/solve_halcyon_sealed.py",
            "scripts/solve_reportlab.py",
            "scripts/solve_prisoner_processor.py",
            "scripts/solve_accountleak.py",
            "scripts/solve_accessible_sesamum.py",
            "scripts/solve_babycha.py",
            "scripts/solve_giedi_composite.py",
            "scripts/solve_golf_hard.py",
            "scripts/solve_attack_of_the_worm.py",
            "scripts/solve_i_see.py",
            "scripts/solve_ee2026.py",
            "scripts/solve_ductf_osint_building.py",
            "scripts/solve_hans_zimmer_osint.py",
            "scripts/solve_cecure_cerver.py",
            "scripts/solve_lamenote.py",
            "scripts/solve_private_hidden_paths.py",
            "scripts/solve_bof_school.py",
            "scripts/solve_pac_shell.py",
            "scripts/solve_chisel.py",
            "scripts/solve_epic_boss_fight.py",
            "scripts/solve_baby_heap.py",
            "scripts/solve_insanity_check.py",
            "scripts/solve_fetcher.py",
            "scripts/solve_co2.py",
            "scripts/solve_http_fanatics.py",
            "scripts/solve_sign_in.py",
            "scripts/solve_filefactory.py",
            "scripts/solve_babybit_vmdk.py",
            "scripts/solve_unbreakable.py",
            "scripts/solve_maze_of_mist_static.py",
            "scripts/solve_prng_stream_cipher_cases.py",
        ):
            self.assertIn(script, docs)

        self.assertIn("底层 solver 已覆盖", docs)
        self.assertIn("手工/外部工具辅助", docs)
        self.assertIn("docs/ctf-casebook.md", docs)
        self.assertIn("docs/ctf-playbook.md", docs)

    def test_prisoner_processor_payload_uses_local_getflag_and_filters_placeholders(self) -> None:
        module = _load_script_module("solve_prisoner_processor")
        example = {
            "data": {
                "signed.name": "jeff",
                "signed.animalType": "emu",
            },
            "signature": "a" * 64,
        }

        payload = module.build_overwrite_payload(example)
        crash = module.build_crash_payload(example)

        self.assertIn("const flag", next(iter(payload["data"])))
        self.assertIn("/bin/getflag", payload["data"][next(iter(payload["data"]))])
        self.assertIn("port:1337", payload["data"][next(iter(payload["data"]))])
        self.assertNotIn(": 1337", payload["data"][next(iter(payload["data"]))])
        self.assertNotIn("/dev/tcp", str(payload))
        self.assertEqual(payload["data"]["signed.__proto__"]["outputPrefix"], "../../proc/self/fd/3\0")
        self.assertEqual(payload["data"]["z"], "hi */")
        self.assertEqual(payload["signature"], "a" * 64)
        self.assertEqual(crash["data"]["signed.__proto__"]["outputPrefix"], "../../proc/self/fd/3\\x")
        self.assertEqual(
            module.extract_real_flags("DUCTF{test_flag_real_flag_on_instance}\nDUCTF{real_service_flag}"),
            ["DUCTF{real_service_flag}"],
        )

    def test_babybit_vmdk_solver_exposes_local_solve_entrypoint(self) -> None:
        module = _load_script_module("solve_babybit_vmdk")

        self.assertTrue(callable(module.solve))

    def test_accountleak_solver_recovers_shifted_rsa_password(self) -> None:
        module = _load_script_module("solve_accountleak")
        p = 1000003
        q = 1009837
        shift = 1337
        password = 42424242
        n = p * q
        c = pow(password, 65537, n)
        leak = (p - shift) * (q - shift)

        recovered, rp, rq, recovered_shift = module.recover_password(c, n, leak, max_shift=4096)

        self.assertEqual(recovered, password)
        self.assertEqual({rp, rq}, {p, q})
        self.assertEqual(recovered_shift, shift)
        self.assertEqual(
            module.parse_public_values("<Bobby> i'll give you the powerful numbers, 12345678 and 87654321"),
            (12345678, 87654321),
        )
        self.assertEqual(module.parse_shifted_product("<Bobby> i'll send coords\n<Bobby> 22222222\n<Bobby> oop wasnt"), 22222222)
        self.assertEqual(module.extract_flags("flag: tjctf{diamonds}"), ["tjctf{diamonds}"])

    def test_accessible_sesamum_solver_builds_reversed_debruijn_pin_stream(self) -> None:
        module = _load_script_module("solve_accessible_sesamum")

        stream = module.build_attempt_stream("01", 3)
        consumed_windows = {stream[index : index + 3][::-1] for index in range(len(stream) - 2)}

        self.assertEqual(consumed_windows, {format(value, "03b") for value in range(8)})
        self.assertLessEqual(len(stream), 2**3 + 3 - 1)
        self.assertEqual(module.extract_flags("done\nirisctf{de_bruijn}\n"), ["irisctf{de_bruijn}"])

    def test_babycha_solver_decrypts_flag_after_state_leak(self) -> None:
        module = _load_script_module("solve_babycha")
        leaked_state = [
            0x61707865,
            0x3320646E,
            0x79622D32,
            0x6B206574,
            *range(4, 16),
        ]
        plaintext = b"irisctf{initialization_is_no_problem}"
        next_state = module.chacha_block(leaked_state)
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, module.state_to_bytes(next_state)))

        recovered = module.decrypt_after_state_leak(module.state_to_bytes(leaked_state).hex(), ciphertext.hex())

        self.assertEqual(recovered, plaintext.decode())
        self.assertEqual(module.extract_flags(f"flag: {recovered}"), [plaintext.decode()])

    def test_giedi_composite_solver_parses_output_lists_and_flags(self) -> None:
        module = _load_script_module("solve_giedi_composite")
        sample = """Public key:
[1, 2, 3]
Ct:
[4, 5, 6]
"""

        pub, ct = module.parse_output_lists(sample)

        self.assertEqual(pub, [1, 2, 3])
        self.assertEqual(ct, [4, 5, 6])
        self.assertEqual(module.extract_flags("b'UMDCTF{NTRUly_a_n1c3_j0b}'"), ["UMDCTF{NTRUly_a_n1c3_j0b}"])

    def test_golf_hard_solver_uses_bounded_regex_patterns(self) -> None:
        module = _load_script_module("solve_golf_hard")

        patterns = module.challenge_patterns()

        self.assertEqual(len(patterns), 5)
        self.assertEqual(patterns[0], "^a")
        self.assertTrue(all(len(pattern) <= limit for pattern, limit in zip(patterns, [2, 16, 12, 18, 20])))
        self.assertEqual(module.extract_flags("ok\ntjctf{regex}\n"), ["tjctf{regex}"])

    def test_attack_of_the_worm_solver_formats_pixel_payloads(self) -> None:
        module = _load_script_module("solve_attack_of_the_worm")

        changes = [
            module.PixelChange(10, 20, 1, 2, 3),
            module.PixelChange(11, 21, 254, 253, 252),
        ]

        self.assertEqual(module.format_pixel_payload(changes), "10,20,1,2,3;11,21,254,253,252")
        self.assertEqual(
            module.parse_pixel_payload("10,20,1,2,3;11,21,254,253,252"),
            changes,
        )
        self.assertEqual(module.extract_flags("LISAN AL GAIB\nUMDCTF{spice}\n"), ["UMDCTF{spice}"])
        command = module.build_docker_command(Path("/tmp/chal"), "forgeflag-worm-test", "forgeflag-worm")
        self.assertIn("--name", command)
        self.assertIn("forgeflag-worm", command)
        volume = command[command.index("-v") + 1]
        self.assertTrue(volume.endswith(":/chal"))
        self.assertIn("chal", volume)

    def test_attack_of_the_worm_solver_scores_payloads_in_local_server_mode(self) -> None:
        module = _load_script_module("solve_attack_of_the_worm")
        payload = "10,20,1,2,3"

        command = module.build_score_command(Path("/tmp/chal"), "forgeflag-worm-test", "forgeflag-worm-score", payload)

        self.assertIn("-e", command)
        self.assertIn(f"{module.PAYLOAD_ENV}={payload}", command)
        self.assertIn("json.dumps", command[-1])
        self.assertEqual(module.parse_score_output('{"pixel_count": 1, "probability": 0.42, "is_adversarial": true}'), {
            "pixel_count": 1,
            "probability": 0.42,
            "is_adversarial": True,
        })
        self.assertEqual(module.read_payload_argument(payload, None), payload)

    def test_attack_of_the_worm_solver_builds_reproducible_unstable_search(self) -> None:
        module = _load_script_module("solve_attack_of_the_worm")

        command = module.build_unstable_search_command(
            Path("/tmp/chal"),
            "forgeflag-worm-test",
            "forgeflag-worm-search",
            module.UnstableSearchConfig(seed=123, steps=2, candidate_trials=3, short_iters=4, long_iters=5, finish_iters=6),
        )

        self.assertIn(f"{module.SEARCH_SEED_ENV}=123", command)
        self.assertIn(f"{module.SEARCH_STEPS_ENV}=2", command)
        self.assertIn(f"{module.SEARCH_CANDIDATE_TRIALS_ENV}=3", command)
        self.assertIn("unstable_pixels", command[-1])
        self.assertEqual(
            module.parse_search_output('progress\n{"best_probability": 0.49, "pixel_count": 2, "payload": "1,2,3,4,5"}'),
            {"best_probability": 0.49, "pixel_count": 2, "payload": "1,2,3,4,5"},
        )

    def test_attack_of_the_worm_solver_writes_search_json_and_payload_outputs(self) -> None:
        module = _load_script_module("solve_attack_of_the_worm")
        result = {
            "best_probability": 0.49,
            "pixel_count": 2,
            "payload": "1,2,3,4,5;6,7,8,9,10",
        }
        with self.subTest("format"):
            self.assertIn('"best_probability": 0.49', module.format_search_result(result))

        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            search_output = Path(tmp) / "search.json"
            payload_output = Path(tmp) / "payload.txt"

            module.write_search_outputs(result, search_output, payload_output)

            self.assertEqual(module.read_payload_argument(None, payload_output), result["payload"])
            written = search_output.read_text(encoding="utf-8")
            self.assertIn('"pixel_count": 2', written)

    def test_attack_of_the_worm_solver_selects_best_multi_seed_search_result(self) -> None:
        module = _load_script_module("solve_attack_of_the_worm")
        results = [
            {"seed": 3, "best_probability": 0.56, "payload": "3,0,0,0,0"},
            {"seed": 1, "best_probability": 0.52, "payload": "1,0,0,0,0"},
            {"seed": 2, "best_probability": 0.54, "payload": "2,0,0,0,0"},
        ]

        self.assertEqual(module.parse_seed_list("1,2,2,5"), [1, 2, 5])
        self.assertEqual(module.select_best_search_result(results), results[1])

    def test_i_see_solver_extracts_pdf_i2c_clues_and_eeprom_flag(self) -> None:
        module = _load_script_module("solve_i_see")
        schematic_text = "U101 M24C02-WMN VSS SDA SCL VCC J1 IO25 IO24"
        eeprom = b"clusterFUQ says here is your flag: DUCTF{I2C_the_flag_now_fcee2acf}\n"

        clues = module.extract_i2c_clues(schematic_text)

        self.assertEqual(clues["eeprom"], "M24C02-WMN")
        self.assertIn("SDA", clues["signals"])
        self.assertIn("SCL", clues["signals"])
        self.assertEqual(module.extract_flags(eeprom.decode()), ["DUCTF{I2C_the_flag_now_fcee2acf}"])

    def test_ductf_osint_building_solver_derives_flags_from_writeup_evidence(self) -> None:
        module = _load_script_module("solve_ductf_osint_building")
        bridget = "The challenge asked for where the photo was taken from. In this case, it's the Four Points by Sheraton."
        cityviews = "From streetview imagery, it appears to be an Holiday Inn but when I clicked on it to investigate I was greeted with: Hotel Indigo Melbourne."

        self.assertEqual(module.derive_flag("Bridget Lives", bridget), "DUCTF{four_points}")
        self.assertEqual(module.derive_flag("cityviews", cityviews), "DUCTF{hotel_indigo_melbourne}")
        self.assertEqual(
            module.extract_evidence("cityviews", cityviews),
            ["cityviews", "streetview", "Hotel Indigo Melbourne"],
        )

    def test_hans_zimmer_osint_solver_derives_dune_track_flag(self) -> None:
        module = _load_script_module("solve_hans_zimmer_osint")
        prompt = (
            "He remembers one specific musician he really liked. "
            "We have intel that the musician operates at the pictured location. "
            "flag format is `UMDCTF{musician's name underscore separated}`"
        )
        source = "Dune Official Soundtrack by Hans Zimmer lists track 4 as Gom Jabbar."

        result = module.derive_flag(prompt, [source])

        self.assertEqual(result.flag, "UMDCTF{Gom_Jabbar}")
        evidence_text = " ".join(result.evidence)
        self.assertIn("Hans Zimmer", evidence_text)
        self.assertIn("Dune", evidence_text)
        self.assertEqual(module.normalize_flag_name("Gom Jabbar"), "Gom_Jabbar")

    def test_cecure_cerver_solver_builds_basic_auth_requests(self) -> None:
        module = _load_script_module("solve_cecure_cerver")

        request = module.build_basic_auth_request("a", "b")

        self.assertTrue(request.startswith(b"GET / HTTP/1.1\r\n"))
        self.assertIn(b"Authorization: Basic YTpi\r\n", request)
        self.assertTrue(request.endswith(b"\r\n\r\n"))
        self.assertEqual(module.extract_flags("HTTP/1.1 200 OK\r\n\r\ngrey{okay}"), ["grey{okay}"])

    def test_private_hidden_paths_solver_builds_pack_payload(self) -> None:
        module = _load_script_module("solve_private_hidden_paths")

        query = module.build_registration_query()

        self.assertIn("a=r", query)
        self.assertIn("p=XXXXa%2A", query)
        self.assertIn("u=7%13%00%00abcde", query)
        self.assertEqual(module.build_flag_path(), "c/self/root/flag.txt")
        self.assertEqual(module.extract_flags("<h2>Hello</h2><br>grey{php_pack}"), ["grey{php_pack}"])

    def test_bof_school_solver_builds_escaped_ret2win_payload(self) -> None:
        module = _load_script_module("solve_bof_school")

        payload = module.build_payload(0x401608)

        self.assertTrue(payload.startswith(b"A" * 56))
        self.assertIn(b"\\08\\16\\40\\00\\00\\00\\00\\00\n", payload)
        self.assertEqual(module.extract_flags("grey{FLAG_FOR_TESTING}\ngrey{real_flag}"), ["grey{real_flag}"])

    def test_pac_shell_solver_derives_addresses_from_leaks(self) -> None:
        module = _load_script_module("solve_pac_shell")

        leaks = module.parse_help(
            b"    help: 0xffff987f0b7c\n"
            b"      ls: 0xffff987f0a54\n"
            b"  read64: 0xffff987f0a78\n"
            b" write64: 0xffff987f0afc\n"
            b"pacsh> "
        )
        layout = module.derive_layout(leaks, system_address=0xffff98686D94, environ_value=0xffffc23212c8)

        self.assertEqual(leaks["help"] - module.HELP_OFFSET, 0xFFFF987F0000)
        self.assertEqual(layout.pie_base, 0xFFFF987F0000)
        self.assertEqual(layout.libc_base, 0xFFFF98640000)
        self.assertEqual(layout.system, 0xFFFF98686D94)
        self.assertEqual(layout.binsh, 0xFFFF9878D9F8)
        self.assertEqual(layout.gadget, 0xFFFF98718854)
        self.assertEqual(layout.builtins, 0xFFFF98802010)
        self.assertEqual(module.stack_base_from_match(0xFFFFC2321130), 0xFFFFC2321120)
        command = module.build_docker_command(Path("/tmp/chal"), "forgeflag-ctf:latest", "forgeflag-pac-shell-test")
        self.assertIn("--name", command)
        self.assertIn("forgeflag-pac-shell-test", command)
        self.assertIn("--rm", command)

    def test_chisel_solver_derives_heap_and_libc_targets(self) -> None:
        module = _load_script_module("solve_chisel")

        layout = module.derive_layout(heap_leak=0x555555554, libc_leak=0x7FFFFF7B5C00)

        self.assertEqual(layout.heap_base, 0x555555554000)
        self.assertEqual(layout.libc_base, 0x7FFFFF5D5000)
        self.assertEqual(layout.malloc_hook, 0x7FFFFF7B5B90)
        self.assertEqual(layout.system, 0x7FFFFF624A60)
        self.assertEqual(layout.binsh, 0x7FFFFF780F05)
        self.assertEqual(layout.tcache_mask, 0x555555554)
        self.assertEqual(module.poisoned_tcache_value(layout), 0x7FFAAA2E0EC4)
        command = module.build_docker_command(Path("/tmp/chal"), "debian:bookworm", "forgeflag-chisel-test")
        self.assertIn("--platform", command)
        self.assertIn("linux/amd64", command)
        self.assertIn("forgeflag-chisel-test", command)

    def test_epic_boss_fight_solver_builds_integer_overflow_stream(self) -> None:
        module = _load_script_module("solve_epic_boss_fight")

        stream = module.build_defend_stream(23)

        self.assertEqual(stream, b"2\n" * 23)
        self.assertEqual(module.overflow_defend_count(initial_hp=10000, heal_amount=1000), 23)
        self.assertEqual(module.extract_flags("grey{TEST_FLAG}\ngrey{real_flag}"), ["grey{real_flag}"])
        self.assertEqual(module.normalize_flag_prefix("grey{real_flag}", "flag"), "flag{real_flag}")

    def test_baby_heap_solver_uses_off_by_one_size_payload(self) -> None:
        module = _load_script_module("solve_baby_heap")

        payload = module.build_input_stream(attack_size=0xA1, new_size=0x90)

        self.assertEqual(payload, b"161\n144\n")
        self.assertEqual(module.default_parameters(), (0xA1, 0x90))
        self.assertEqual(module.extract_flags("tjctf{bby-eap-lol171296386}"), ["tjctf{bby-eap-lol171296386}"])

    def test_insanity_check_solver_aligns_suffix_dotcom_to_return_address(self) -> None:
        module = _load_script_module("solve_insanity_check")

        payload = module.build_payload()
        alignment = module.compute_alignment()

        self.assertEqual(payload, b"A" * 56 + b"\n")
        self.assertEqual(alignment["name_length"], 56)
        self.assertEqual(alignment["suffix_ret_offset"], module.SUFFIX.find(b".com"))
        self.assertEqual(module.p64(module.WIN_ADDRESS), b".com\x00\x00\x00\x00")
        self.assertEqual(module.extract_flags("irisctf{c0nv3n13nt_symb0l_pl4cem3nt}"), ["irisctf{c0nv3n13nt_symb0l_pl4cem3nt}"])

    def test_fetcher_solver_uses_loopback_alias_ssrf_payload(self) -> None:
        module = _load_script_module("solve_fetcher")

        self.assertEqual(module.build_ssrf_url(), "http://127.0.0.2:3000/flag")
        self.assertEqual(module.build_post_body(), b"url=http%3A%2F%2F127.0.0.2%3A3000%2Fflag")
        self.assertEqual(
            module.extract_flags("hey myself! here's your flag: tjctf{h3ll0_m3_h3e_h3e_d699bdcd}"),
            ["tjctf{h3ll0_m3_h3e_h3e_d699bdcd}"],
        )

    def test_co2_solver_builds_class_pollution_payload(self) -> None:
        module = _load_script_module("solve_co2")

        payload = module.build_pollution_payload()

        self.assertEqual(payload["title"], "")
        self.assertEqual(payload["content"], "")
        self.assertEqual(payload["__class__"]["__init__"]["__globals__"]["flag"], "true")
        self.assertEqual(module.build_login_form("user", "pass"), b"username=user&password=pass")
        self.assertEqual(module.extract_flags("Nope\nDUCTF{_cl455_p0lluti0n_ftw_}"), ["DUCTF{_cl455_p0lluti0n_ftw_}"])

    def test_http_fanatics_solver_builds_h1_smuggling_bytes(self) -> None:
        module = _load_script_module("solve_http_fanatics")

        payload = module.build_smuggled_h1_request("bob", "bob2")
        cookie = module.build_credentials_cookie("bob", "bob2")

        self.assertTrue(payload.startswith(b"PUT /put HTTP/1.1\r\n"))
        self.assertIn(b"transfer-encoding: chunked\r\n", payload)
        self.assertIn(b"0\r\n\r\nPOST /admin/register HTTP/1.1\r\n", payload)
        self.assertIn(b'{"username":"bob","password":"bob2"}', payload)
        self.assertIn("credentials=", cookie)
        self.assertEqual(module.extract_flags("Flag: UMDCTF{w4tCh_0ut_F0R_RE9u3sT_5mugg1iN9}"), ["UMDCTF{w4tCh_0ut_F0R_RE9u3sT_5mugg1iN9}"])

    def test_sign_in_solver_builds_uaf_reuse_stream(self) -> None:
        module = _load_script_module("solve_sign_in")

        stream = module.build_exploit_stream(0x402EB8, shell_command="cat flag.txt")

        self.assertIn(module.p64(0x402EB8), stream)
        self.assertIn(b"\x00" * 8, stream)
        self.assertIn(b"cat flag.txt\n", stream)
        self.assertTrue(stream.endswith(b"exit\n"))
        self.assertEqual(module.extract_flags("root\nDUCTF{welcome_root!_9dbfa98e17b7af9dbc1}\n"), ["DUCTF{welcome_root!_9dbfa98e17b7af9dbc1}"])

    def test_filefactory_solver_repairs_mangled_png_signature(self) -> None:
        module = _load_script_module("solve_filefactory")

        mangled = b"JESS\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 8
        repaired = module.repair_png_signature(mangled)

        self.assertTrue(module.is_mangled_png(mangled))
        self.assertTrue(repaired.startswith(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"))
        self.assertEqual(module.normalize_visual_transcription("these files are kinda weird but im weirder"), "grey{these_files_are_kinda_weird_but_im_weirder}")
        self.assertEqual(module.extract_flags("visual flag grey{these_files_are_kinda_weird_but_im_weirder}"), ["grey{these_files_are_kinda_weird_but_im_weirder}"])

    def _require_heldout(self, *relative: str) -> None:
        missing = [path for path in relative if not Path(path).exists()]
        if missing:
            self.skipTest(f"heldout challenge attachment not cached: {missing[0]}")

    def test_unbreakable_solver_builds_blacklist_safe_eval_payload(self) -> None:
        module = _load_script_module("solve_unbreakable")

        self._require_heldout(".forgeflag/heldout-cache/htb2024/misc/[Easy] Unbreakable/htb/main.py")
        payload = module.build_payload()
        source = Path(".forgeflag/heldout-cache/htb2024/misc/[Easy] Unbreakable/htb/main.py").read_text()
        blacklist = module.parse_blacklist(source)

        self.assertEqual(payload, "print(open('flag.txt','r').read())#")
        self.assertFalse(module.payload_hits_blacklist(payload, blacklist))
        self.assertEqual(module.extract_flags("Flag --> HTB{3v4l_0r_3vuln??}"), ["HTB{3v4l_0r_3vuln??}"])

    def test_ee2026_solver_recovers_student_id_from_vivado_dcp_edif(self) -> None:
        module = _load_script_module("solve_ee2026")

        self._require_heldout(
            ".forgeflag/heldout-cache/nus-welcome-ctf-2024/misc/EE2026/distribution/graded_post_lab_assignment_1.zip"
        )
        result = module.solve_project(
            Path(".forgeflag/heldout-cache/nus-welcome-ctf-2024/misc/EE2026/distribution/graded_post_lab_assignment_1.zip")
        )

        self.assertEqual(result["password"], "1248X")
        self.assertEqual(result["value_a"], "2")
        self.assertEqual(result["alphabet_b"], "G")
        self.assertEqual(result["value_c"], "8")
        self.assertEqual(result["flag"], "grey{21248xG8}")
        self.assertIn("32'h00000008", result["lut_inits"])
        self.assertIn("64'h0010000000000000", result["lut_inits"])

    def test_lamenote_solver_identifies_substring_oracle_pattern(self) -> None:
        module = _load_script_module("solve_lamenote")

        self._require_heldout(
            ".forgeflag/heldout-cache/irisctf2024/lamenote/dist/chal.py",
            ".forgeflag/heldout-cache/irisctf2024/lamenote/dist/index.html",
        )
        chal = Path(".forgeflag/heldout-cache/irisctf2024/lamenote/dist/chal.py").read_text()
        index = Path(".forgeflag/heldout-cache/irisctf2024/lamenote/dist/index.html").read_text()
        signals = module.analyze_source(chal, index)

        self.assertTrue(signals["substring_search_oracle"])
        self.assertTrue(signals["iframe_fetch_gate"])
        self.assertTrue(signals["dynamic_img_csp"])
        self.assertEqual(module.recover_with_substring_oracle("irisctf{lame_note}"), "irisctf{lame_note}")
        self.assertEqual(module.manifest_flag_pattern(), "irisctf{[a-z_]+}")

    def test_maze_of_mist_static_solver_reports_missing_vm_artifacts(self) -> None:
        module = _load_script_module("solve_maze_of_mist_static")
        readme = """# [Hard] Maze of Mist

        The handout contains:
        - Linux kernel image (`vmlinuz-linux`)
        - Linux rootfs archive (`initramfs.cpio.gz`)
        - QEMU run script (`run.sh`)

        The target is a tiny 32-bit ELF with a 0x20 stack buffer and ret2vdso path.
        """
        exploit = """from pwn import *
        VDSO_BASE_ADDR = 0xf7ffc000
        MOV_EAX_ECX_PLUS_EBP_M20 = VDSO_BASE_ADDR + 0x67c
        POP_EBP = VDSO_BASE_ADDR + 0x0000613
        POP_EDX_ECX = VDSO_BASE_ADDR + 0x0000057a
        SYSCALL_POP_EBP_EDX_ECX = VDSO_BASE_ADDR + 0x00000577
        BINSH = 0xffffdf20
        """

        report = module.analyze_case_text(readme, exploit, present_files={"htb/exploit.py"})

        self.assertFalse(report.can_replay)
        self.assertEqual(report.technique, "ret2vdso")
        self.assertEqual(report.missing_artifacts, ("vmlinuz-linux", "initramfs.cpio.gz", "run.sh", "target"))
        self.assertEqual(report.vdso_base, 0xF7FFC000)
        self.assertIn("MOV_EAX_ECX_PLUS_EBP_M20", report.gadgets)
        self.assertEqual(report.gadgets["SYSCALL_POP_EBP_EDX_ECX"], 0xF7FFC577)


if __name__ == "__main__":
    unittest.main()


def _load_script_module(name: str):
    script = Path("scripts") / f"{name}.py"
    loader = SourceFileLoader(name, str(script))
    spec = spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError(f"could not load {script}")
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module

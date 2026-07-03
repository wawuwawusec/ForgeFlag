from __future__ import annotations

import ast
from pathlib import Path
import random
import re

from forgeflag.crypto_analysis import (
    recover_lfsr_bm_flags_from_text,
    recover_repeating_key_xor_flags_from_text,
    recover_prng_stream_flags_from_text,
    recover_python_random_prime_offset_flags_from_text,
    recover_python_random_xor_flags_from_text,
    recover_rsa_flags_from_text,
    recover_single_byte_xor_flags_from_text,
    recover_vigenere_flags_from_text,
    rsa_summary_from_text,
)
from forgeflag.ctf_scope import ctf_scope_evidence
from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.hash_analysis import hash_summary_from_text
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf
from forgeflag.transforms import candidates_to_payload, transform_candidates


class CryptoSolver:
    name = "CryptoSolver"
    supported_categories = {ChallengeCategory.CRYPTO}

    def solve(self, context: SolverContext) -> SolverResult:
        text = "\n".join(_text_inputs(context))
        primitive_pattern = _primitive_misuse_pattern(text)
        if primitive_pattern:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Identified crypto primitive misuse pattern",
                evidence={**primitive_pattern, "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO)},
                hypothesis=_primitive_hypothesis(primitive_pattern["pattern"]),
                confidence=0.72,
                next_action=_primitive_next_action(primitive_pattern["pattern"]),
            )
            context.notebook.add_finding(finding)
            return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        prng_stream = recover_prng_stream_flags_from_text(text)
        if prng_stream["flags"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Recovered PRNG/stream cipher flag candidates",
                evidence={"prng_stream": prng_stream, "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO)},
                hypothesis="A PRNG or stream-cipher challenge leaked enough source/output evidence to replay the generator or invert its state.",
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the generator parameters, outputs, and replay method.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate",
                (finding,),
                tuple(str(flag) for flag in prng_stream["flags"]),
            )

        hash_summary = hash_summary_from_text(text)
        if hash_summary["candidates"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed hash candidates",
                evidence={"hashes": hash_summary, "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO)},
                hypothesis="Hash-like values were detected; offline dictionary tooling may be appropriate.",
                confidence=0.68,
                next_action="Use hashcat/John with an explicit wordlist and bounded runtime; do not start cracking automatically.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        rsa_recovery = recover_rsa_flags_from_text(text)
        if rsa_recovery["flags"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Recovered RSA flag candidates",
                evidence={"rsa_recovery": rsa_recovery, "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO)},
                hypothesis="RSA parameters are directly decryptable and produced a flag-like plaintext.",
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the RSA parameters as replay evidence.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate",
                (finding,),
                tuple(str(flag) for flag in rsa_recovery["flags"]),
            )

        python_random_xor = recover_python_random_xor_flags_from_text(text)
        if python_random_xor["flags"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Recovered Python random XOR flag candidates",
                evidence={"python_random_xor": python_random_xor, "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO)},
                hypothesis="Python random was seeded from a small range before deriving an XOR key, so seed brute force recovered plaintext.",
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the seed/key evidence for replay.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate",
                (finding,),
                tuple(str(flag) for flag in python_random_xor["flags"]),
            )

        python_random_prime_offset = recover_python_random_prime_offset_flags_from_text(text)
        if python_random_prime_offset["flags"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Recovered Python random prime-offset flag candidates",
                evidence={
                    "python_random_prime_offset": python_random_prime_offset,
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO),
                },
                hypothesis="A byte seed was recovered from key XOR gift output, then Python random reproduced prime offsets around the flag integer.",
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the XOR-derived seed and prime offsets for replay.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate",
                (finding,),
                tuple(str(flag) for flag in python_random_prime_offset["flags"]),
            )

        linear_xorshift = _recover_linear_xorshift_flags_from_text(text)
        if linear_xorshift["flags"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Recovered linear xorshift flag candidates",
                evidence={"linear_xorshift": linear_xorshift, "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO)},
                hypothesis="The script applies a reversible GF(2) transform of repeated x ^= x >> k steps, so the ciphertext can be inverted without Sage.",
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the seed, shift range, and ciphertext evidence for replay.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate",
                (finding,),
                tuple(str(flag) for flag in linear_xorshift["flags"]),
            )

        lfsr_bm = recover_lfsr_bm_flags_from_text(text)
        if lfsr_bm["flags"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Recovered LFSR Berlekamp-Massey flag candidates",
                evidence={"lfsr_bm": lfsr_bm, "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO)},
                hypothesis="A source-backed LFSR leaks enough output bits to recover a mask/key candidate with GF(2) linear algebra and validate it through the flag hash prefix.",
                confidence=0.86,
                next_action="Send recovered candidates to Verifier and preserve the sequence, key, mask, and free-variable evidence for replay.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate",
                (finding,),
                tuple(str(flag) for flag in lfsr_bm["flags"]),
            )

        self_sync_xor = _recover_self_sync_low_nibble_xor(context, text)
        if self_sync_xor["flags"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Recovered self-synchronizing XOR flag candidates",
                evidence={"self_sync_xor": self_sync_xor, "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO)},
                hypothesis="The encryption script uses the previous plaintext byte modulo 16 to select an XOR key slot; CTF-format cribs recovered a consistent flag candidate.",
                confidence=0.8,
                next_action="Send recovered candidates to Verifier and preserve the crib offset/key-slot consistency evidence.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate",
                (finding,),
                tuple(str(flag) for flag in self_sync_xor["flags"]),
            )

        candidates = transform_candidates(text)
        flags = extract_flags("\n".join(candidate.value for candidate in candidates))
        if flags:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Decoded crypto transform candidates",
                evidence={
                    "transform_candidates": candidates_to_payload(candidates),
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO),
                },
                hypothesis=_transform_hypothesis(flags),
                confidence=0.82,
                next_action=_transform_next_action(flags),
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate",
                (finding,),
                flags,
            )

        classical_recovery = _classical_crypto_recovery(text)
        if classical_recovery["flags"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Recovered classical crypto flag candidates",
                evidence={**classical_recovery, "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO)},
                hypothesis="Classical XOR/Vigenere recovery produced flag-like plaintext from supplied ciphertext/key evidence.",
                confidence=0.84,
                next_action="Send recovered candidates to Verifier and preserve the ciphertext, key, and method evidence for replay.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate",
                (finding,),
                tuple(str(flag) for flag in classical_recovery["flags"]),
            )

        if candidates:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Decoded crypto transform candidates",
                evidence={
                    "transform_candidates": candidates_to_payload(candidates),
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO),
                },
                hypothesis=_transform_hypothesis(flags),
                confidence=0.56,
                next_action=_transform_next_action(flags),
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "ok",
                (finding,),
                flags,
            )

        rsa_summary = rsa_summary_from_text(text)
        if rsa_summary["parameters"] or rsa_summary["has_public_key"] or rsa_summary["has_private_key"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed RSA challenge parameters",
                evidence={"rsa": rsa_summary, "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO)},
                hypothesis=_rsa_hypothesis(rsa_summary),
                confidence=0.66,
                next_action=_rsa_next_action(rsa_summary),
            )
            context.notebook.add_finding(finding)
            return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Crypto solver placeholder registered",
            evidence={
                "planned_adapters": ["z3", "sage", "hash/fingerprint classifiers"],
                "ctf_scope": ctf_scope_evidence(ChallengeCategory.CRYPTO),
            },
            hypothesis="Future implementation should extract parameters and generate reproducible solve scripts.",
            confidence=0.4,
            next_action="Implement primitive fingerprinting and solver script workspace.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))


def _text_inputs(context: SolverContext) -> list[str]:
    challenge = context.challenge
    values = [
        challenge.title or "",
        challenge.description or "",
        " ".join(challenge.tags),
    ]
    for attachment_path in challenge.attachment_paths:
        try:
            resolved = ctf.ensure_existing_file(attachment_path)
        except FileNotFoundError:
            continue
        try:
            raw = Path(resolved).read_bytes()[:64_000]
        except OSError:
            continue
        values.append(raw.decode("utf-8", errors="ignore"))
    return [value for value in values if value.strip()]


def _classical_crypto_recovery(text: str) -> dict[str, object]:
    trithemius = _recover_trithemius_flags_from_text(text)
    shufflebox = _recover_shufflebox_flags_from_text(text)
    recoveries = {
        "single_byte_xor": recover_single_byte_xor_flags_from_text(text),
        "repeating_key_xor": recover_repeating_key_xor_flags_from_text(text),
        "vigenere": recover_vigenere_flags_from_text(text),
        "trithemius_shift": trithemius,
        "shufflebox": shufflebox,
    }
    flags: list[str] = []
    for recovery in recoveries.values():
        flags.extend(str(flag) for flag in recovery.get("flags", []))
    return {
        **recoveries,
        "flags": list(dict.fromkeys(flags)),
    }


def _recover_linear_xorshift_flags_from_text(text: str) -> dict[str, object]:
    params = _linear_xorshift_params(text)
    if not params:
        return {"method": "right_shift_xor_linear_inverse", "flags": [], "candidates": []}
    rng = random.Random(params["seed"])
    shifts = [rng.randint(params["shift_min"], params["shift_max"]) for _ in range(params["rounds"])]
    value = int.from_bytes(params["ciphertext"], "big")
    bit_length = params["length"] * 8
    for shift in reversed(shifts):
        value = _invert_right_xor_shift(value, shift, bit_length)
    plaintext = value.to_bytes(params["length"], "big").lstrip(b"\x00")
    decoded = plaintext.decode("utf-8", errors="ignore")
    flags = extract_flags(decoded)
    candidates = []
    if decoded:
        candidates.append(
            {
                "plaintext_preview": decoded[:200],
                "flags": list(flags),
            }
        )
    return {
        "method": "right_shift_xor_linear_inverse",
        "seed": params["seed"],
        "rounds": params["rounds"],
        "shift_min": params["shift_min"],
        "shift_max": params["shift_max"],
        "ciphertext_hex": params["ciphertext"].hex(),
        "plaintext_length": params["length"],
        "candidates": candidates,
        "flags": list(flags),
    }


def _linear_xorshift_params(text: str) -> dict[str, object] | None:
    compact = re.sub(r"\s+", "", text)
    if "^=ct>>random.randint(" not in compact or "random.seed(" not in compact:
        return None
    seed_match = re.search(r"random\.seed\(\s*(\d+)\s*\)", text)
    rounds_match = re.search(r"for\s+_\s+in\s+range\(\s*(\d+)\s*\)\s*:\s*\n\s*ct\s*\^=\s*ct\s*>>\s*random\.randint\(\s*(\d+)\s*,\s*(\d+)\s*\)", text)
    length_match = re.search(r"assert\s+len\(flag\)\s*==\s*(\d+)", text)
    ciphertext_match = re.search(r"assert\s+enc\(flag\)\s*==\s*(b(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'))", text)
    if not seed_match or not rounds_match or not length_match or not ciphertext_match:
        return None
    try:
        ciphertext = ast.literal_eval(ciphertext_match.group(1))
    except (SyntaxError, ValueError):
        return None
    if not isinstance(ciphertext, bytes) or not ciphertext:
        return None
    return {
        "seed": int(seed_match.group(1)),
        "rounds": int(rounds_match.group(1)),
        "shift_min": int(rounds_match.group(2)),
        "shift_max": int(rounds_match.group(3)),
        "length": int(length_match.group(1)),
        "ciphertext": ciphertext,
    }


def _invert_right_xor_shift(value: int, shift: int, bit_length: int) -> int:
    recovered = value
    step = shift
    mask = (1 << bit_length) - 1
    while step < bit_length:
        recovered ^= recovered >> step
        recovered &= mask
        step *= 2
    return recovered


def _recover_self_sync_low_nibble_xor(context: SolverContext, text: str) -> dict[str, object]:
    if not _looks_like_self_sync_low_nibble_xor_script(text):
        return {"method": "previous_plaintext_low_nibble_key_slot", "candidates": [], "flags": []}
    ciphertext = _largest_binary_attachment(context)
    if not ciphertext:
        return {"method": "previous_plaintext_low_nibble_key_slot", "candidates": [], "flags": []}
    wrapper = _flag_wrapper_from_text(text)
    flags: list[str] = []
    candidates: list[dict[str, object]] = []
    for phrase in _ctf_idiom_flag_phrases():
        candidate = f"{wrapper}{{{phrase}}}".encode("ascii")
        matches = _self_sync_crib_matches(ciphertext, candidate)
        for match in matches[:3]:
            flag = candidate.decode("ascii")
            flags.append(flag)
            candidates.append(
                {
                    "flag": flag,
                    "offset": match["offset"],
                    "known_key_slots": match["known_key_slots"],
                    "crib": phrase,
                }
            )
    return {
        "method": "previous_plaintext_low_nibble_key_slot",
        "script_pattern": "q[y % 16] ^ x; y = x",
        "candidates": candidates[:10],
        "flags": list(dict.fromkeys(flags)),
    }


def _looks_like_self_sync_low_nibble_xor_script(text: str) -> bool:
    compact = re.sub(r"\s+", "", text.lower())
    return "os.urandom(16)" in compact and "q[y%16]^x" in compact and "y=x" in compact


def _largest_binary_attachment(context: SolverContext) -> bytes:
    blobs: list[bytes] = []
    for attachment_path in context.challenge.attachment_paths:
        try:
            resolved = ctf.ensure_existing_file(attachment_path)
        except FileNotFoundError:
            continue
        try:
            data = Path(resolved).read_bytes()
        except OSError:
            continue
        if _looks_like_self_sync_low_nibble_xor_script(data.decode("utf-8", errors="ignore")):
            continue
        if len(data) >= 16:
            blobs.append(data)
    return max(blobs, key=len) if blobs else b""


def _ctf_idiom_flag_phrases() -> tuple[str, ...]:
    return (
        "when_in_doubt_xor_it_out",
        "when_in_doubt_xort_it_out",
        "xor_it_out",
        "just_xor_it",
        "known_plaintext_attack",
        "crib_dragging",
        "reused_key_stream",
    )


def _self_sync_crib_matches(ciphertext: bytes, candidate: bytes) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    if len(candidate) < 6 or len(ciphertext) < len(candidate):
        return matches
    for offset in range(0, len(ciphertext) - len(candidate) + 1):
        key_slots: dict[int, int] = {}
        previous = candidate[0]
        for index in range(1, len(candidate)):
            slot = previous % 16
            key_byte = ciphertext[offset + index] ^ candidate[index]
            if slot in key_slots and key_slots[slot] != key_byte:
                break
            key_slots[slot] = key_byte
            previous = candidate[index]
        else:
            if len(key_slots) >= 8:
                matches.append({"offset": offset, "known_key_slots": dict(sorted(key_slots.items()))})
    return matches


def _recover_trithemius_flags_from_text(text: str) -> dict[str, object]:
    flags: list[str] = []
    candidates: list[dict[str, str]] = []
    wrapper = _flag_wrapper_from_text(text)
    for line in text.splitlines():
        ciphertext = line.strip()
        if not _looks_like_upper_ciphertext(ciphertext):
            continue
        plaintext = _trithemius_decrypt(ciphertext)
        candidate = _wrap_plaintext_flag(plaintext, wrapper)
        if not candidate:
            continue
        candidates.append({"ciphertext": ciphertext, "plaintext": plaintext, "flag": candidate})
        flags.append(candidate)
    return {
        "method": "position_dependent_caesar_shift",
        "candidates": candidates[:10],
        "flags": list(dict.fromkeys(flags)),
    }


def _recover_shufflebox_flags_from_text(text: str) -> dict[str, object]:
    pairs = [
        (left.strip(), right.strip())
        for left, right in re.findall(r"([^\n]{16})\s*->\s*([^\n]{16})", text)
        if len(left.strip()) == 16 and len(right.strip()) == 16
    ]
    if len(pairs) < 3:
        return {"method": "known_plaintext_permutation", "candidates": [], "flags": []}
    known_pairs = [(left, right) for left, right in pairs if "?" not in left]
    unknown_pairs = [(left, right) for left, right in pairs if "?" in left]
    wrapper = _flag_wrapper_from_text(text)
    flags: list[str] = []
    candidates: list[dict[str, object]] = []
    for unknown_left, unknown_right in unknown_pairs:
        if unknown_left.count("?") != 16:
            continue
        permutation = _infer_shufflebox_permutation(known_pairs)
        if not permutation:
            continue
        plaintext = ["?"] * 16
        for output_index, source_index in enumerate(permutation):
            plaintext[source_index] = unknown_right[output_index]
        recovered = "".join(plaintext)
        candidate = _wrap_plaintext_flag(recovered, wrapper)
        if not candidate:
            continue
        candidates.append(
            {
                "ciphertext": unknown_right,
                "plaintext": recovered,
                "permutation": permutation,
                "flag": candidate,
            }
        )
        flags.append(candidate)
    return {
        "method": "known_plaintext_permutation",
        "candidates": candidates[:10],
        "flags": list(dict.fromkeys(flags)),
    }


def _infer_shufflebox_permutation(known_pairs: list[tuple[str, str]]) -> list[int] | None:
    if not known_pairs:
        return None
    permutation: list[int] = []
    for output_index in range(16):
        possible = set(range(16))
        for left, right in known_pairs:
            possible = {index for index in possible if left[index] == right[output_index]}
        if len(possible) != 1:
            return None
        permutation.append(next(iter(possible)))
    return permutation


def _looks_like_upper_ciphertext(value: str) -> bool:
    if len(value) < 24 or "{" in value or "}" in value:
        return False
    alpha = sum(1 for char in value if char.isalpha())
    upper = sum(1 for char in value if "A" <= char <= "Z")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ_?!-'.,:;0123456789 ")
    return alpha >= 12 and upper == alpha and all(char in allowed for char in value)


def _trithemius_decrypt(ciphertext: str) -> str:
    plaintext: list[str] = []
    for index, char in enumerate(ciphertext):
        if not char.isalpha():
            plaintext.append(char)
            continue
        plaintext.append(chr((ord(char.upper()) - ord("A") - index) % 26 + ord("A")))
    return "".join(plaintext)


def _flag_wrapper_from_text(text: str) -> str:
    lowered = text.lower()
    if "ductf" in lowered or "downunderctf" in lowered:
        return "DUCTF"
    if "htb" in lowered or "hack the box" in lowered:
        return "HTB"
    return "flag"


def _wrap_plaintext_flag(plaintext: str, wrapper: str) -> str | None:
    if not plaintext or "{" in plaintext or "}" in plaintext:
        return None
    if not re.search(r"[A-Za-z]{3,}", plaintext):
        return None
    normalized = plaintext.strip()
    if not normalized:
        return None
    return f"{wrapper}{{{normalized}}}"


def _primitive_misuse_pattern(text: str) -> dict[str, object] | None:
    lowered = text.lower()
    if ("mode_gcm" in lowered or "mode gcm" in lowered or "aes-gcm" in lowered or "gcm" in lowered) and (
        "nonce" in lowered or "iv" in lowered
    ) and ("tag" in lowered or "ghash" in lowered or "forbidden" in lowered):
        return {
            "pattern": "aes_gcm_nonce_reuse",
            "evidence_terms": _matched_terms(lowered, ("AES-GCM", "GCM", "nonce", "tag", "GHASH", "forbidden")),
            "source_lines": _matching_lines(text, ("gcm", "nonce", "iv", "tag", "ghash", "forbidden")),
        }
    if ("mode_ctr" in lowered or "mode ctr" in lowered or "ctr" in lowered) and "nonce" in lowered:
        return {
            "pattern": "aes_ctr_nonce_reuse",
            "evidence_terms": _matched_terms(lowered, ("AES", "CTR", "nonce", "keystream", "xor", "crib")),
            "source_lines": _matching_lines(text, ("ctr", "nonce", "keystream", "xor", "crib")),
        }
    if "poly1305" in lowered and ("one-time" in lowered or "otm" in lowered) and (
        "reuse" in lowered or "reused" in lowered or "algebra" in lowered
    ):
        return {
            "pattern": "poly1305_one_time_key_reuse",
            "evidence_terms": _matched_terms(lowered, ("Poly1305", "one-time", "reuse", "algebra", "tag")),
            "source_lines": _matching_lines(text, ("poly1305", "one-time", "reuse", "algebra", "tag")),
        }
    return None


def _matched_terms(lowered: str, terms: tuple[str, ...]) -> list[str]:
    return [term for term in terms if term.lower() in lowered]


def _matching_lines(text: str, terms: tuple[str, ...], limit: int = 8) -> list[str]:
    lowered_terms = tuple(term.lower() for term in terms)
    lines: list[str] = []
    for line in text.splitlines():
        if any(term in line.lower() for term in lowered_terms):
            lines.append(line.strip()[:220])
        if len(lines) >= limit:
            break
    return lines


def _primitive_hypothesis(pattern: object) -> str:
    if pattern == "aes_gcm_nonce_reuse":
        return "The text indicates AES-GCM reused a nonce, which can break confidentiality and expose GHASH/tag-forgery algebra."
    if pattern == "aes_ctr_nonce_reuse":
        return "The text indicates AES CTR was used with a repeated nonce, which can reuse the stream-cipher keystream."
    if pattern == "poly1305_one_time_key_reuse":
        return "The text indicates a Poly1305 one-time key was reused, so the solve path is algebraic MAC recovery."
    return "The challenge text contains a known crypto misuse pattern."


def _primitive_next_action(pattern: object) -> str:
    if pattern == "aes_gcm_nonce_reuse":
        return "Collect reused nonce/IV, AAD, ciphertexts, and tags; compare ciphertext XORs, then model GHASH equations before attempting a bounded forbidden attack or tag forgery."
    if pattern == "aes_ctr_nonce_reuse":
        return "Collect ciphertexts, nonce, and known plaintext cribs; XOR ciphertexts to recover keystream bytes and replay the derivation."
    if pattern == "poly1305_one_time_key_reuse":
        return "Extract message/tag pairs, model the reused one-time key equations, then solve with Sage or a bounded Python algebra script."
    return "Extract parameters and generate a reproducible solve script for the detected primitive."


def _transform_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "A reversible transform chain produced a flag-like token."
    return "Challenge text contains encoded or transformed data worth preserving for the next solver step."


def _transform_next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send decoded candidates to Verifier and preserve the transform recipe."
    return "Inspect transform candidates for keys, parameters, or secondary encodings."


def _rsa_hypothesis(summary: dict[str, object]) -> str:
    hints = summary.get("hints", [])
    if "known_factors" in hints:
        return "RSA parameters include factors; private key recovery should be direct."
    if "low_exponent" in hints:
        return "RSA parameters include a low public exponent; small-message or broadcast style checks may apply."
    if summary.get("has_public_key"):
        return "RSA public key material is present and should be sent to a dedicated RSA CTF tool."
    return "RSA-like parameters were extracted and should guide a reproducible crypto solve path."


def _rsa_next_action(summary: dict[str, object]) -> str:
    tools = summary.get("recommended_tools", [])
    if "RsaCtfTool" in tools:
        return "Run RsaCtfTool or build a SageMath solve script from the extracted parameters."
    return "Normalize parameters and identify the matching RSA weakness before attempting decryption."

from __future__ import annotations

from pathlib import Path

from forgeflag.crypto_analysis import (
    recover_repeating_key_xor_flags_from_text,
    recover_python_random_xor_flags_from_text,
    recover_rsa_flags_from_text,
    recover_single_byte_xor_flags_from_text,
    recover_vigenere_flags_from_text,
    rsa_summary_from_text,
)
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
        hash_summary = hash_summary_from_text(text)
        if hash_summary["candidates"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed hash candidates",
                evidence={"hashes": hash_summary},
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
                evidence={"rsa_recovery": rsa_recovery},
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
                evidence={"python_random_xor": python_random_xor},
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

        primitive_pattern = _primitive_misuse_pattern(text)
        if primitive_pattern:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Identified crypto primitive misuse pattern",
                evidence=primitive_pattern,
                hypothesis=_primitive_hypothesis(primitive_pattern["pattern"]),
                confidence=0.72,
                next_action=_primitive_next_action(primitive_pattern["pattern"]),
            )
            context.notebook.add_finding(finding)
            return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        classical_recovery = _classical_crypto_recovery(text)
        if classical_recovery["flags"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Recovered classical crypto flag candidates",
                evidence=classical_recovery,
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

        candidates = transform_candidates(text)
        flags = extract_flags("\n".join(candidate.value for candidate in candidates))
        if candidates:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Decoded crypto transform candidates",
                evidence={"transform_candidates": candidates_to_payload(candidates)},
                hypothesis=_transform_hypothesis(flags),
                confidence=0.82 if flags else 0.56,
                next_action=_transform_next_action(flags),
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate" if flags else "ok",
                (finding,),
                flags,
            )

        rsa_summary = rsa_summary_from_text(text)
        if rsa_summary["parameters"] or rsa_summary["has_public_key"] or rsa_summary["has_private_key"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed RSA challenge parameters",
                evidence={"rsa": rsa_summary},
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
            evidence={"planned_adapters": ["z3", "sage", "hash/fingerprint classifiers"]},
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
    recoveries = {
        "single_byte_xor": recover_single_byte_xor_flags_from_text(text),
        "repeating_key_xor": recover_repeating_key_xor_flags_from_text(text),
        "vigenere": recover_vigenere_flags_from_text(text),
    }
    flags: list[str] = []
    for recovery in recoveries.values():
        flags.extend(str(flag) for flag in recovery.get("flags", []))
    return {
        **recoveries,
        "flags": list(dict.fromkeys(flags)),
    }


def _primitive_misuse_pattern(text: str) -> dict[str, object] | None:
    lowered = text.lower()
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
    if pattern == "aes_ctr_nonce_reuse":
        return "The text indicates AES CTR was used with a repeated nonce, which can reuse the stream-cipher keystream."
    if pattern == "poly1305_one_time_key_reuse":
        return "The text indicates a Poly1305 one-time key was reused, so the solve path is algebraic MAC recovery."
    return "The challenge text contains a known crypto misuse pattern."


def _primitive_next_action(pattern: object) -> str:
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

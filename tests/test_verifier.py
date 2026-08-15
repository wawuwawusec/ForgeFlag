from __future__ import annotations

import unittest

from forgeflag.domain import Finding
from forgeflag.verifier import Verifier


class VerifierTest(unittest.TestCase):
    def test_verifier_rejects_prompt_template_flags_even_when_present_in_evidence(self) -> None:
        finding = Finding(
            challenge_id="osint-template",
            solver="ReconSolver",
            finding="Found flag-like token in challenge text",
            evidence={
                "description": "NOTE: wrap answers like DUCTF{name_of_building}, DUCTF{password123!}, or DUCTF{[1]_[2]_[3]_[4]}."
            },
        )

        result = Verifier().verify(
            [finding],
            (
                "DUCTF{name_of_building}",
                "DUCTF{password123!}",
                "DUCTF{[1]_[2]_[3]_[4]}",
                "DUCTF{NOT_THE_REAL_FLAG}",
                "tjctf{'+chr(b2)+chr(b9)+'}",
                "DUCTF{real_answer_123}",
            ),
        )

        self.assertEqual(result.accepted, ())
        self.assertEqual(
            result.rejected,
            (
                "DUCTF{name_of_building}",
                "DUCTF{password123!}",
                "DUCTF{[1]_[2]_[3]_[4]}",
                "DUCTF{NOT_THE_REAL_FLAG}",
                "tjctf{'+chr(b2)+chr(b9)+'}",
                "DUCTF{real_answer_123}",
            ),
        )

    def test_verifier_still_accepts_evidence_backed_non_template_flags(self) -> None:
        finding = Finding(
            challenge_id="real-flag",
            solver="ForensicsSolver",
            finding="Recovered flag from artifact",
            evidence={"artifact_text": "DUCTF{hotel_indigo_melbourne}"},
        )

        result = Verifier().verify([finding], ("DUCTF{hotel_indigo_melbourne}",))

        self.assertEqual(result.accepted, ("DUCTF{hotel_indigo_melbourne}",))
        self.assertEqual(result.rejected, ())

    def test_verifier_accepts_reverse_recovered_input_when_evidence_marks_it(self) -> None:
        finding = Finding(
            challenge_id="rev-key",
            solver="ReverseSolver",
            finding="Recovered argv validation input",
            evidence={
                "elf_argv_repeating_xor": {
                    "pattern": "ELF argv repeating XOR validation against .rodata string",
                    "recovered_input": "reverse_xor",
                    "flag_candidates": ["reverse_xor"],
                },
                "flag_candidates": ["reverse_xor"],
            },
        )

        result = Verifier().verify([finding], ("reverse_xor", "wrong_key"))

        self.assertEqual(result.accepted, ("reverse_xor",))
        self.assertEqual(result.rejected, ("wrong_key",))


if __name__ == "__main__":
    unittest.main()


class PlaceholderFlagRejectionTest(unittest.TestCase):
    def setUp(self):
        self.verifier = Verifier()

    def _rejects(self, flag: str) -> None:
        result = self.verifier.verify([], (flag,))
        self.assertEqual(result.accepted, ())
        self.assertIn(flag, result.rejected)

    def test_handout_placeholder_bodies_are_rejected(self):
        for candidate in (
            "CTF{fake flag}",
            "CTF{fakeflag}",
            "CTF{TestingFlag}",
            "CTF{FlagGoesHere}",
            "CTF{not_the_real_thing}",
            "CTF{not-a-real-flag}",
            "CTF{*censored*}",
            "CTF{flag}",
            "CTF{[0-9a-zA-Z_@!?-]+}",
        ):
            with self.subTest(candidate=candidate):
                self._rejects(candidate)

    def test_real_flag_shapes_still_accepted(self):
        from forgeflag.domain import Finding, FindingStatus

        flag = "CTF{TheySayTheEmptyCanRattlesTheMost}"
        finding = Finding(
            challenge_id="x",
            solver="MiscSolver",
            finding="strings hit",
            evidence={"stdout": flag},
            confidence=0.9,
            status=FindingStatus.ACTIVE,
        )
        result = self.verifier.verify([finding], (flag,))
        self.assertEqual(result.accepted, (flag,))

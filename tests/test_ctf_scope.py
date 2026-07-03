from __future__ import annotations

import unittest

from forgeflag.ctf_scope import DEFAULT_CTF_CHALLENGE_ASSUMPTION, ctf_scope_evidence
from forgeflag.domain import ChallengeCategory


class CTFScopeTest(unittest.TestCase):
    def test_default_assumption_is_carried_for_unknown_challenge_context(self) -> None:
        evidence = ctf_scope_evidence(ChallengeCategory.UNKNOWN)

        self.assertIn("local or authorized CTF challenge", DEFAULT_CTF_CHALLENGE_ASSUMPTION)
        self.assertEqual(evidence["default_user_assumption"], DEFAULT_CTF_CHALLENGE_ASSUMPTION)
        self.assertEqual(evidence["research_context"], "local_or_authorized_ctf_lab")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, Finding
from forgeflag.notebook import SQLiteNotebook
from forgeflag.pwn_replay import record_pwn_replay_proof


class PwnReplayProofTest(unittest.TestCase):
    def test_record_pwn_replay_proof_promotes_exploit_plan_to_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="pwn3-proof",
                    category=ChallengeCategory.PWN,
                    attachment_paths=("/tmp/2016-CCTF-pwn3",),
                )
            )
            notebook.add_finding(
                Finding(
                    challenge_id="pwn3-proof",
                    solver="PwnSolver",
                    finding="Analyzed pwn binary artifact",
                    evidence={"exploit_plan": {"workflow": "ftp_heap_format_string"}},
                    confidence=0.6,
                    next_action="Replay exploit harness.",
                )
            )
            notebook.record_run(
                "pwn3-proof",
                "exploit_plan",
                {
                    "challenge_id": "pwn3-proof",
                    "status": "exploit_plan",
                    "accepted_flags": [],
                    "rejected_flags": [],
                },
            )

            summary = record_pwn_replay_proof(
                notebook,
                "pwn3-proof",
                transcript="command: cat flag\nflag{forgeflag_local_pwn3_replay}\n",
                command="docker run ... python3 scripts/solve_pwn3_local_replay.py",
                test_flag="flag{forgeflag_local_pwn3_replay}",
                docker_image="forgeflag-i386-pwnlab:latest",
            )
            latest = notebook.latest_run_summary("pwn3-proof")
            findings = notebook.findings_for("pwn3-proof")
            observations = notebook.observations_for("pwn3-proof")

        self.assertEqual(summary["status"], "exploit_verified")
        self.assertEqual(summary["proof_status"], "exploit_verified")
        self.assertTrue(summary["proof"]["verified"])
        self.assertEqual(summary["proof"]["evidence"]["test_flag"], "flag{forgeflag_local_pwn3_replay}")
        self.assertEqual(latest["status"], "exploit_verified")
        self.assertTrue(any(f.status.value == "verified" and "replay_proof" in f.evidence for f in findings))
        self.assertTrue(any(obs.kind == "exploit_replay" for obs in observations))


if __name__ == "__main__":
    unittest.main()

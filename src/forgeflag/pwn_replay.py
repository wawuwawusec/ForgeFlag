from __future__ import annotations

from typing import Any

from forgeflag.domain import Finding, FindingStatus, Observation
from forgeflag.manager import _proof_status
from forgeflag.notebook import SQLiteNotebook
from forgeflag.report import ReportBuilder


def record_pwn_replay_proof(
    notebook: SQLiteNotebook,
    challenge_id: str,
    *,
    transcript: str,
    command: str,
    test_flag: str,
    docker_image: str,
) -> dict[str, Any]:
    challenge = notebook.get_challenge(challenge_id)
    evidence = {
        "replay_proof": {
            "status": "success",
            "command": command,
            "docker_image": docker_image,
            "test_flag": test_flag,
            "transcript": transcript,
            "proof_kind": "local_test_flag_command_execution",
        }
    }
    notebook.add_finding(
        Finding(
            challenge_id=challenge_id,
            solver="PwnSolver",
            finding="Verified local pwn exploit replay",
            evidence=evidence,
            hypothesis="The exploit reached command execution inside the local authorized CTF harness.",
            confidence=0.95,
            next_action="Preserve the transcript and environment details as proof-of-solve evidence.",
            status=FindingStatus.VERIFIED,
        )
    )
    notebook.add_observation(
        Observation(
            challenge_id=challenge_id,
            source="PwnProofReplay",
            kind="exploit_replay",
            summary=f"Local pwn replay executed command and recovered test flag {test_flag}",
            evidence=evidence["replay_proof"],
        )
    )
    findings = notebook.findings_for(challenge_id)
    proof = _proof_status(challenge.category, findings, ())
    previous = notebook.latest_run_summary(challenge_id) or {}
    summary: dict[str, Any] = {
        **previous,
        "challenge_id": challenge_id,
        "status": proof["status"],
        "proof_status": proof["status"],
        "proof": proof,
        "accepted_flags": list(previous.get("accepted_flags") or []),
        "rejected_flags": list(previous.get("rejected_flags") or []),
        "observations": len(notebook.observations_for(challenge_id)),
        "replay_report": ReportBuilder().build(
            challenge_id,
            (),
            findings,
            notebook.observations_for(challenge_id),
            challenge=challenge,
        ),
    }
    notebook.record_run(challenge_id, str(proof["status"]), summary)
    return summary

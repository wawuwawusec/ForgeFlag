"""LLM-driven script execution solver.

The model receives the challenge artifacts (bounded previews plus file names)
and writes a self-contained Python solve script. The script runs inside the
ForgeFlag Docker tool sandbox — network disabled, read-only challenge files,
memory/cpu/pids caps — using the image's analysis venv (pycryptodome, z3,
pwntools). Failed runs feed their traceback back to the model for one bounded
revision round. Only deterministic offline analysis is in scope; the script
never gets network access.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from forgeflag.ctf_scope import ctf_scope_evidence
from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags_generic
from forgeflag.solvers.base import SolverContext
from forgeflag.solvers.llm import LLMProvider, _attachment_previews
from forgeflag.tools.runner import _docker_host_mount

MAX_SCRIPT_CHARS = 16_000
MAX_OUTPUT_CHARS = 16_000
MAX_ATTEMPTS = 3
SANDBOX_IMAGE = "forgeflag-ctf:latest"
SANDBOX_PYTHON = "/opt/forgeflag-venv/bin/python"


class LLMExecuteSolver:
    name = "LLMExecuteSolver"
    supported_categories = set(ChallengeCategory)

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    def solve(self, context: SolverContext) -> SolverResult:
        challenge = context.challenge
        if not self.provider.enabled:
            return SolverResult(self.name, challenge.challenge_id, "disabled")
        attachments = [path for path in challenge.attachment_paths if Path(path).is_file()]
        if not attachments:
            return SolverResult(self.name, challenge.challenge_id, "no_artifacts")

        preview = _attachment_previews(tuple(attachments), max_files=6, max_chars_per_file=2600)
        observations = "\n".join(
            f"- {observation.kind}: {observation.summary}" for observation in context.observations[-12:]
        )
        history: list[dict[str, str]] = []
        last_output = ""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = self.provider.generate(_instructions(), _prompt(context, preview, observations, history))
            except Exception as exc:  # noqa: BLE001 - provider outages must not kill the run
                finding = Finding(
                    challenge_id=challenge.challenge_id,
                    solver=self.name,
                    finding="LLM execution solver unavailable",
                    evidence={"error": str(exc)[:500], "attempt": attempt, "ctf_scope": ctf_scope_evidence(challenge.category)},
                    hypothesis="The LLM provider errored (rate limit, balance, transport); deterministic solvers remain authoritative.",
                    confidence=0.1,
                    next_action="Retry when the provider recovers; check llm_status for details.",
                )
                context.notebook.add_finding(finding)
                return SolverResult(self.name, challenge.challenge_id, "provider_unavailable", (finding,))
            script = _extract_code(response.content)
            if not script:
                history.append({"role": "assistant", "content": response.content[:2000]})
                last_output = "no python code block found in model response"
                continue
            run = _run_in_sandbox(attachments, script)
            last_output = run["stdout"]
            flags = extract_flags_generic(run["stdout"])
            history.append(
                {
                    "attempt": str(attempt),
                    "script": script[:4000],
                    "returncode": str(run["returncode"]),
                    "stderr": run["stderr"][:2000],
                    "stdout": run["stdout"][:2000],
                }
            )
            if run["status"] == "unavailable":
                finding = _finding(context, script, run, attempt, (), "sandbox_unavailable")
                context.notebook.add_finding(finding)
                return SolverResult(self.name, challenge.challenge_id, "sandbox_unavailable", (finding,))
            if flags:
                finding = _finding(context, script, run, attempt, flags, "flag_candidate")
                context.notebook.add_finding(finding)
                return SolverResult(
                    self.name,
                    challenge.challenge_id,
                    "flag_candidate",
                    (finding,),
                    tuple(flags),
                )
            if run["returncode"] == 0:
                # script ran cleanly without recovering a flag; one more
                # attempt with the output as context is still useful
                continue

        finding = _finding(context, "", {"stdout": last_output, "stderr": "", "returncode": -1, "status": "failed"}, MAX_ATTEMPTS, (), "no_flag_recovered")
        context.notebook.add_finding(finding)
        return SolverResult(self.name, challenge.challenge_id, "no_flag_recovered", (finding,))


def _instructions() -> str:
    return (
        "You are ForgeFlag's execution solver for an authorized local CTF challenge. "
        "Write ONE self-contained Python 3 script that reads the challenge files from its "
        "working directory and prints the recovered flag to stdout. "
        "Available libraries: python stdlib, Crypto (pycryptodome), z3, gmpy2-free integer math, pwntools. "
        "There is NO network access; do not import sockets or make requests. "
        "Read files by relative name exactly as listed. Print every intermediate finding on its own line; "
        "end with the flag alone on a line if recovered. "
        "If the previous attempt failed, its traceback and output are provided — fix the script. "
        "Respond with a single ```python code block and nothing else."
    )


def _prompt(
    context: SolverContext,
    preview: str,
    observations: str,
    history: list[dict[str, str]],
) -> str:
    challenge = context.challenge
    parts = [
        f"challenge_id: {challenge.challenge_id}",
        f"category: {challenge.category.value}",
        f"title: {challenge.title or ''}",
        f"description: {challenge.description or ''}",
        "attachment files (read-only, in the working directory):",
        ", ".join(Path(path).name for path in challenge.attachment_paths),
        preview,
        "prior solver observations:",
        observations or "- none",
    ]
    for entry in history:
        parts.append(
            "previous attempt:\n"
            f"```python\n{entry.get('script', '')[:3000]}\n```\n"
            f"returncode={entry.get('returncode')} stderr:\n{entry.get('stderr', '')[:1500]}\n"
            f"stdout:\n{entry.get('stdout', '')[:1500]}"
        )
    return "\n".join(parts)


def _extract_code(content: str) -> str:
    match = re.search(r"```(?:python|py)?\s*\n(.*?)```", content, re.S)
    if not match:
        return ""
    script = match.group(1).strip()
    if not script or len(script) > MAX_SCRIPT_CHARS:
        return ""
    if re.search(r"\b(?:socket|urllib|requests|http\.client|telnetlib|ftplib)\b", script):
        return ""
    return script


def _run_in_sandbox(attachments: list[str], script: str) -> dict[str, Any]:
    import shutil

    if not shutil.which("docker"):
        return {"status": "unavailable", "returncode": -1, "stdout": "", "stderr": "docker not found"}
    with tempfile.TemporaryDirectory(prefix="forgeflag-llmexec-") as tmp:
        work = Path(tmp)
        for attachment in attachments:
            source = Path(attachment)
            destination = work / source.name
            if source.is_file():
                shutil.copy2(source, destination)
                destination.chmod(0o400)
        script_path = work / "solve.py"
        script_path.write_text(script, encoding="utf-8")
        script_path.chmod(0o400)
        argv = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--pids-limit",
            "64",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "-v",
            f"{_docker_host_mount(work.resolve())}:/challenge:ro",
            "-w",
            "/challenge",
            SANDBOX_IMAGE,
            "timeout",
            "-k",
            "10",
            "80",
            SANDBOX_PYTHON,
            "-I",
            "-B",
            "-u",
            "/challenge/solve.py",
        ]
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                timeout=90,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "returncode": -1, "stdout": "", "stderr": "sandbox timeout"}
        except OSError as exc:
            return {"status": "error", "returncode": -1, "stdout": "", "stderr": str(exc)}
        stdout = completed.stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT_CHARS]
        stderr = completed.stderr.decode("utf-8", errors="replace")[:8000]
        return {
            "status": "success" if completed.returncode == 0 else "error",
            "returncode": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }


def _finding(
    context: SolverContext,
    script: str,
    run: dict[str, Any],
    attempt: int,
    flags: tuple[str, ...],
    status: str,
) -> Finding:
    challenge = context.challenge
    hypothesis = (
        "Model-authored solve script executed in the offline sandbox recovered the flag."
        if flags
        else "Model-authored solve script did not recover the flag; retain the transcript for the next revision."
    )
    return Finding(
        challenge_id=challenge.challenge_id,
        solver="LLMExecuteSolver",
        finding="Executed model-authored solve script in sandbox",
        evidence={
            "attempts": attempt,
            "script": script[:MAX_SCRIPT_CHARS],
            "returncode": run.get("returncode"),
            "stdout": str(run.get("stdout", ""))[:8000],
            "stderr": str(run.get("stderr", ""))[:4000],
            "flag_candidates": list(flags),
            "sandbox": {"image": SANDBOX_IMAGE, "network": "none", "filesystem": "read-only"},
            "ctf_scope": ctf_scope_evidence(challenge.category),
        },
        hypothesis=hypothesis,
        confidence=0.85 if flags else 0.3,
        next_action=(
            "Verify the recovered flag against challenge evidence and record the script as replay proof."
            if flags
            else "Feed the failure transcript back for a revised script or escalate to manual analysis."
        ),
    )

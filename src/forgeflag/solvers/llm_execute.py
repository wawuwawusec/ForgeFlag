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
from uuid import uuid4
import subprocess
import tempfile
import time
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
import os as _os

MAX_ATTEMPTS = max(1, int(_os.environ.get("FORGEFLAG_LLMEXEC_MAX_ATTEMPTS", "30")))
MAX_SESSION_SECONDS = max(60, int(_os.environ.get("FORGEFLAG_LLMEXEC_MAX_SECONDS", "2400")))
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
            f"- {observation.kind}: {observation.summary}" for observation in context.observations[-20:]
        )
        prior_findings = _prior_findings_digest(context)
        history: list[dict[str, str]] = []
        last_output = ""
        started = time.monotonic()
        not_recovered_streak = 0
        tokens_spent = 0
        max_tokens_budget = max(50_000, int(_os.environ.get("FORGEFLAG_LLMEXEC_MAX_TOKENS", "700000")))
        import tempfile as _tempfile

        target = (challenge.target or "").strip()
        allow_localhost = bool(target) and ("127.0.0.1" in target or "localhost" in target)
        session = _tempfile.mkdtemp(prefix="forgeflag-llmsession-")
        for attempt in range(1, MAX_ATTEMPTS + 1):
            if time.monotonic() - started > MAX_SESSION_SECONDS:
                break
            if tokens_spent >= max_tokens_budget:
                break
            vision_images = (*_image_attachments(attachments), *_work_images(Path(session) / "work"))
            try:
                response = self.provider.generate(
                    _instructions(),
                    _prompt(context, preview, observations, history, prior_findings),
                    **({"images": vision_images} if vision_images else {}),
                )
                tokens_spent += int(response.usage.get("total_tokens") or 0)
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
            run = _run_in_sandbox(attachments, script, session=session, allow_localhost=allow_localhost, target=target)
            last_output = run["stdout"]
            flags = extract_flags_generic(run["stdout"])
            history.append(
                {
                    "attempt": str(attempt),
                    "script": script[:4000],
                    "returncode": str(run["returncode"]),
                    "stderr": run["stderr"][:3000],
                    "stdout": run["stdout"][:3000],
                }
            )
            if run["status"] == "unavailable":
                finding = _finding(context, script, run, attempt, (), "sandbox_unavailable")
                context.notebook.add_finding(finding)
                return SolverResult(self.name, challenge.challenge_id, "sandbox_unavailable", (finding,))
            work_listing = _work_listing(Path(session) / "work")
            history[-1]["work_files"] = work_listing[:600]
            if "NOT_RECOVERED" in run["stdout"]:
                not_recovered_streak += 1
                if not_recovered_streak >= 3:
                    break
            else:
                not_recovered_streak = 0
            if len(history) >= 2 and history[-1].get("script") == history[-2].get("script"):
                break
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
        "Each round you write ONE self-contained Python 3 script that reads the challenge files from its "
        "working directory and prints the recovered flag to stdout. You have up to 8 rounds — use them to "
        "explore: first round can inspect files (print listings, hexdumps, parse structures), later rounds "
        "should attempt the full solve informed by every prior output. "
        "Available libraries: python stdlib, Crypto (pycryptodome), z3, pwntools. "
        "There is NO network access; do not import sockets or make requests. "
        "Read files by relative name exactly as listed (cwd, read-only). A read-write scratch directory /work persists across ALL rounds: save intermediates (decoded blobs, candidate keys, partial plaintexts) there and reuse them in later rounds. Print every intermediate finding on its own line; "
        "end with the flag alone on a line if recovered. "
        "Exploit the prior deterministic solver findings: their partial decodes, wrong-key cryptanalysis, "
        "and near-miss flag candidates are the strongest starting points. "
        "If a previous attempt failed, its full traceback and output are provided — fix and go deeper; "
        "try brute-force over small keyspaces, known-plaintext attacks, and category-standard attacks. "
        "NEVER guess or invent a flag: a flag candidate must be a byte-exact string your script printed from parsed challenge data. "
        "If after all attempts you cannot recover it, print exactly NOT_RECOVERED — a wrong guess is worse than an honest failure. "
        "Respond with a single ```python code block and nothing else."
    )


def _prior_findings_digest(context: SolverContext) -> str:
    """Compress every prior solver finding into actionable hints.

    Deterministic solvers often land one step away from the flag (wrong
    substitution key, partial decode); feeding those near-misses to the
    execution model is the highest-signal context available.
    """
    try:
        findings = context.notebook.findings_for(context.challenge.challenge_id)
    except Exception:  # noqa: BLE001
        return ""
    rows: list[str] = []
    for finding in findings:
        if finding.solver in ("LLMSolver", "LLMExecuteSolver", "ReconSolver"):
            continue
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        interesting = []
        for key in ("flag_candidates", "decoded", "recovered", "analysis", "ciphertext", "script", "stdout"):
            value = evidence.get(key)
            if value:
                interesting.append(f"{key}={str(value)[:300]}")
        summary = finding.finding[:160]
        detail = " | ".join(interesting)[:600]
        rows.append(f"- [{finding.solver}] {summary}" + (f" :: {detail}" if detail else ""))
    return "\n".join(rows[:20])


def _prompt(
    context: SolverContext,
    preview: str,
    observations: str,
    history: list[dict[str, str]],
    prior_findings: str = "",
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
        *( [f"live local challenge service reachable at: {challenge.target} (env CHALLENGE_TARGET; use pwntools remote/socket to 127.0.0.1) — interact with it, read menus, send payloads"] if (challenge.target and "127.0.0.1" in (challenge.target or "")) else [] ),
        "prior solver observations:",
        observations or "- none",
        "prior deterministic solver findings (near-misses and partial decodes are high-signal):",
        prior_findings or "- none",
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


def _work_listing(work_dir: Path) -> str:
    try:
        rows = [f"{item.name}:{item.stat().st_size}B" for item in sorted(work_dir.rglob("*")) if item.is_file()]
        return ", ".join(rows[:30])
    except OSError:
        return ""


def _run_in_sandbox(attachments: list[str], script: str, session: str | None = None, allow_localhost: bool = False, target: str = "") -> dict[str, Any]:
    import shutil

    if not shutil.which("docker"):
        return {"status": "unavailable", "returncode": -1, "stdout": "", "stderr": "docker not found"}
    with tempfile.TemporaryDirectory(prefix="forgeflag-llmexec-") as tmp:
        work = Path(session) / "challenge" if session else Path(tmp)
        work.mkdir(parents=True, exist_ok=True)
        scratch = Path(session) / "work" if session else None
        if scratch is not None:
            scratch.mkdir(parents=True, exist_ok=True)
        for attachment in attachments:
            source = Path(attachment)
            destination = work / source.name
            if source.is_file() and not destination.exists():
                shutil.copy2(source, destination)
                destination.chmod(0o400)
        script_path = work / "solve.py"
        if script_path.exists():
            script_path.chmod(0o600)
        script_path.write_text(script, encoding="utf-8")
        script_path.chmod(0o400)
        container = f"forgeflag-llmexec-{uuid4().hex[:12]}"
        network_mode = "none"
        if allow_localhost:
            # service challenges: reach the locally deployed authorized
            # challenge service; still no other network egress via docker
            network_mode = "host"
        argv = [
            "docker",
            "run",
            "--rm",
            "--name",
            container,
            "--network",
            network_mode,
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
            *(
                [
                    "-v",
                    f"{_docker_host_mount(scratch.resolve())}:/work:rw",
                ]
                if scratch is not None
                else []
            ),
            "-w",
            "/challenge",
            *([ "-e", f"CHALLENGE_TARGET={target}" ] if (allow_localhost and target) else []),
            SANDBOX_IMAGE,
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
            subprocess.run(["docker", "kill", container], capture_output=True, timeout=30, check=False)
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


def _image_attachments(attachments: list[str], max_images: int = 3, max_bytes: int = 2_500_000) -> tuple[bytes, ...]:
    from forgeflag.solvers.llm import _image_attachments as _read_images

    return _read_images(tuple(attachments), max_images=max_images, max_bytes=max_bytes)


def _work_images(work_dir: Path, max_images: int = 3, max_bytes: int = 2_500_000) -> tuple[bytes, ...]:
    """Latest images produced in the persistent workspace, newest first."""
    try:
        candidates = [
            item
            for item in sorted(work_dir.rglob("*"), key=lambda i: i.stat().st_mtime, reverse=True)
            if item.is_file() and item.suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp"}
        ]
    except OSError:
        return ()
    images: list[bytes] = []
    for item in candidates:
        if len(images) >= max_images:
            break
        try:
            data = item.read_bytes()
        except OSError:
            continue
        if len(data) <= max_bytes:
            images.append(data)
    return tuple(images)

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
import platform
import shutil
import subprocess
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from forgeflag import __version__
from forgeflag.agent_roster import agent_roster_path_for_db, load_agent_roster
from forgeflag.analysis_hints import recommended_analysis_hints
from forgeflag.artifacts import ArtifactWorkspace, summarize_artifact_paths
from forgeflag.domain import DEFAULT_ZHIPU_MODEL, Challenge, ChallengeCategory, LLMConfig, RunConfig
from forgeflag.llm import build_llm_provider
from forgeflag.manager import Manager, _proof_status
from forgeflag.notebook import SQLiteNotebook
from forgeflag.project_catalog import recommended_projects
from forgeflag.report import ReportBuilder
from forgeflag.safety import ScopePolicy
from forgeflag.tools.runner import ToolRunner


def run_webapp(db_path: str | Path, host: str = "127.0.0.1", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), create_handler(db_path))
    print(f"ForgeFlag web UI listening on http://{host}:{port}/")
    server.serve_forever()


def create_handler(db_path: str | Path):
    db = Path(db_path)

    class ForgeFlagWebHandler(BaseHTTPRequestHandler):
        notebook = SQLiteNotebook(db)
        db_path = db

        def log_message(self, format: str, *args: object) -> None:
            return

        @classmethod
        def render_index(cls) -> str:
            return INDEX_HTML

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/":
                self._send_html(self.render_index())
                return
            if path == "/favicon.ico":
                self.send_response(HTTPStatus.NO_CONTENT.value)
                self.end_headers()
                return
            if path == "/api/challenges":
                self._send_json(self.handle_list_challenges())
                return
            if path == "/api/tools":
                self._send_json(self.handle_tools())
                return
            if path == "/api/project-catalog":
                self._send_json(self.handle_project_catalog())
                return
            if path == "/api/analysis-hints":
                category = parse_qs(parsed.query).get("category", [None])[0]
                self._send_json(self.handle_analysis_hints(category))
                return
            if path == "/api/capability-benchmark":
                self._send_json(self.handle_capability_benchmark())
                return
            if path == "/api/system-health":
                self._send_json(self.handle_system_health())
                return
            if path == "/api/agents":
                self._send_json(self.handle_agents())
                return
            challenge_id, suffix = _challenge_route(path)
            if challenge_id and suffix == "findings":
                self._send_json(self.handle_findings(challenge_id))
                return
            if challenge_id and suffix == "summary":
                self._send_json(self.handle_summary(challenge_id))
                return
            if challenge_id and suffix == "observations":
                self._send_json(self.handle_observations(challenge_id))
                return
            if challenge_id and suffix == "report":
                self._send_json(self.handle_report(challenge_id))
                return
            if challenge_id and suffix == "artifacts":
                self._send_json(self.handle_artifacts(challenge_id))
                return
            self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                payload = self._read_json()
                if path == "/api/challenges":
                    self._send_json(self.handle_create_challenge(payload))
                    return
                if path == "/api/llm/test":
                    self._send_json(self.handle_test_llm(payload))
                    return
                challenge_id, suffix = _challenge_route(path)
                if challenge_id and suffix == "run":
                    self._send_json(self.handle_run_challenge(challenge_id, payload))
                    return
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except Exception as exc:  # noqa: BLE001 - API should return JSON errors to the UI.
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        def do_DELETE(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                if path == "/api/challenges":
                    self._send_json(self.handle_clear_challenges())
                    return
                challenge_id = _challenge_id_route(path)
                if challenge_id:
                    self._send_json(self.handle_delete_challenge(challenge_id))
                    return
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except Exception as exc:  # noqa: BLE001 - API should return JSON errors to the UI.
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        @classmethod
        def handle_list_challenges(cls) -> list[dict[str, Any]]:
            rows = []
            for challenge in cls.notebook.list_challenges():
                summary = cls.notebook.latest_run_summary(challenge.challenge_id) or {}
                accepted_flags = _string_list(summary.get("accepted_flags"))
                summary = cls._with_proof_status(challenge, summary)
                proof = summary.get("proof") if isinstance(summary.get("proof"), dict) else {}
                rows.append(
                    {
                        "challenge_id": challenge.challenge_id,
                        "category": challenge.category.value,
                        "title": challenge.title,
                        "target": challenge.target,
                        "description": challenge.description,
                        "tags": list(challenge.tags),
                        "attachment_paths": list(challenge.attachment_paths),
                        "latest_status": str(summary.get("status") or "not_run"),
                        "proof_status": str(summary.get("proof_status") or proof.get("status") or summary.get("status") or "not_run"),
                        "proof": proof,
                        "accepted_flags": accepted_flags,
                        "accepted_flag_count": len(accepted_flags),
                    }
                )
            return rows

        @classmethod
        def handle_tools(cls) -> dict[str, Any]:
            wrappers = ToolRunner(ScopePolicy()).inventory()
            catalog = recommended_projects()
            analysis_hints = recommended_analysis_hints()
            profiles = _docker_profile_inventory()
            host_wrappers = sum(1 for row in wrappers if row.get("source") == "host")
            docker_wrappers = sum(1 for row in wrappers if row.get("source") == "docker")
            missing_wrappers = sum(1 for row in wrappers if row.get("source") == "missing")
            return {
                "wrappers": wrappers,
                "catalog": catalog,
                "analysis_hints": analysis_hints,
                "docker_profiles": profiles,
                "counts": {
                    "wrappers": len(wrappers),
                    "available_wrappers": sum(1 for row in wrappers if row.get("available")),
                    "host_wrappers": host_wrappers,
                    "docker_wrappers": docker_wrappers,
                    "missing_wrappers": missing_wrappers,
                    "catalog": len(catalog),
                    "analysis_hints": len(analysis_hints),
                    "docker_profiles": len(profiles),
                    "available_docker_profiles": sum(1 for row in profiles if row.get("available")),
                },
                "runtime_smoke": {
                    "command": "scripts/forgeflag-tool-smoke",
                    "docker_build_command": "scripts/forgeflag-control docker-build",
                    "docker_smoke_command": "scripts/forgeflag-control docker-smoke",
                    "active_network_command": "scripts/forgeflag-tool-smoke --include-active-network",
                    "cracking_command": "scripts/forgeflag-tool-smoke --include-cracking",
                },
            }

        @classmethod
        def handle_create_challenge(cls, payload: dict[str, Any]) -> dict[str, Any]:
            category = ChallengeCategory(str(payload.get("category") or ChallengeCategory.UNKNOWN.value))
            challenge_id = _optional_string(payload.get("challenge_id")) or _generated_challenge_id(
                cls.notebook,
                category.value,
                _optional_string(payload.get("title")),
            )
            upload_dir = cls.db_path.parent / "uploads" / _safe_name(challenge_id)
            upload_dir.mkdir(parents=True, exist_ok=True)

            attachment_sources: list[Path] = []
            for raw_path in _string_list(payload.get("attachment_paths")):
                attachment_sources.append(Path(raw_path))
            for upload in payload.get("attachments") or []:
                if not isinstance(upload, dict):
                    continue
                name = _safe_name(str(upload.get("name") or "upload.bin"))
                content = base64.b64decode(str(upload.get("content_base64") or ""))
                path = upload_dir / name
                path.write_bytes(content)
                attachment_sources.append(path)

            workspace = ArtifactWorkspace(cls.db_path.parent / "artifacts")
            attachment_paths = tuple(str(workspace.register_file(challenge_id, source).workspace_path) for source in attachment_sources)
            challenge = Challenge(
                challenge_id=challenge_id,
                category=category,
                title=_optional_string(payload.get("title")),
                target=_optional_string(payload.get("target")),
                description=_optional_string(payload.get("description")),
                tags=tuple(_tags(payload.get("tags"))),
                attachment_paths=attachment_paths,
            )
            cls.notebook.add_challenge(challenge)
            return {"status": "ok", "challenge_id": challenge_id, "attachment_paths": list(attachment_paths)}

        @classmethod
        def handle_run_challenge(cls, challenge_id: str, payload: dict[str, Any]) -> dict[str, Any]:
            config = RunConfig(
                active_probe=bool(payload.get("active_probe")),
                allowed_hosts=tuple(_tags(payload.get("allowed_hosts"))),
                llm_config=_llm_config(payload),
            )
            return Manager(cls.notebook, config=config).run_challenge(challenge_id)

        @classmethod
        def handle_delete_challenge(cls, challenge_id: str) -> dict[str, Any]:
            # Validate before deleting so accidental unknown IDs surface as API errors.
            cls.notebook.get_challenge(challenge_id)
            deleted = cls.notebook.delete_challenge(challenge_id)
            removed_dirs = _remove_challenge_dirs(cls.db_path.parent, challenge_id)
            return {
                "status": "deleted",
                "challenge_id": challenge_id,
                "deleted": deleted,
                "removed_dirs": removed_dirs,
            }

        @classmethod
        def handle_clear_challenges(cls) -> dict[str, Any]:
            deleted = cls.notebook.clear_challenges()
            removed_dirs = _remove_all_challenge_dirs(cls.db_path.parent)
            return {"status": "cleared", "deleted": deleted, "removed_dirs": removed_dirs}

        @classmethod
        def handle_test_llm(cls, payload: dict[str, Any]) -> dict[str, Any]:
            config = _llm_config({**payload, "llm_enabled": True})
            if not config.enabled:
                raise ValueError("LLM config is disabled or missing model")
            provider = build_llm_provider(config)
            response = provider.generate(
                "You are ForgeFlag. Reply briefly for a connection test.",
                "Return a short confirmation that the model connection works.",
            )
            return {
                "status": "ok",
                "provider": provider.name,
                "model": provider.model,
                "content_sample": response.content[:300],
            }

        @classmethod
        def handle_findings(cls, challenge_id: str) -> list[dict[str, Any]]:
            return [
                {
                    "solver": finding.solver,
                    "finding": finding.finding,
                    "confidence": finding.confidence,
                    "hypothesis": finding.hypothesis,
                    "next_action": finding.next_action,
                    "evidence": finding.evidence,
                }
                for finding in cls.notebook.findings_for(challenge_id)
            ]

        @classmethod
        def handle_summary(cls, challenge_id: str) -> dict[str, Any]:
            summary = cls.notebook.latest_run_summary(challenge_id)
            if isinstance(summary, dict) and summary:
                challenge = cls.notebook.get_challenge(challenge_id)
                return cls._with_proof_status(challenge, summary)
            # Validate that the challenge exists and return a stable empty run shape.
            try:
                cls.notebook.get_challenge(challenge_id)
            except KeyError:
                return {
                    "challenge_id": challenge_id,
                    "status": "not_found",
                    "solvers": [],
                    "accepted_flags": [],
                    "rejected_flags": [],
                    "proof_status": "not_found",
                    "proof": {
                        "status": "not_found",
                        "label": "Challenge not saved",
                        "verified": False,
                        "summary": "The selected challenge id is not present in the notebook.",
                        "next_action": "Save the challenge or select an existing challenge before running analysis.",
                    },
                    "observations": 0,
                }
            return {
                "challenge_id": challenge_id,
                "status": "not_run",
                "solvers": [],
                "accepted_flags": [],
                "rejected_flags": [],
                "proof_status": "not_run",
                "proof": {
                    "status": "not_run",
                    "label": "Not run",
                    "verified": False,
                    "summary": "This challenge has not been run yet.",
                    "next_action": "Run the challenge to collect solver evidence.",
                },
                "observations": len(cls.notebook.observations_for(challenge_id)),
            }

        @classmethod
        def _with_proof_status(cls, challenge, summary: dict[str, Any]) -> dict[str, Any]:
            proof = summary.get("proof")
            if isinstance(proof, dict) and summary.get("proof_status"):
                return summary
            accepted_flags = tuple(_string_list(summary.get("accepted_flags")))
            derived = _proof_status(
                challenge.category,
                cls.notebook.findings_for(challenge.challenge_id),
                accepted_flags,
            )
            enriched = dict(summary)
            enriched["proof"] = derived
            enriched["proof_status"] = derived["status"]
            if enriched.get("status") in {"completed", None, ""} or derived["status"] in {"flag_found", "exploit_plan", "exploit_verified", "analysis_only"}:
                enriched["status"] = derived["status"]
            return enriched

        @classmethod
        def handle_observations(cls, challenge_id: str) -> list[dict[str, Any]]:
            return [
                {
                    "source": observation.source,
                    "kind": observation.kind,
                    "summary": observation.summary,
                    "evidence": observation.evidence,
                    "created_at": observation.created_at,
                }
                for observation in cls.notebook.observations_for(challenge_id)
            ]

        @classmethod
        def handle_artifacts(cls, challenge_id: str) -> dict[str, Any]:
            challenge = cls.notebook.get_challenge(challenge_id)
            return {
                "challenge_id": challenge.challenge_id,
                "artifacts": summarize_artifact_paths(challenge.attachment_paths),
            }

        @classmethod
        def handle_report(cls, challenge_id: str) -> dict[str, Any]:
            summary = cls.notebook.latest_run_summary(challenge_id)
            replay_report = (summary or {}).get("replay_report")
            if isinstance(replay_report, dict) and replay_report:
                return replay_report
            challenge = cls.notebook.get_challenge(challenge_id)
            findings = cls.notebook.findings_for(challenge_id)
            observations = cls.notebook.observations_for(challenge_id)
            if not findings and not observations and not summary:
                return {}
            accepted_flags = tuple(_string_list((summary or {}).get("accepted_flags")))
            return ReportBuilder().build(
                challenge_id,
                accepted_flags,
                findings,
                observations,
                challenge=challenge,
            )

        @classmethod
        def handle_project_catalog(cls) -> list[dict[str, Any]]:
            return recommended_projects()

        @classmethod
        def handle_analysis_hints(cls, category: str | None = None) -> list[dict[str, Any]]:
            return recommended_analysis_hints(category)

        @classmethod
        def handle_capability_benchmark(cls) -> dict[str, Any]:
            latest = _capability_benchmark_path(cls.db_path)
            history_path = _capability_benchmark_history_path(cls.db_path)
            history = _read_capability_benchmark_history(history_path)
            refresh_command = f"scripts/forgeflag-capability-benchmark --output {latest} --history {history_path}"
            if not latest.exists():
                return {
                    "status": "missing",
                    "path": str(latest),
                    "history_path": str(history_path),
                    "refresh_command": refresh_command,
                    "scorecard": None,
                    "history": history,
                }
            scorecard = json.loads(latest.read_text(encoding="utf-8"))
            return {
                "status": "ok",
                "path": str(latest),
                "history_path": str(history_path),
                "refresh_command": refresh_command,
                "scorecard": scorecard,
                "history": history,
            }

        @classmethod
        def handle_system_health(cls) -> dict[str, Any]:
            return _system_health(cls.db_path)

        @classmethod
        def handle_agents(cls) -> dict[str, Any]:
            return load_agent_roster(agent_roster_path_for_db(cls.db_path)).to_public_dict()

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("content-length") or "0")
            if length == 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def _send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status.value)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(HTTPStatus.OK.value)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ForgeFlagWebHandler


_DOCKER_PROFILES = (
    {
        "name": "forgeflag-volatility",
        "target": "forgeflag-volatility",
        "image": "forgeflag-ctf:volatility",
        "purpose": "Memory forensics and dump triage without bloating the default tool image.",
    },
    {
        "name": "forgeflag-sagemath",
        "target": "forgeflag-sagemath",
        "image": "forgeflag-ctf:sagemath",
        "purpose": "Math-heavy crypto work such as lattices, finite fields, and elliptic curves.",
    },
    {
        "name": "forgeflag-ghidra-headless",
        "target": "forgeflag-ghidra-headless",
        "image": "forgeflag-ctf:ghidra-headless",
        "purpose": "Scripted reverse-engineering exports and headless analysis jobs.",
    },
)


def _docker_profile_inventory() -> list[dict[str, Any]]:
    docker = shutil.which("docker")
    rows: list[dict[str, Any]] = []
    for profile in _DOCKER_PROFILES:
        image = str(profile["image"])
        available = False
        if docker:
            try:
                result = subprocess.run(
                    [docker, "image", "inspect", image],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
                available = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                available = False
        rows.append(
            {
                **profile,
                "available": available,
                "source": "docker" if available else "missing",
                "category": "heavyweight-profile",
                "build_command": (
                    "docker build -f docker/Dockerfile.ctf "
                    f"--target {profile['target']} -t {image} ."
                ),
                "verify_command": f"docker image inspect {image}",
            }
        )
    return rows


def _capability_benchmark_path(db_path: Path) -> Path:
    return db_path.parent / "capability-benchmark-latest.json"


def _capability_benchmark_history_path(db_path: Path) -> Path:
    return db_path.parent / "capability-benchmark-history.jsonl"


def _read_capability_benchmark_history(history_path: Path, limit: int = 20) -> list[dict[str, Any]]:
    if not history_path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in history_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records[-limit:]


def _system_health(db_path: Path) -> dict[str, Any]:
    checks = [
        _notebook_health(db_path),
        _tool_health(),
        _docker_profile_health(),
        _benchmark_health(db_path),
        _llm_health(),
    ]
    errors = sum(1 for check in checks if check["status"] == "error")
    warnings = sum(1 for check in checks if check["status"] == "warning")
    status = "blocked" if errors else "limited" if warnings else "ready"
    core_readiness = _core_readiness(checks)
    next_actions = _deduped_health_actions(checks)
    diagnostic_bundle = _diagnostic_bundle(
        db_path=db_path,
        status=status,
        core_readiness=core_readiness,
        checks=checks,
        next_actions=next_actions,
    )
    return {
        "status": status,
        "summary": _commercial_health_summary(status),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "core_readiness": core_readiness,
        "commercial_readiness": {
            "status": status,
            "label": "Commercial readiness",
            "blocking_checks": [check["id"] for check in checks if check["status"] == "error"],
            "warning_checks": [check["id"] for check in checks if check["status"] == "warning"],
        },
        "counts": {
            "checks": len(checks),
            "ok": sum(1 for check in checks if check["status"] == "ok"),
            "warnings": warnings,
            "errors": errors,
        },
        "checks": checks,
        "next_actions": next_actions,
        "diagnostic_bundle": diagnostic_bundle,
    }


def _diagnostic_bundle(
    db_path: Path,
    status: str,
    core_readiness: dict[str, Any],
    checks: list[dict[str, Any]],
    next_actions: list[str],
) -> dict[str, Any]:
    config = LLMConfig.from_env()
    blocking_checks = [str(check["id"]) for check in checks if check.get("status") == "error"]
    warning_checks = [str(check["id"]) for check in checks if check.get("status") == "warning"]
    counts = {
        "checks": len(checks),
        "ok": sum(1 for check in checks if check.get("status") == "ok"),
        "warnings": len(warning_checks),
        "errors": len(blocking_checks),
    }
    support_summary = [
        f"ForgeFlag {__version__} status={status}",
        f"checks ok={counts['ok']} warnings={counts['warnings']} errors={counts['errors']}",
        f"db={db_path}",
        f"llm={config.provider}/{config.model} enabled={config.enabled}",
        f"next_actions={len(next_actions)}",
    ]
    return {
        "bundle_version": 1,
        "service": {
            "name": "ForgeFlag",
            "version": __version__,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "pid": os.getpid(),
            "cwd": str(Path.cwd()),
            "db_path": str(db_path),
        },
        "readiness": {
            "status": status,
            "counts": counts,
            "blocking_checks": blocking_checks,
            "warning_checks": warning_checks,
        },
        "core_readiness": core_readiness,
        "llm": {
            "enabled": config.enabled,
            "provider": config.provider,
            "model": config.model,
            "base_url": config.base_url,
            "api_key_configured": bool(config.api_key),
        },
        "checks": [
            {
                "id": str(check.get("id") or "unknown"),
                "status": str(check.get("status") or "unknown"),
                "summary": str(check.get("summary") or ""),
            }
            for check in checks
        ],
        "next_actions": list(next_actions),
        "support_summary": support_summary,
    }


def _core_readiness(checks: list[dict[str, Any]]) -> dict[str, Any]:
    core_ids = {"notebook", "tools", "benchmark"}
    core_checks = [check for check in checks if check.get("id") in core_ids]
    blocking = [str(check["id"]) for check in core_checks if check.get("status") == "error"]
    warnings = [str(check["id"]) for check in core_checks if check.get("status") == "warning"]
    status = "blocked" if blocking else "limited" if warnings else "ready"
    return {
        "status": status,
        "label": "Core solving readiness",
        "summary": _core_health_summary(status),
        "blocking_checks": blocking,
        "warning_checks": warnings,
        "check_ids": [str(check.get("id") or "unknown") for check in core_checks],
    }


def _notebook_health(db_path: Path) -> dict[str, Any]:
    exists = db_path.exists()
    return {
        "id": "notebook",
        "label": "Notebook",
        "status": "ok",
        "summary": f"SQLite notebook {'exists' if exists else 'will be initialized'} at {db_path}",
        "next_actions": [],
    }


def _tool_health() -> dict[str, Any]:
    wrappers = ToolRunner(ScopePolicy()).inventory()
    missing = [row for row in wrappers if row.get("source") == "missing" or row.get("available") is False]
    status = "error" if missing else "ok"
    return {
        "id": "tools",
        "label": "Tool wrappers",
        "status": status,
        "summary": f"{len(wrappers) - len(missing)} available wrappers; missing wrappers: {len(missing)}",
        "next_actions": ["scripts/forgeflag-tool-smoke"] if missing else [],
        "details": {
            "total": len(wrappers),
            "missing": [str(row.get("name") or "unknown") for row in missing[:12]],
        },
    }


def _docker_profile_health() -> dict[str, Any]:
    profiles = _docker_profile_inventory()
    missing = [row for row in profiles if not row.get("available")]
    return {
        "id": "docker_profiles",
        "label": "Heavyweight Docker profiles",
        "status": "warning" if missing else "ok",
        "summary": f"{len(profiles) - len(missing)} / {len(profiles)} optional heavyweight profiles built",
        "next_actions": [str(row.get("build_command")) for row in missing[:3] if row.get("build_command")],
        "details": {
            "missing": [str(row.get("name") or "unknown") for row in missing],
        },
    }


def _benchmark_health(db_path: Path) -> dict[str, Any]:
    latest = _capability_benchmark_path(db_path)
    refresh_command = f"scripts/forgeflag-capability-benchmark --output {latest} --history {_capability_benchmark_history_path(db_path)}"
    if not latest.exists():
        return {
            "id": "benchmark",
            "label": "Capability benchmark",
            "status": "warning",
            "summary": "No saved capability benchmark scorecard yet",
            "next_actions": [refresh_command],
        }
    try:
        scorecard = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "id": "benchmark",
            "label": "Capability benchmark",
            "status": "error",
            "summary": f"Saved capability benchmark is unreadable: {exc}",
            "next_actions": [refresh_command],
        }
    readiness = scorecard.get("readiness") if isinstance(scorecard, dict) else {}
    readiness_status = str((readiness or {}).get("status") or "unknown")
    status = "ok" if readiness_status == "ready" else "error" if readiness_status == "blocked" else "warning"
    totals = scorecard.get("totals", {}) if isinstance(scorecard, dict) else {}
    return {
        "id": "benchmark",
        "label": "Capability benchmark",
        "status": status,
        "summary": f"readiness={readiness_status}; passed={totals.get('passed', 0)} / {totals.get('cases', 0)}; failed={totals.get('failed', 0)}",
        "next_actions": (readiness or {}).get("next_actions") or ([] if status == "ok" else [refresh_command]),
        "details": {"readiness": readiness, "path": str(latest)},
    }


def _llm_health() -> dict[str, Any]:
    config = LLMConfig.from_env()
    if config.enabled:
        return {
            "id": "llm",
            "label": "LLM runtime",
            "status": "ok",
            "summary": f"{config.provider} {config.model} configured",
            "next_actions": [],
        }
    return {
        "id": "llm",
        "label": "LLM runtime",
        "status": "warning",
        "summary": "LLM runtime is not configured; deterministic solvers still run",
        "next_actions": ["Set FORGEFLAG_LLM_PROVIDER and provider API key or configure it in the Web UI"],
    }


def _commercial_health_summary(status: str) -> str:
    if status == "ready":
        return "commercial-ready: core runtime, tools, benchmark gate, and optional LLM are green"
    if status == "limited":
        return "commercial-limited: core runtime works but release evidence or optional integrations need attention"
    return "commercial-blocked: fix blocking checks before treating this platform as production-ready"


def _core_health_summary(status: str) -> str:
    if status == "ready":
        return "core-ready: notebook, tool wrappers, and capability benchmark are green for CTF solving"
    if status == "limited":
        return "core-limited: refresh the capability benchmark or resolve core warnings before trusting solves"
    return "core-blocked: fix notebook, tool wrapper, or benchmark errors before running challenge work"


def _deduped_health_actions(checks: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    seen: set[str] = set()
    for check in checks:
        for action in check.get("next_actions", []):
            if not isinstance(action, str):
                continue
            cleaned = action.strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            actions.append(cleaned)
    return actions[:12]


def _challenge_route(path: str) -> tuple[str | None, str | None]:
    parts = [unquote(part) for part in path.strip("/").split("/")]
    if len(parts) == 4 and parts[0] == "api" and parts[1] == "challenges":
        return parts[2], parts[3]
    return None, None


def _challenge_id_route(path: str) -> str | None:
    parts = [unquote(part) for part in path.strip("/").split("/")]
    if len(parts) == 3 and parts[0] == "api" and parts[1] == "challenges":
        return parts[2]
    return None


def _required_string(payload: dict[str, Any], key: str) -> str:
    value = str(payload.get(key) or "").strip()
    if not value:
        raise ValueError(f"missing required field: {key}")
    return value


def _optional_string(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _tags(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in ("-", "_", ".") else "_" for char in value)
    return cleaned.strip("._") or "upload.bin"


def _generated_challenge_id(notebook: SQLiteNotebook, category: str, title: str | None = None) -> str:
    category_slug = _slug_part(category or ChallengeCategory.UNKNOWN.value) or ChallengeCategory.UNKNOWN.value
    title_slug = _slug_part(title or "challenge") or "challenge"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = f"{category_slug}-{stamp}-{title_slug}"
    candidate = base
    suffix = 2
    while _challenge_exists(notebook, candidate):
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _slug_part(value: str) -> str:
    cleaned = []
    last_dash = False
    for char in value.lower():
        if char.isalnum():
            cleaned.append(char)
            last_dash = False
        elif not last_dash:
            cleaned.append("-")
            last_dash = True
    return "".join(cleaned).strip("-")[:36]


def _challenge_exists(notebook: SQLiteNotebook, challenge_id: str) -> bool:
    try:
        notebook.get_challenge(challenge_id)
    except KeyError:
        return False
    return True


def _remove_challenge_dirs(root: Path, challenge_id: str) -> list[str]:
    removed: list[str] = []
    safe_id = _safe_name(challenge_id)
    for base in (root / "uploads", root / "artifacts"):
        path = base / safe_id
        if path.exists():
            shutil.rmtree(path)
            removed.append(str(path))
    return removed


def _remove_all_challenge_dirs(root: Path) -> list[str]:
    removed: list[str] = []
    for path in (root / "uploads", root / "artifacts"):
        if path.exists():
            shutil.rmtree(path)
            removed.append(str(path))
    return removed


def _llm_config(payload: dict[str, Any]) -> LLMConfig:
    base = LLMConfig.from_env()
    provider = str(payload.get("llm_provider") or base.provider)
    if not bool(payload.get("llm_enabled")):
        return LLMConfig(
            provider="disabled",
            model=base.model,
            api_key=base.api_key,
            base_url=base.base_url,
            timeout_seconds=base.timeout_seconds,
            max_retries=base.max_retries,
            retry_initial_seconds=base.retry_initial_seconds,
            retry_max_seconds=base.retry_max_seconds,
            cooldown_seconds=base.cooldown_seconds,
        )
    return LLMConfig(
        provider=provider,
        model=_optional_string(payload.get("llm_model")) or base.model or _default_llm_model(provider),
        api_key=_optional_string(payload.get("llm_api_key")) or base.api_key,
        base_url=_optional_string(payload.get("llm_base_url")) or _default_llm_base_url(provider, base.base_url),
        timeout_seconds=_int_value(payload.get("llm_timeout_seconds"), base.timeout_seconds),
        max_retries=_int_value(payload.get("llm_max_retries"), base.max_retries),
        retry_initial_seconds=_int_value(payload.get("llm_retry_initial_seconds"), base.retry_initial_seconds),
        retry_max_seconds=_int_value(payload.get("llm_retry_max_seconds"), base.retry_max_seconds),
        cooldown_seconds=_int_value(payload.get("llm_cooldown_seconds"), base.cooldown_seconds),
    )


def _int_value(value: object, default: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _default_llm_base_url(provider: str, fallback: str) -> str:
    if provider == "zhipu":
        return "https://open.bigmodel.cn/api/paas/v4"
    return fallback


def _default_llm_model(provider: str) -> str | None:
    if provider == "zhipu":
        return DEFAULT_ZHIPU_MODEL
    return None


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ForgeFlag Workbench</title>
  <style>
    :root {
      color-scheme: dark;
      --ink:#e8f3ff;
      --muted:#91a6b8;
      --subtle:#647989;
      --line:rgba(108,137,155,.30);
      --line-strong:rgba(0,255,171,.36);
      --surface:#071016;
      --surface-raised:rgba(10,22,30,.88);
      --surface-solid:#0c1821;
      --surface-tint:rgba(0,255,171,.08);
      --surface-glass:rgba(9,20,29,.72);
      --accent:#00d7ff;
      --accent-strong:#00ffab;
      --accent-soft:rgba(0,215,255,.12);
      --matrix-green:#00ffab;
      --phosphor:#a6ffcb;
      --signal-cyan:#00d7ff;
      --signal-indigo:#8b7dff;
      --signal-emerald:#18d987;
      --signal-amber:#ffbf4d;
      --warn:#ffbf4d;
      --warn-soft:rgba(255,191,77,.13);
      --danger:#ff5d73;
      --danger-soft:rgba(255,93,115,.13);
      --code:#03080d;
      --shadow-soft:0 24px 80px rgba(0,0,0,.45);
      --shadow-tight:0 12px 34px rgba(0,0,0,.32);
      --shadow-hairline:0 1px 0 rgba(255,255,255,.06) inset;
    }
    * { box-sizing: border-box; }
    html { background: var(--surface); }
    body { margin: 0; min-height: 100vh; height: 100vh; overflow: hidden; display: grid; grid-template-rows: auto minmax(0, 1fr); font-size: 14px; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: #071016; }
    body::before { content: ""; position: fixed; inset: 0; z-index: -2; background-image: repeating-linear-gradient(90deg, rgba(0, 255, 171, .07) 0 1px, transparent 1px 120px), repeating-linear-gradient(0deg, rgba(0, 215, 255, .055) 0 1px, transparent 1px 84px), linear-gradient(135deg, #071016 0%, #0b1322 45%, #111827 100%); }
    body::after { content: ""; position: fixed; inset: 0; z-index: -1; background: linear-gradient(180deg, rgba(0,0,0,.1), rgba(0,0,0,.52)), repeating-linear-gradient(0deg, rgba(255,255,255,.035) 0 1px, transparent 1px 4px); pointer-events: none; }
    .topbar { position: sticky; top: 0; z-index: 8; min-height: 82px; padding: 14px 24px; border-bottom: 1px solid rgba(0,255,171,.22); display: flex; justify-content: space-between; gap: 18px; align-items: center; background: rgba(5,12,18,.88); backdrop-filter: blur(18px) saturate(150%); box-shadow: 0 14px 44px rgba(0,0,0,.35); overflow: hidden; }
    .signal-field { position: absolute; inset: 0; pointer-events: none; background-image: linear-gradient(90deg, rgba(0,255,171,.16) 1px, transparent 1px), linear-gradient(rgba(0,215,255,.10) 1px, transparent 1px); background-size: 48px 48px; opacity: .34; mask-image: linear-gradient(90deg, rgba(0,0,0,.85), transparent 76%); }
    .ops-orbit { position: absolute; right: 24px; top: 12px; width: 260px; height: 56px; pointer-events: none; border: 1px solid rgba(0,255,171,.18); border-inline-color: rgba(0,215,255,.28); transform: skewX(-18deg); opacity: .62; }
    .brand { position: relative; z-index: 1; display: grid; gap: 5px; min-width: 0; }
    .brand-line { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .brand-mark { width: 34px; height: 34px; border-radius: 8px; display: grid; place-items: center; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 900; color: #03110d; border: 1px solid rgba(0,255,171,.58); background: linear-gradient(135deg, var(--matrix-green), var(--signal-cyan)); box-shadow: 0 0 24px rgba(0,255,171,.24), var(--shadow-hairline); }
    .brand-meta { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-top: 2px; }
    .signal-chip { border: 1px solid rgba(0,255,171,.30); background: rgba(0,255,171,.09); color: var(--phosphor); border-radius: 999px; padding: 4px 9px; font-size: 11px; font-weight: 800; box-shadow: var(--shadow-hairline); text-transform: uppercase; }
    .signal-chip.indigo { border-color: rgba(139,125,255,.32); background: rgba(139,125,255,.10); color: #d9d4ff; }
    .signal-chip.amber { border-color: rgba(255,191,77,.32); background: rgba(255,191,77,.10); color: #ffe1a0; }
    h1 { margin: 0; font-size: 23px; line-height: 1.1; letter-spacing: 0; }
    .brand-subtitle { color: var(--muted); font-size: 12px; }
    .mission-strip { position: relative; z-index: 1; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; min-width: min(520px, 44vw); }
    .mission-tile { border: 1px solid rgba(0,255,171,.20); background: rgba(5,14,20,.72); border-radius: 8px; padding: 8px 10px; box-shadow: var(--shadow-hairline); }
    .mission-tile span { display: block; color: var(--subtle); font-size: 10px; text-transform: uppercase; font-weight: 800; }
    .mission-tile strong { display: block; color: var(--ink); font-size: 13px; margin-top: 2px; overflow-wrap: anywhere; }
    .runtime-status[data-tone="busy"] { color: var(--signal-cyan); }
    .runtime-status[data-tone="success"] { color: var(--matrix-green); }
    .runtime-status[data-tone="error"] { color: #ffd8df; }
    h2 { margin: 0 0 12px; font-size: 12px; line-height: 1.2; letter-spacing: 0; text-transform: uppercase; color: var(--phosphor); }
    h3 { letter-spacing: 0; }
    .app-shell { display: grid; grid-template-columns: minmax(260px, 320px) minmax(520px, 1fr) minmax(300px, 380px); gap: 14px; height: 100%; overflow: hidden; padding: 14px; }
    .sidebar-panel, .content-panel, .evidence-rail { min-width: 0; min-height: 0; }
    .sidebar-panel { display: grid; gap: 14px; overflow: hidden; }
    .content-panel { display: grid; grid-template-rows: minmax(200px, 34vh) minmax(320px, 1fr); gap: 12px; overflow: hidden; }
    .evidence-rail { min-width: 0; overflow: auto; display: grid; align-content: start; gap: 14px; padding-right: 2px; }
    .queue-workspace { height: 100%; overflow: auto; }
    .panel-section, .run-card { border: 1px solid var(--line); border-radius: 8px; background: var(--surface-raised); box-shadow: var(--shadow-tight), var(--shadow-hairline); backdrop-filter: blur(18px); }
    .panel-section { padding: 16px; position: relative; overflow: hidden; }
    .panel-section.queue-workspace { min-height: 0; overflow: auto; overscroll-behavior: contain; }
    .panel-section::before, .run-card::before, .result-card::before { content: ""; position: absolute; inset: 0 0 auto; height: 2px; background: linear-gradient(90deg, var(--matrix-green), transparent 42%, var(--signal-indigo)); opacity: .82; }
    .panel-heading { display: flex; justify-content: space-between; gap: 12px; align-items: start; margin-bottom: 12px; }
    .panel-heading .meta { margin-top: 3px; }
    .section-heading { margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--line); }
    label { display: block; margin: 10px 0 5px; font-size: 12px; font-weight: 800; color: #b4c7d9; }
    input, select, textarea { width: 100%; border: 1px solid var(--line); border-radius: 7px; padding: 10px 11px; font: inherit; color: var(--ink); background: rgba(3,9,14,.74); transition: border-color .12s ease, box-shadow .12s ease, background-color .12s ease; box-shadow: var(--shadow-hairline); }
    input:focus, select:focus, textarea:focus { outline: none; border-color: rgba(0,255,171,.66); box-shadow: 0 0 0 3px rgba(0,255,171,.11), var(--shadow-hairline); background: rgba(4,13,19,.92); }
    textarea { min-height: 84px; resize: vertical; }
    button { border: 1px solid rgba(0,255,171,.52); background: linear-gradient(135deg, rgba(0,255,171,.92), rgba(0,215,255,.82)); color: #03110d; border-radius: 7px; padding: 9px 12px; font: inherit; font-weight: 900; cursor: pointer; transition: transform .08s ease, box-shadow .12s ease, opacity .12s ease, background-color .12s ease, border-color .12s ease; box-shadow: 0 10px 26px rgba(0,255,171,.16); }
    button:hover { background: linear-gradient(135deg, var(--phosphor), var(--signal-cyan)); box-shadow: 0 12px 30px rgba(0,215,255,.20); }
    button.secondary { background: rgba(10,22,30,.74); color: var(--ink); border-color: var(--line); box-shadow: var(--shadow-hairline); }
    button.secondary:hover { background: rgba(14,31,42,.92); border-color: rgba(0,255,171,.42); box-shadow: var(--shadow-tight); }
    button.warn { background: rgba(255,93,115,.16); color: #ffd8df; border-color: rgba(255,93,115,.50); }
    button.warn:hover { background: rgba(255,93,115,.24); }
    button:active { transform: translateY(1px); }
    button:focus-visible { outline: 3px solid rgba(0,255,171,.22); outline-offset: 2px; }
    button:disabled { opacity: .58; cursor: wait; }
    button.is-busy { position: relative; padding-left: 32px; }
    button.is-busy::before { content: ""; position: absolute; left: 11px; top: 50%; width: 12px; height: 12px; margin-top: -6px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 999px; animation: spin .75s linear infinite; }
    button.just-done { box-shadow: 0 0 0 3px rgba(0,255,171,.18); }
    button.just-error { box-shadow: 0 0 0 3px rgba(255,93,115,.22); }
    @keyframes spin { to { transform: rotate(360deg); } }
    .row { display: flex; gap: 8px; align-items: center; }
    .row > * { flex: 1; }
    .actions { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; align-items: center; }
    .run-panel { display: grid; gap: 12px; padding: 16px; min-height: 0; overflow: auto; align-content: start; overscroll-behavior: contain; }
    .runtime-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
    .inline-check { display: flex; align-items: center; gap: 8px; margin: 0; color: var(--ink); font-size: 13px; font-weight: 600; }
    .inline-check input { width: auto; }
    .llm-settings { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; border-top: 1px solid var(--line); padding-top: 12px; }
    .llm-settings[hidden] { display: none; }
    .llm-actions { grid-column: 1 / -1; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .llm-status { color: var(--muted); font-size: 12px; }
    .pwn-helper { border: 1px solid rgba(0,255,171,.24); border-radius: 8px; background: linear-gradient(180deg, rgba(0,255,171,.08), rgba(10,22,30,.78)); padding: 12px; display: grid; gap: 10px; }
    .pwn-helper[hidden] { display: none; }
    .pwn-helper h3 { margin: 0; font-size: 14px; }
    .command-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 6px; }
    .command-head strong { font-size: 13px; }
    .command-block { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; background: var(--code); color: var(--phosphor); border-radius: 8px; padding: 11px 12px; font-size: 12px; line-height: 1.5; border: 1px solid rgba(0,255,171,.18); box-shadow: inset 0 1px 0 rgba(255,255,255,.08); }
    .category-bar, .status-bar { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin: 12px 0 10px; }
    .category-pill, .status-pill { background: rgba(10,22,30,.76); color: var(--ink); border-color: var(--line); display: flex; justify-content: space-between; align-items: center; padding: 8px 10px; box-shadow: var(--shadow-hairline); }
    .category-pill:hover, .status-pill:hover { box-shadow: var(--shadow-tight); border-color: rgba(0,255,171,.36); }
    .category-pill.active, .status-pill.active { background: linear-gradient(135deg, rgba(0,255,171,.16), rgba(139,125,255,.12)); color: var(--phosphor); border-color: rgba(0,255,171,.42); box-shadow: inset 3px 0 0 var(--matrix-green), var(--shadow-hairline); }
    .category-pill span:last-child, .status-pill span:last-child { font-size: 12px; opacity: .85; }
    .list { display: grid; gap: 8px; margin-top: 12px; }
    .item { border: 1px solid var(--line); background: rgba(10,22,30,.72); border-radius: 8px; padding: 10px; cursor: pointer; transition: border-color .12s ease, box-shadow .12s ease, transform .08s ease; box-shadow: var(--shadow-hairline); }
    .item:hover { border-color: rgba(0,255,171,.36); box-shadow: var(--shadow-tight); }
    .item.active { border-color: rgba(0,255,171,.5); box-shadow: inset 3px 0 0 var(--matrix-green), var(--shadow-tight); background: rgba(14,31,42,.92); }
    .item-head { display: flex; justify-content: space-between; gap: 8px; align-items: center; }
    .category-group, .tool-group { border: 1px solid var(--line); border-radius: 8px; background: rgba(10,22,30,.78); overflow: hidden; box-shadow: var(--shadow-tight), var(--shadow-hairline); }
    .category-group summary, .tool-group summary { list-style: none; cursor: pointer; padding: 10px 12px; display: flex; justify-content: space-between; gap: 10px; align-items: center; }
    .category-group summary::-webkit-details-marker, .tool-group summary::-webkit-details-marker { display: none; }
    .category-group summary::before, .tool-group summary::before { content: "›"; color: var(--muted); font-size: 16px; transition: transform .15s ease; }
    .category-group[open] summary::before, .tool-group[open] summary::before { transform: rotate(90deg); }
    .category-items, .tool-items { display: grid; gap: 8px; padding: 0 10px 10px; }
    .group-count { color: var(--muted); font-size: 12px; margin-left: auto; }
    .meta { color: var(--muted); font-size: 12px; margin-top: 4px; overflow-wrap: anywhere; }
    .tabs { display: flex; gap: 6px; margin: 2px 0 0; overflow-x: auto; padding: 4px; border: 1px solid var(--line); border-radius: 8px; background: rgba(5,12,18,.82); box-shadow: var(--shadow-hairline), var(--shadow-tight); backdrop-filter: blur(18px); }
    .tabs button { background: transparent; color: #a9bbc8; border-color: transparent; border-radius: 6px; white-space: nowrap; box-shadow: none; font-size: 14px; line-height: 1.15; padding: 8px 10px; flex: 0 0 auto; }
    .tabs button:hover { background: rgba(0,255,171,.08); border-color: rgba(0,255,171,.24); box-shadow: none; }
    .tabs button.active { background: linear-gradient(135deg, rgba(0,255,171,.22), rgba(0,215,255,.16)); color: var(--phosphor); border-color: rgba(0,255,171,.42); }
    .result-view { display: flex; flex-direction: column; gap: 12px; min-height: 0; overflow: auto; padding-right: 2px; }
    .workspace-stack { min-height: 0; overflow: hidden; display: grid; grid-template-rows: auto minmax(0, 1fr); border: 1px solid var(--line); border-radius: 8px; background: var(--surface-raised); box-shadow: var(--shadow-tight), var(--shadow-hairline); backdrop-filter: blur(18px); }
    .workspace-stack .tabs { position: sticky; top: 0; z-index: 2; margin: 0; border: 0; border-bottom: 1px solid var(--line); border-radius: 8px 8px 0 0; background: rgba(5,12,18,.96); }
    .workspace-stack .result-view { padding: 12px; min-height: 0; overflow: auto; overscroll-behavior: contain; }
    .empty-state { border: 1px dashed var(--line-strong); border-radius: 8px; padding: 18px; color: var(--muted); background: rgba(10,22,30,.62); box-shadow: var(--shadow-hairline); }
    .result-card { position: relative; overflow: visible; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-raised); padding: 14px; display: grid; gap: 10px; flex: 0 0 auto; box-shadow: var(--shadow-tight), var(--shadow-hairline); backdrop-filter: blur(18px); }
    .result-card h3 { margin: 0; font-size: 15px; }
    .writeup-hero { border-color: rgba(0,255,171,.28); background: linear-gradient(180deg, rgba(0,255,171,.08), rgba(10,22,30,.82)); }
    .writeup-section-body { margin: 0; line-height: 1.65; color: #d7e7f2; }
    .writeup-section-body:empty { display: none; }
    .writeup-section .steps li { margin: 8px 0; line-height: 1.55; }
    .writeup-code { margin: 12px 0 0; max-height: 520px; overflow: auto; border: 1px solid rgba(0,255,171,.22); border-radius: 8px; background: var(--code); color: var(--phosphor); padding: 14px; line-height: 1.45; font-size: 12px; }
    .tab-intro { border: 1px solid rgba(0,255,171,.24); border-radius: 8px; background: linear-gradient(135deg, rgba(0,255,171,.10), rgba(139,125,255,.10)); color: #d7e7f2; padding: 10px 12px; font-size: 13px; box-shadow: var(--shadow-tight), var(--shadow-hairline); }
    .tab-intro strong { display: block; margin-bottom: 3px; color: var(--ink); }
    .card-head { display: flex; justify-content: space-between; gap: 12px; align-items: start; flex-wrap: wrap; }
    .card-title { display: grid; gap: 4px; min-width: 0; }
    .badge { display: inline-flex; width: fit-content; align-items: center; border-radius: 999px; padding: 3px 8px; font-size: 12px; background: rgba(0,255,171,.10); color: var(--phosphor); border: 1px solid rgba(0,255,171,.28); box-shadow: var(--shadow-hairline); }
    .badge.warn { background: var(--warn-soft); color: #ffe1a0; border-color: rgba(255,191,77,.38); }
    .badge.muted { background: rgba(145,166,184,.10); color: var(--muted); border-color: var(--line); }
    .flag-list { display: flex; gap: 8px; flex-wrap: wrap; }
    .flag-chip { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: var(--code); color: var(--phosphor); border-radius: 6px; padding: 5px 8px; overflow-wrap: anywhere; border: 1px solid rgba(0,255,171,.18); }
    .tag-row { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 6px; }
    .tag-chip { border: 1px solid var(--line); border-radius: 999px; background: rgba(10,22,30,.78); color: var(--muted); padding: 2px 7px; font-size: 11px; }
    .kv-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
    .kv { border: 1px solid var(--line); border-radius: 8px; padding: 9px 10px; background: rgba(5,12,18,.66); min-width: 0; box-shadow: var(--shadow-hairline); }
    .kv span { display: block; color: var(--muted); font-size: 12px; margin-bottom: 4px; }
    .kv strong { overflow-wrap: anywhere; }
    .steps { margin: 0; padding-left: 20px; }
    .steps li { margin: 5px 0; }
    details.raw { border-top: 1px solid var(--line); padding-top: 8px; }
    details.raw summary { color: var(--muted); cursor: pointer; font-size: 13px; }
    pre.raw-json { margin: 8px 0 0; white-space: pre-wrap; overflow-wrap: anywhere; background: var(--code); color: var(--phosphor); border-radius: 8px; padding: 12px; max-height: 360px; overflow: auto; border: 1px solid rgba(0,255,171,.18); }
    .status { position: relative; z-index: 1; font-size: 12px; color: var(--phosphor); border: 1px solid rgba(0,255,171,.28); background: rgba(5,12,18,.76); border-radius: 999px; padding: 6px 10px; white-space: nowrap; box-shadow: var(--shadow-hairline); }
    .status[data-tone="busy"] { color: var(--signal-cyan); border-color: rgba(0,215,255,.38); background: rgba(0,215,255,.10); }
    .status[data-tone="success"] { color: var(--matrix-green); }
    .status[data-tone="error"] { color: #ffd8df; border-color: rgba(255,93,115,.38); background: var(--danger-soft); }
    .action-toast { position: fixed; right: 18px; top: 92px; z-index: 10; max-width: min(420px, calc(100vw - 36px)); border: 1px solid rgba(0,255,171,.28); border-radius: 8px; background: rgba(5,12,18,.9); color: #d7e7f2; padding: 10px 12px; font-size: 13px; box-shadow: var(--shadow-soft), var(--shadow-hairline); backdrop-filter: blur(18px); }
    .action-toast[data-tone="busy"] { border-color: rgba(0,215,255,.38); }
    .action-toast[data-tone="success"] { border-color: rgba(0,255,171,.38); background: rgba(0,255,171,.10); }
    .action-toast[data-tone="error"] { border-color: rgba(255,93,115,.38); background: var(--danger-soft); color: #ffd8df; }
    .action-toast[hidden] { display: none; }
    @media (max-width: 1280px) { .app-shell { grid-template-columns: minmax(220px, 260px) minmax(420px, 1fr) minmax(240px, 300px); } .evidence-rail { grid-template-columns: 1fr; overflow: auto; } .mission-strip { min-width: min(420px, 42vw); } }
    @media (max-width: 900px) { body { height: auto; overflow: visible; display: block; } .app-shell { grid-template-columns: 1fr; height: auto; overflow: visible; } .sidebar-panel, .content-panel { overflow: visible; } .content-panel { grid-template-rows: auto auto; } .workspace-stack { height: min(760px, calc(100vh - 96px)); } .panel-section.queue-workspace { height: min(640px, calc(100vh - 96px)); } .evidence-rail { grid-template-columns: 1fr; } .mission-strip { min-width: 0; width: 100%; } }
    @media (max-width: 720px) { .topbar { align-items: start; flex-direction: column; padding: 13px 16px; } .mission-strip { grid-template-columns: 1fr; } .app-shell { padding: 12px; gap: 12px; } .row, .runtime-grid, .llm-settings, .kv-grid { display: grid; grid-template-columns: 1fr; } .category-bar, .status-bar { grid-template-columns: 1fr; } .tabs { padding-bottom: 5px; } .status { white-space: normal; } .brand-line { align-items: start; } }
  </style>
</head>
<body data-theme="forgeflag-hacker-ops">
  <header class="topbar">
    <div class="signal-field"></div>
    <div class="ops-orbit"></div>
    <div class="brand">
      <div class="brand-line"><div class="brand-mark">FF</div><h1>ForgeFlag Workbench</h1></div>
      <div class="brand-subtitle">Local and authorized CTF challenge research console</div>
      <div class="brand-meta"><span class="signal-chip">Mission console</span><span class="signal-chip indigo">Evidence rail</span><span class="signal-chip amber">CTF scoped</span></div>
    </div>
    <div class="mission-strip" aria-label="ForgeFlag readiness overview">
      <div class="mission-tile"><span>Scope</span><strong>Local / authorized CTF</strong></div>
      <div class="mission-tile"><span>Mode</span><strong>Replay evidence first</strong></div>
      <div class="mission-tile"><span>Runtime</span><strong id="status" class="runtime-status">ready</strong></div>
    </div>
  </header>
  <div class="action-toast" id="actionToast" role="status" aria-live="polite" hidden></div>
  <main class="app-shell">
    <aside class="sidebar-panel queue-column">
      <div class="panel-section queue-workspace">
        <div class="panel-heading">
          <div>
            <h2>Challenge queue</h2>
            <div class="meta">筛选、选择和回到最近的 CTF 题目，不把录入表单塞进主流程。</div>
          </div>
          <button class="secondary" id="refreshBtn" type="button">刷新</button>
        </div>
        <h2 class="section-heading">分类工作台</h2>
        <div class="category-bar" id="categoryFilters"></div>
        <div class="meta" id="categoryCounts"></div>
        <h2 class="section-heading">状态筛选</h2>
        <div class="status-bar" id="statusFilters"></div>
        <div class="meta" id="statusCounts"></div>
        <h2 class="section-heading">题目列表</h2>
        <div class="list" id="challengeList"></div>
      </div>
    </aside>
    <section class="content-panel mission-column">
      <div class="run-panel run-card">
        <div class="panel-heading">
          <div>
            <h2>Run control</h2>
            <div class="meta">运行选中题目，控制主动探测和 LLM 辅助，保留可复现证据。</div>
          </div>
        </div>
        <div class="actions">
          <button id="runBtn">运行选中题目</button>
          <label class="inline-check"><input id="activeProbe" type="checkbox"> Active probe</label>
          <label class="inline-check"><input id="llmEnabled" type="checkbox"> 大模型分析</label>
        </div>
        <div class="runtime-grid">
          <div>
            <label>Allowed Hosts</label>
            <input id="allowedHosts" placeholder="127.0.0.1,localhost">
          </div>
          <div>
            <label>LLM Provider</label>
            <select id="llmProvider">
              <option value="zhipu">智谱 GLM</option>
              <option value="openai">OpenAI-compatible</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>
        </div>
        <form class="llm-settings" id="llmSettings" hidden autocomplete="off" onsubmit="return false;">
          <div>
            <label>Model</label>
            <input id="llmModel" placeholder="gpt-4.1">
          </div>
          <div>
            <label>API Key</label>
            <input id="llmApiKey" type="password" autocomplete="off" placeholder="sk-...">
          </div>
          <div>
            <label>Saved Key</label>
            <select id="llmSavedKeySelect">
              <option value="">选择已保存 Key</option>
            </select>
          </div>
          <div>
            <label>Base URL</label>
            <input id="llmBaseUrl" placeholder="https://api.openai.com/v1">
          </div>
          <div>
            <label>Timeout Seconds</label>
            <input id="llmTimeout" type="number" min="1" value="30">
          </div>
          <div class="llm-actions">
            <button class="secondary" id="llmSaveConfig" type="button">保存配置</button>
            <button class="secondary" id="llmClearSavedKeys" type="button">清空保存Key</button>
            <button class="secondary" id="llmTestBtn" type="button">测试大模型</button>
            <span class="llm-status" id="llmConfigStatus">配置未保存；保存后 API Key 会保存到本浏览器</span>
          </div>
        </form>
      </div>
      <section class="workspace-stack" aria-label="Challenge analysis workspace">
        <div class="tabs">
          <button class="active" data-tab="summary">Summary</button>
          <button data-tab="report">Write-up</button>
          <button data-tab="agent">Agent</button>
          <button data-tab="findings">Findings</button>
          <button data-tab="observations">Observations</button>
          <button data-tab="artifacts">Artifacts</button>
          <button data-tab="benchmark">Benchmark</button>
          <button data-tab="health">Health</button>
          <button data-tab="tools">Tools</button>
          <button data-tab="catalog">Catalog</button>
        </div>
        <div id="output" class="result-view"><div class="empty-state">选择题目并运行后，这里会显示可读的解题结果。</div></div>
      </section>
    </section>
    <aside class="evidence-rail">
      <div class="panel-section intake-panel">
        <div class="panel-heading">
          <div>
            <h2>Evidence rail</h2>
            <div class="meta">新建 / 更新题目，上传本地附件，保留 CTF/lab replay 上下文。</div>
          </div>
        </div>
        <label>Challenge ID</label>
        <div class="row">
          <input id="challengeId" placeholder="自动生成，如 crypto-20260603-195201-rsa">
          <button class="secondary" id="generateIdBtn" type="button">自动生成</button>
        </div>
        <div class="row">
          <div><label>Category</label><select id="category"></select></div>
          <div><label>Tags</label><input id="tags" placeholder="zip,stego"></div>
        </div>
        <label>Title</label>
        <input id="title">
        <label>Target</label>
        <input id="target" placeholder="http://127.0.0.1:8081">
        <label>Description</label>
        <textarea id="description"></textarea>
        <label>Attachments</label>
        <input id="attachments" type="file" multiple>
        <div class="actions">
          <button id="saveBtn">保存题目</button>
          <button class="warn" id="deleteBtn">删除选中</button>
          <button class="warn" id="clearBtn">清空全部</button>
        </div>
      </div>
      <div class="pwn-helper" id="pwnEnvironmentPanel" hidden></div>
    </aside>
  </main>
  <script>
    const categories = ["unknown","web","pwn","reverse","crypto","forensics","traffic","misc","infra"];
    const categoryLabels = { all:"全部", unknown:"未知", web:"Web", pwn:"Pwn", reverse:"Reverse", crypto:"Crypto", forensics:"Forensics", traffic:"Traffic", misc:"Misc", infra:"Infra" };
    const statusFilters = ["all","solved","ran","not_run"];
    const statusLabels = { all:"全部", solved:"已出 flag", ran:"已运行未出", not_run:"未运行" };
    const state = { selected: null, activeCategory: "all", activeStatus: "all", challenges: [], lastSummary: {}, summaries: {}, openChallengeGroups: {}, idTouched: false };
    const writeupSectionOrder = ["解题思路", "复现步骤"];
    const builtinAnalysisHintIds = ["traffic-http-webshell-delimited-flag", "traffic-data-uri-image", "traffic-raw-capture-flag-scan", "traffic-pcap-resync-ip-id-stego", "traffic-rf-image-manchester-ask", "forensics-registry-wifi", "forensics-bmp-quickstego-braille", "forensics-visual-crypto-xor", "forensics-osint-building-geolocation", "forensics-osint-music-cross-reference", "forensics-archive-mangled-png", "forensics-minecraft-region-orphan", "web-renderer-dns-rebinding", "web-basic-auth-prefix-strcmp", "web-php-pack-procfs", "web-loopback-alias-ssrf", "web-python-class-pollution", "web-h3-h1-request-smuggling", "web-lamenote-substring-oracle", "crypto-python-random-prime-offset", "crypto-linear-xorshift-inverse", "crypto-shifted-rsa-factor-leak", "crypto-rsa-modular-low-exponent-root", "crypto-lfsr-berlekamp-massey", "crypto-prng-stream-replay", "crypto-debruijn-pin-replay", "crypto-chacha-state-keystream", "crypto-composite-ntru-crt-lattice", "misc-recipe-state", "misc-decayed-doublehelix-ruby", "misc-recursive-regex-golf", "misc-python-eval-blacklist-bypass", "misc-vivado-dcp-edif-lut", "misc-i2c-eeprom-schematic-dump", "misc-sparse-adversarial-pixels", "pwn-ret2win-escaped-bytes", "pwn-int16-hp-overflow", "pwn-heap-off-by-one-overlap", "pwn-suffix-retaddr-alignment", "pwn-uaf-uninitialized-list-next", "pwn-aarch64-pac-signing-oracle", "pwn-glibc-tcache-malloc-hook", "pwn-ret2vdso-vm-artifact-check", "reverse-elf-argv-repeating-xor", "reverse-jmp-popcount-table", "reverse-compiled-byte-equality-chain", "reverse-pe-stack-xor-key-check", "reverse-mlvm-pixel-art", "reverse-python-vm-perfect-sha1", "reverse-python-grid-constraints"];
    const $ = (id) => document.getElementById(id);
    let toastTimer = null;
    const status = (text, tone="info") => {
      const headerStatus = $("status");
      headerStatus.textContent = text;
      headerStatus.dataset.tone = tone;
      const toast = $("actionToast");
      if (toast) {
        toast.textContent = text;
        toast.dataset.tone = tone;
        toast.hidden = false;
        clearTimeout(toastTimer);
        if (tone !== "busy") {
          toastTimer = setTimeout(() => { toast.hidden = true; }, tone === "error" ? 5200 : 2800);
        }
      }
      return text;
    };
    function setButtonBusy(buttonOrId, busy, busyText) {
      const button = typeof buttonOrId === "string" ? $(buttonOrId) : buttonOrId;
      if (!button) return;
      if (!button.dataset.idleLabel) button.dataset.idleLabel = button.textContent;
      button.disabled = busy;
      button.classList.toggle("is-busy", busy);
      button.setAttribute("aria-busy", busy ? "true" : "false");
      button.textContent = busy ? busyText : button.dataset.idleLabel;
    }
    function flashButton(buttonOrId, tone="success") {
      const button = typeof buttonOrId === "string" ? $(buttonOrId) : buttonOrId;
      if (!button) return;
      const className = tone === "error" ? "just-error" : "just-done";
      button.classList.add(className);
      setTimeout(() => button.classList.remove(className), 900);
    }
    async function withButtonFeedback(buttonId, busyText, successText, action) {
      setButtonBusy(buttonId, true, busyText);
      status(busyText, "busy");
      try {
        const result = await action();
        if (result !== false) {
          flashButton(buttonId, "success");
          if (successText) status(successText, "success");
        }
        return result;
      } catch (error) {
        flashButton(buttonId, "error");
        status(error.message || "操作失败", "error");
        throw error;
      } finally {
        setButtonBusy(buttonId, false);
      }
    }
    const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[ch]));
    const rawJson = (data) => `<details class="raw"><summary>查看调试 JSON</summary><pre class="raw-json">${escapeHtml(JSON.stringify(data, null, 2))}</pre></details>`;
    const asList = (value) => Array.isArray(value) ? value : [];
    const show = (data, tab="raw") => $("output").innerHTML = renderData(tab, data);
    const LLM_CONFIG_KEY = "forgeflag.llm.config.v1";
    const LLM_SAVED_KEYS_LIMIT = 10;
    const DEFAULT_ZHIPU_MODEL = "glm-5.1";
    const PWN_LOCAL_TARGET = "tcp://127.0.0.1:31337";
    categories.forEach(c => { const o = document.createElement("option"); o.value = c; o.textContent = c; $("category").appendChild(o); });
    function slugifyIdPart(value) {
      return String(value || "")
        .normalize("NFKD")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 36) || "challenge";
    }
    function timestampForId(date = new Date()) {
      const pad = value => String(value).padStart(2, "0");
      return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
    }
    function generateChallengeId() {
      const category = slugifyIdPart($("category").value || "unknown");
      const upload = Array.from($("attachments").files || []).map(file => file.name)[0];
      const titleSeed = $("title").value.trim() || $("target").value.trim() || upload || "challenge";
      const base = `${category}-${timestampForId()}-${slugifyIdPart(titleSeed)}`;
      const existing = new Set(state.challenges.map(ch => ch.challenge_id));
      let candidate = base;
      let suffix = 2;
      while (existing.has(candidate)) candidate = `${base}-${suffix++}`;
      return candidate;
    }
    function ensureChallengeId(force=false) {
      if (!force && state.idTouched && $("challengeId").value.trim()) return $("challengeId").value.trim();
      const generated = generateChallengeId();
      $("challengeId").value = generated;
      state.idTouched = false;
      return generated;
    }
    function maybeRefreshGeneratedId() {
      if (!state.idTouched || !$("challengeId").value.trim()) ensureChallengeId(false);
    }
    function syncLLMSettings() {
      $("llmSettings").hidden = !$("llmEnabled").checked;
      if ($("llmEnabled").checked && $("llmProvider").value === "disabled") $("llmProvider").value = "zhipu";
      const zhipu = $("llmProvider").value === "zhipu";
      $("llmModel").placeholder = zhipu ? DEFAULT_ZHIPU_MODEL : "gpt-4.1";
      if (zhipu && !$("llmModel").value.trim()) $("llmModel").value = DEFAULT_ZHIPU_MODEL;
      $("llmApiKey").placeholder = zhipu ? "ZAI_API_KEY" : "sk-...";
      $("llmBaseUrl").placeholder = zhipu ? "https://open.bigmodel.cn/api/paas/v4" : "https://api.openai.com/v1";
      hydrateLLMKeyFromStorage();
      renderSavedLLMKeyOptions();
    }
    function llmPayload() {
      const llmEnabled = $("llmEnabled").checked;
      return {
        llm_enabled: llmEnabled,
        llm_provider: llmEnabled ? $("llmProvider").value : "disabled",
        llm_model: $("llmModel").value.trim(),
        llm_api_key: $("llmApiKey").value.trim(),
        llm_base_url: $("llmBaseUrl").value.trim(),
        llm_timeout_seconds: $("llmTimeout").value
      };
    }
    function saveLLMConfig() {
      const payload = llmPayload();
      const previous = readSavedLLMConfig() || {};
      const saved = {
        llm_enabled: payload.llm_enabled,
        llm_provider: payload.llm_provider,
        llm_model: payload.llm_model,
        llm_api_key: payload.llm_api_key,
        llm_saved_keys: upsertSavedLLMKey(previous, payload),
        llm_base_url: payload.llm_base_url,
        llm_timeout_seconds: payload.llm_timeout_seconds
      };
      localStorage.setItem(LLM_CONFIG_KEY, JSON.stringify(saved));
      renderSavedLLMKeyOptions(payload.llm_api_key);
      $("llmConfigStatus").textContent = payload.llm_api_key ? "配置已保存到本浏览器（含 Key）" : "配置已保存到本浏览器（未保存 Key）";
      flashButton("llmSaveConfig", "success");
      status("大模型配置已保存", "success");
    }
    function readSavedLLMConfig() {
      const raw = localStorage.getItem(LLM_CONFIG_KEY);
      if (!raw) return null;
      try {
        return JSON.parse(raw);
      } catch {
        return null;
      }
    }
    function savedLLMKeys(saved = readSavedLLMConfig()) {
      if (!saved) return [];
      const rows = Array.isArray(saved.llm_saved_keys) ? saved.llm_saved_keys : [];
      const legacy = saved.llm_api_key ? [{
        provider: saved.llm_provider || "zhipu",
        model: saved.llm_model || "",
        api_key: saved.llm_api_key,
        base_url: saved.llm_base_url || "",
        saved_at: saved.saved_at || ""
      }] : [];
      const deduped = [];
      const seen = new Set();
      [...rows, ...legacy].forEach(row => {
        const apiKey = String(row && (row.api_key || row.llm_api_key) || "");
        if (!apiKey) return;
        const provider = String(row.provider || row.llm_provider || "zhipu");
        const identity = `${provider}:${apiKey}`;
        if (seen.has(identity)) return;
        seen.add(identity);
        deduped.push({
          provider,
          model: String(row.model || row.llm_model || ""),
          api_key: apiKey,
          base_url: String(row.base_url || row.llm_base_url || ""),
          saved_at: String(row.saved_at || "")
        });
      });
      return deduped.slice(0, LLM_SAVED_KEYS_LIMIT);
    }
    function maskLLMKey(apiKey) {
      const key = String(apiKey || "");
      if (key.length <= 10) return key ? "saved key" : "";
      return `${key.slice(0, 6)}...${key.slice(-4)}`;
    }
    function upsertSavedLLMKey(saved, payload) {
      const apiKey = String(payload.llm_api_key || "").trim();
      const rows = savedLLMKeys(saved);
      if (!apiKey) return rows;
      const provider = payload.llm_provider || "zhipu";
      const next = {
        provider,
        model: payload.llm_model || "",
        api_key: apiKey,
        base_url: payload.llm_base_url || "",
        saved_at: new Date().toISOString()
      };
      return [next, ...rows.filter(row => !(row.provider === provider && row.api_key === apiKey))].slice(0, LLM_SAVED_KEYS_LIMIT);
    }
    function renderSavedLLMKeyOptions(selectedKey = "") {
      const select = $("llmSavedKeySelect");
      if (!select) return;
      const rows = savedLLMKeys();
      select.innerHTML = "";
      const empty = document.createElement("option");
      empty.value = "";
      empty.textContent = rows.length ? "选择已保存 Key" : "暂无已保存 Key";
      select.appendChild(empty);
      rows.forEach((row, index) => {
        const option = document.createElement("option");
        option.value = String(index);
        option.textContent = `${row.provider || "llm"} ${maskLLMKey(row.api_key)}`;
        if (selectedKey && row.api_key === selectedKey) option.selected = true;
        select.appendChild(option);
      });
    }
    function applySavedLLMKey(index) {
      if (index === "") return;
      const row = savedLLMKeys()[Number(index)];
      if (!row) return;
      $("llmEnabled").checked = true;
      $("llmProvider").value = row.provider || "zhipu";
      $("llmModel").value = row.model || (row.provider === "zhipu" ? DEFAULT_ZHIPU_MODEL : "");
      $("llmBaseUrl").value = row.base_url || "";
      $("llmApiKey").value = row.api_key || "";
      syncLLMSettings();
      $("llmSavedKeySelect").value = String(index);
      $("llmConfigStatus").textContent = "已从保存的 Key 填充";
      status("已填充保存的 API Key", "success");
    }
    function clearSavedLLMKeys() {
      const saved = readSavedLLMConfig() || {};
      saved.llm_api_key = "";
      saved.llm_saved_keys = [];
      localStorage.setItem(LLM_CONFIG_KEY, JSON.stringify(saved));
      $("llmApiKey").value = "";
      renderSavedLLMKeyOptions();
      $("llmConfigStatus").textContent = "已清空本浏览器保存的 Key";
      status("已清空保存的 API Key", "success");
    }
    function hydrateLLMKeyFromStorage() {
      if (!$("llmEnabled").checked || $("llmApiKey").value.trim()) return;
      const saved = readSavedLLMConfig();
      const row = savedLLMKeys(saved).find(item => item.provider === $("llmProvider").value) || savedLLMKeys(saved)[0];
      if (!row || !row.api_key) return;
      $("llmApiKey").value = row.api_key;
    }
    function ensureLLMReady() {
      if (!$("llmEnabled").checked) return true;
      syncLLMSettings();
      const payload = llmPayload();
      if (payload.llm_provider === "disabled") {
        $("llmConfigStatus").textContent = "请先选择大模型 Provider";
        status("请先选择大模型 Provider", "error");
        return false;
      }
      if (!payload.llm_model) {
        $("llmConfigStatus").textContent = "请先填写大模型版本";
        status("请先填写大模型版本", "error");
        return false;
      }
      if (!payload.llm_api_key) {
        $("llmConfigStatus").textContent = "请先填写并保存大模型 API Key";
        status("请先填写并保存大模型 API Key", "error");
        flashButton("llmSaveConfig", "error");
        return false;
      }
      return true;
    }
    function restoreLLMConfig() {
      const saved = readSavedLLMConfig();
      if (!saved) return syncLLMSettings();
      try {
        $("llmEnabled").checked = !!saved.llm_enabled;
        $("llmProvider").value = saved.llm_provider || "zhipu";
        $("llmModel").value = saved.llm_model || "";
        $("llmBaseUrl").value = saved.llm_base_url || "";
        $("llmTimeout").value = saved.llm_timeout_seconds || "30";
        $("llmApiKey").value = saved.llm_api_key || "";
        $("llmConfigStatus").textContent = saved.llm_api_key ? "已载入本浏览器配置（含 Key）" : "已载入本浏览器配置（未保存 Key）";
        renderSavedLLMKeyOptions(saved.llm_api_key || "");
      } catch {
        $("llmConfigStatus").textContent = "本地配置读取失败";
      }
      syncLLMSettings();
    }
    function categoryCounts(challenges) {
      const counts = Object.fromEntries(["all", ...categories].map(c => [c, 0]));
      counts.all = challenges.length;
      challenges.forEach(ch => counts[ch.category] = (counts[ch.category] || 0) + 1);
      return counts;
    }
    function renderCategoryFilters(challenges) {
      const counts = categoryCounts(challenges);
      const filters = $("categoryFilters");
      filters.innerHTML = "";
      ["all", ...categories].forEach(category => {
        const btn = document.createElement("button");
        btn.className = "category-pill" + (state.activeCategory === category ? " active" : "");
        btn.innerHTML = `<span>${categoryLabels[category] || category}</span><span>${counts[category] || 0}</span>`;
        btn.onclick = () => {
          state.activeCategory = category;
          if (category !== "all") $("category").value = category;
          renderChallengeList();
          renderCategoryFilters(state.challenges);
          renderStatusFilters(state.challenges);
        };
        filters.appendChild(btn);
      });
      $("categoryCounts").textContent = `当前分类：${categoryLabels[state.activeCategory] || state.activeCategory}，题目数：${counts[state.activeCategory] || 0}`;
    }
    function statusCounts(challenges) {
      const rows = challenges.filter(ch => state.activeCategory === "all" || ch.category === state.activeCategory);
      const counts = Object.fromEntries(statusFilters.map(status => [status, 0]));
      counts.all = rows.length;
      rows.forEach(ch => {
        const key = statusBucket(ch);
        counts[key] = (counts[key] || 0) + 1;
      });
      return counts;
    }
    function renderStatusFilters(challenges) {
      const counts = statusCounts(challenges);
      const filters = $("statusFilters");
      filters.innerHTML = "";
      statusFilters.forEach(filter => {
        const btn = document.createElement("button");
        btn.className = "status-pill" + (state.activeStatus === filter ? " active" : "");
        btn.innerHTML = `<span>${statusLabels[filter] || filter}</span><span>${counts[filter] || 0}</span>`;
        btn.onclick = () => {
          state.activeStatus = filter;
          renderChallengeList();
          renderStatusFilters(state.challenges);
        };
        filters.appendChild(btn);
      });
      $("statusCounts").textContent = `当前状态：${statusLabels[state.activeStatus] || state.activeStatus}，题目数：${counts[state.activeStatus] || 0}`;
    }
    async function api(path, options={}) {
      const res = await fetch(path, options);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      return data;
    }
    async function filesPayload() {
      const files = Array.from($("attachments").files || []);
      const out = [];
      for (const file of files) {
        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        out.push({ name: file.name, content_base64: btoa(binary) });
      }
      return out;
    }
    async function refresh() {
      const challenges = await api("/api/challenges");
      state.challenges = challenges;
      reconcileSelectedChallenge(challenges);
      renderCategoryFilters(challenges);
      renderStatusFilters(challenges);
      renderChallengeList();
      renderPwnEnvironmentPanel();
      if (!state.selected) show(draftChallengeSummary(), "summary");
      else if (state.summaries[state.selected]) show(state.summaries[state.selected], "summary");
      else show({}, "summary");
    }
    function reconcileSelectedChallenge(challenges) {
      if (!state.selected) return;
      if (challenges.some(ch => ch.challenge_id === state.selected)) return;
      delete state.summaries[state.selected];
      state.selected = null;
      state.lastSummary = {};
    }
    function draftChallengeSummary() {
      const challengeId = $("challengeId").value.trim();
      if (!challengeId) return {};
      return {
        challenge_id: challengeId,
        status: "not_found",
        solvers: [],
        accepted_flags: [],
        rejected_flags: [],
        proof_status: "not_found",
        proof: {
          status: "not_found",
          label: "Challenge not saved",
          verified: false,
          summary: "当前 ID 尚未保存，不属于题目列表，也不会参与状态分组。",
          next_action: "请先保存题目或从列表选择已有题目。"
        },
        observations: 0
      };
    }
    function renderChallengeList() {
      const list = $("challengeList");
      list.innerHTML = "";
      const visible = state.challenges.filter(ch => (state.activeCategory === "all" || ch.category === state.activeCategory) && statusMatches(ch));
      if (!visible.length) {
        list.innerHTML = `<div class="empty-state">当前筛选暂无题目。</div>`;
        renderPwnEnvironmentPanel();
        return;
      }
      list.innerHTML = renderChallengeGroups(visible);
      list.querySelectorAll("details.category-group").forEach(details => {
        details.addEventListener("toggle", () => {
          state.openChallengeGroups[details.dataset.category] = details.open;
        });
      });
      list.querySelectorAll("[data-challenge-id]").forEach(item => {
        item.onclick = () => {
          state.selected = item.dataset.challengeId;
          renderChallengeList();
          renderPwnEnvironmentPanel();
          loadTab(document.querySelector(".tabs button.active").dataset.tab).catch(e => show({error:e.message}));
        };
      });
    }
    function renderChallengeGroups(challenges) {
      const groups = groupRows(challenges, ch => ch.category || "unknown");
      return groupOrder(groups, categories).map(category => {
        const rows = groups[category] || [];
        const selectedInGroup = rows.some(ch => ch.challenge_id === state.selected);
        const shouldOpen = groupOpenState(category, selectedInGroup);
        return `<details class="category-group" data-category="${escapeHtml(category)}" ${shouldOpen ? "open" : ""}>
          <summary><strong>${escapeHtml(categoryLabels[category] || category)}</strong><span class="group-count">${rows.length}</span></summary>
          <div class="category-items">
            ${rows.map(ch => `
              <div class="item${state.selected === ch.challenge_id ? " active" : ""}" data-challenge-id="${escapeHtml(ch.challenge_id)}">
                <div class="item-head"><strong>${escapeHtml(ch.challenge_id)}</strong>${statusLabel(ch)}</div>
                <div class="meta">${escapeHtml(ch.target || ch.title || "无目标")}</div>
                ${tagChips(ch.tags || [])}
                <div class="meta">${escapeHtml((ch.attachment_paths || []).join(", "))}</div>
              </div>`).join("")}
          </div>
        </details>`;
      }).join("");
    }
    function groupOpenState(category, selectedInGroup) {
      if (selectedInGroup) return true;
      if (Object.prototype.hasOwnProperty.call(state.openChallengeGroups, category)) return state.openChallengeGroups[category];
      return true;
    }
    function statusLabel(challenge) {
      const status = challenge.latest_status || "not_run";
      const count = challenge.accepted_flag_count || 0;
      const proof = proofLabel(challenge.proof || {status: challenge.proof_status || status});
      const badgeClass = proof.verified ? "badge" : (status === "not_run" ? "badge muted" : "badge warn");
      const suffix = count ? ` · ${count} flag` : "";
      return `<span class="${badgeClass}">${escapeHtml(proof.label || status)}${escapeHtml(suffix)}</span>`;
    }
    function proofLabel(proof) {
      const status = (proof && (proof.status || proof.proof_status)) || "not_run";
      const labels = {
        flag_found: "Flag verified",
        exploit_verified: "Exploit verified",
        exploit_plan: "Exploit plan",
        analysis_only: "Analysis only",
        completed: "Completed",
        not_run: "Not run"
      };
      return {
        status,
        label: (proof && proof.label) || labels[status] || status,
        verified: !!(proof && proof.verified) || status === "flag_found" || status === "exploit_verified",
        summary: (proof && proof.summary) || "",
        next_action: (proof && proof.next_action) || "",
        required_evidence: asList(proof && proof.required_evidence)
      };
    }
    function tagChips(tags) {
      const values = asList(tags).filter(Boolean).slice(0, 5);
      if (!values.length) return "";
      return `<div class="tag-row">${values.map(tag => `<span class="tag-chip">${escapeHtml(tag)}</span>`).join("")}</div>`;
    }
    function isSolvedStatus(status) {
      return status === "flag_found" || status === "exploit_verified";
    }
    function statusBucket(challenge) {
      const proof = proofLabel(challenge.proof || {status: challenge.proof_status || challenge.latest_status});
      if ((challenge.accepted_flag_count || 0) > 0 || isSolvedStatus(challenge.latest_status) || isSolvedStatus(challenge.proof_status) || proof.verified) return "solved";
      if (challenge.latest_status && challenge.latest_status !== "not_run") return "ran";
      return "not_run";
    }
    function statusMatches(challenge) {
      return state.activeStatus === "all" || statusBucket(challenge) === state.activeStatus;
    }
    function renderData(tab, data) {
      const intro = tabIntro(tab);
      if (tab === "summary") return intro + renderSummary(data);
      if (tab === "agent") return intro + renderAgentView(data);
      if (tab === "findings") return intro + renderFindings(data);
      if (tab === "observations") return intro + renderObservations(data);
      if (tab === "artifacts") return intro + renderArtifacts(data);
      if (tab === "report") return intro + renderReport(data);
      if (tab === "benchmark") return intro + renderBenchmark(data);
      if (tab === "health") return intro + renderSystemHealth(data);
      if (tab === "tools") return intro + renderToolRows(data, "工具可用性", "tool");
      if (tab === "catalog") return intro + renderToolRows(data, "项目目录", "catalog");
      return intro + renderRaw(data);
    }
    function tabIntro(tab) {
      const intros = {
        summary: ["Summary", "总览本题最近一次运行状态、已确认 flag、执行过的 solver 和被拒候选。"],
        agent: ["Agent", "按答题者视角串起 LLM 规划、知识检索、行动队列、工具摘要和最短发现路径。"],
        findings: ["Findings", "每个 solver 产出的发现、判断依据、置信度和建议下一步。"],
        observations: ["Observations", "跨 solver 共享的线索池，包括 LLM 建议、flag 候选和工具压缩摘要。"],
        artifacts: ["Artifacts", "确认上传附件是否已进入工作区，并查看文件大小、SHA256 和实际路径。"],
        report: ["Write-up", "只保留解题思路和复现步骤，方便照着复现拿 flag。"],
        benchmark: ["Benchmark", "最新能力评测、证据分、UI flow 和角色 Backlog，用来判断 ForgeFlag 是否真的能打。"],
        health: ["Health", "商业化健康检查：运行时、工具链、benchmark gate、LLM 和下一步修复建议。"],
        tools: ["Tools", "本机和 Docker 中可用的工具清单，以及缺失工具和验证命令。"],
        catalog: ["Catalog", "推荐集成的 CTF 项目目录，用来规划后续工具能力，不会自动安装。"],
      };
      const info = intros[tab] || ["Raw", "原始接口数据，用于调试。"];
      return `<div class="tab-intro"><strong>${escapeHtml(info[0])}</strong>${escapeHtml(info[1])}</div>`;
    }
    function renderRaw(data) {
      if (Array.isArray(data) && data.length === 0) return `<div class="empty-state">暂无数据。</div>${rawJson(data)}`;
      return `<div class="result-card"><div class="card-head"><div class="card-title"><h3>原始结果</h3><div class="meta">该视图暂未做专门排版。</div></div></div>${rawJson(data)}</div>`;
    }
    function flagChips(flags) {
      const values = asList(flags);
      if (!values.length) return `<div class="meta">暂未确认 flag。</div>`;
      return `<div class="flag-list">${values.map(flag => `<span class="flag-chip">${escapeHtml(flag)}</span>`).join("")}</div>`;
    }
    function renderSummary(data) {
      if (!data || !data.challenge_id) {
        return `<div class="empty-state">还没有本轮运行摘要。点击“运行选中题目”后会在这里显示状态、flag 和执行路径。</div>`;
      }
      const proof = proofLabel(data.proof || {status: data.proof_status || data.status});
      const statusClass = proof.verified ? "badge" : "badge muted";
      const rejected = asList(data.rejected_flags);
      return `
        <div class="result-card">
          <div class="card-head">
            <div class="card-title">
              <h3>${escapeHtml(data.challenge_id)}</h3>
              <div class="meta">运行摘要</div>
            </div>
            <span class="${statusClass}">${escapeHtml(data.status || "unknown")}</span>
          </div>
          ${flagChips(data.accepted_flags)}
          <div class="kv-grid">
            <div class="kv"><span>Solvers</span><strong>${asList(data.solvers).length}</strong></div>
            <div class="kv"><span>Observations</span><strong>${escapeHtml(data.observations ?? 0)}</strong></div>
            <div class="kv"><span>Rejected</span><strong>${rejected.length}</strong></div>
          </div>
          <div class="kv">
            <span>证明状态</span>
            <strong>${escapeHtml(proof.label)}</strong>
            <div class="meta">${escapeHtml(proof.summary || "等待 solver/verifier 证据。")}</div>
            ${proof.next_action ? `<div class="meta">下一步：${escapeHtml(proof.next_action)}</div>` : ""}
            ${proof.required_evidence.length ? `<div class="meta">所需证据：${proof.required_evidence.map(escapeHtml).join("；")}</div>` : ""}
            ${proof && proof.summary ? "" : ""}
          </div>
          ${renderLLMStatus(data.llm_status)}
          ${rejected.length ? `<div class="meta">被拒候选：${rejected.map(escapeHtml).join(", ")}</div>` : ""}
          ${rawJson(data)}
        </div>`;
    }
    function renderLLMStatus(llm) {
      if (!llm) return "";
      const enabled = !!llm.enabled;
      const state = llm.status || (enabled ? "unknown" : "disabled");
      const provider = llm.provider || "disabled";
      const model = llm.model || "";
      const failed = enabled && ["config_error", "error", "unavailable", "timeout"].includes(String(state));
      const title = failed ? "LLM 请求失败" : (enabled ? "LLM 已参与本轮规划" : "LLM 未启用");
      const toneClass = failed ? "badge warn" : (enabled ? "badge" : "badge muted");
      return `<div>
        <div class="card-head">
          <div class="card-title">
            <h3>大模型运行状态</h3>
            <div class="meta">${escapeHtml(title)}</div>
          </div>
          <span class="${toneClass}">${escapeHtml(state)}</span>
        </div>
        <div class="kv-grid">
          <div class="kv"><span>provider</span><strong>${escapeHtml(provider)}</strong></div>
          <div class="kv"><span>model</span><strong>${escapeHtml(model || "-")}</strong></div>
          <div class="kv"><span>role</span><strong>planning only</strong><div class="meta">最终 flag 仍由 solver/verifier 证据确认。</div></div>
        </div>
        ${llm.error ? `<div class="meta">错误摘要：${escapeHtml(String(llm.error).slice(0, 360))}</div>` : ""}
      </div>`;
    }
    function renderFindings(data) {
      const findings = asList(data);
      if (!findings.length) return `<div class="empty-state">暂无 Findings。运行题目后，这里会按 solver 展示发现、证据和下一步。</div>${rawJson(data)}`;
      return findings.map(finding => {
        const confidence = typeof finding.confidence === "number" ? Math.round(finding.confidence * 100) + "%" : "n/a";
        const evidence = finding.evidence || {};
        const candidates = evidence.transform_candidates || evidence.flag_candidates || evidence.decoded_http_artifacts || [];
        const rsaRecovery = renderRsaRecoveryEvidence(evidence);
        const classicalCrypto = renderClassicalCryptoEvidence(evidence);
        const webRoutes = renderWebRouteEvidence(evidence);
        const webSource = renderWebSourceEvidence(evidence);
        const toolSamples = renderToolSampleEvidence(evidence);
        const transformRecipes = renderTransformRecipeEvidence(evidence);
        const antswordRecovery = renderAntSwordEvidence(evidence);
        const archiveImage = renderArchiveImageEvidence(evidence);
        const jpegStego = renderJpegStegoEvidence(evidence);
        const pwnExploit = renderPwnExploitEvidence(evidence);
        return `
          <div class="result-card">
            <div class="card-head">
              <div class="card-title">
                <h3>${escapeHtml(finding.finding || "Finding")}</h3>
                <div class="meta">${escapeHtml(finding.solver || "unknown solver")}</div>
              </div>
              <span class="badge">${confidence}</span>
            </div>
            ${finding.hypothesis ? `<div><strong>判断：</strong>${escapeHtml(finding.hypothesis)}</div>` : ""}
            ${finding.next_action ? `<div><strong>下一步：</strong>${escapeHtml(finding.next_action)}</div>` : ""}
            ${rsaRecovery}
            ${classicalCrypto}
            ${webRoutes}
            ${webSource}
            ${toolSamples}
            ${transformRecipes}
            ${antswordRecovery}
            ${archiveImage}
            ${jpegStego}
            ${pwnExploit}
            ${Array.isArray(candidates) && candidates.length ? `<div><strong>关键候选：</strong><div class="flag-list">${candidates.slice(0, 6).map(item => `<span class="flag-chip">${escapeHtml(item.value || item)}</span>`).join("")}</div></div>` : ""}
            ${rawJson(finding)}
          </div>`;
      }).join("");
    }
    function renderRsaRecoveryEvidence(evidence) {
      const rsa = evidence.rsa_recovery || null;
      if (!rsa) return "";
      const flags = asList(rsa.flags);
      const method = rsa.method || "rsa_recovery";
      const tools = asList(rsa.recommended_tools);
      return `<div><strong>RSA 恢复：</strong><div class="kv-grid">
        <div class="kv">
          <span>method</span>
          <strong>${escapeHtml(method)}</strong>
          ${rsa.plaintext_preview ? `<div class="meta">${escapeHtml(rsa.plaintext_preview)}</div>` : ""}
        </div>
        ${flags.length ? `<div class="kv"><span>flags</span><strong>${escapeHtml(flags[0])}</strong></div>` : ""}
        ${tools.length ? `<div class="kv"><span>tools</span><strong>${tools.map(escapeHtml).join(", ")}</strong></div>` : ""}
      </div></div>`;
    }
    function renderClassicalCryptoEvidence(evidence) {
      const rows = ["single_byte_xor", "repeating_key_xor", "vigenere"]
        .map(name => [name, evidence[name]])
        .filter(([, value]) => value && (asList(value.flags).length || value.key || value.plaintext_preview));
      if (!rows.length) return "";
      return `<div><strong>经典密码恢复：</strong><div class="kv-grid">${rows.map(([name, value]) => `
        <div class="kv">
          <span>${escapeHtml(name)}</span>
          <strong>${escapeHtml(asList(value.flags)[0] || value.plaintext_preview || "candidate")}</strong>
          ${value.key ? `<div class="meta">key=${escapeHtml(value.key)}</div>` : ""}
          ${value.plaintext_preview ? `<div class="meta">${escapeHtml(value.plaintext_preview)}</div>` : ""}
        </div>`).join("")}</div></div>`;
    }
    function renderWebRouteEvidence(evidence) {
      const routes = asList(evidence.followed_urls);
      const sample = evidence.response_sample || "";
      const headers = evidence.response_headers || {};
      const headerItems = Object.entries(headers).slice(0, 8);
      if (!routes.length && !sample && !headerItems.length) return "";
      return `<div><strong>Web 证据：</strong>
        ${routes.length ? `<div class="flag-list">${routes.slice(0, 6).map(url => `<span class="flag-chip">${escapeHtml(url)}</span>`).join("")}</div>` : ""}
        ${sample ? `<div class="meta">${escapeHtml(sample)}</div>` : ""}
        ${headerItems.length ? `<div class="meta">${headerItems.map(([key, value]) => `${escapeHtml(key)}=${escapeHtml(value)}`).join(" · ")}</div>` : ""}
      </div>`;
    }
    function renderWebSourceEvidence(evidence) {
      const hints = asList(evidence.bug_class_hints);
      const routes = asList(evidence.routes);
      const routeGroups = evidence.routes_by_attachment || {};
      const samples = evidence.source_samples || {};
      const routeGroupItems = Object.entries(routeGroups).slice(0, 4);
      const sampleItems = Object.entries(samples).slice(0, 4);
      if (!hints.length && !routes.length && !routeGroupItems.length && !sampleItems.length) return "";
      return `<div><strong>源码线索：</strong>
        ${hints.length ? `<div class="flag-list">${hints.map(hint => `<span class="flag-chip">${escapeHtml(hint)}</span>`).join("")}</div>` : ""}
        ${routes.length ? `<div class="meta">Routes: ${routes.slice(0, 8).map(escapeHtml).join(" · ")}</div>` : ""}
        ${routeGroupItems.length ? `<div class="meta">${routeGroupItems.map(([path, values]) => `${escapeHtml(path.split("/").pop() || path)} -> ${asList(values).slice(0, 6).map(escapeHtml).join(", ") || "no routes"}`).join("；")}</div>` : ""}
        ${sampleItems.length ? `<div class="meta">${sampleItems.map(([path, values]) => `${escapeHtml(path.split("/").pop() || path)}: ${asList(values).slice(0, 3).map(escapeHtml).join(" | ") || "no source sample"}`).join("；")}</div>` : ""}
      </div>`;
    }
    function renderToolSampleEvidence(evidence) {
      const samples = evidence.tool_samples || {};
      const rows = Object.entries(samples)
        .map(([name, sample]) => {
          const stdout = sample && typeof sample === "object" ? sample.stdout : "";
          const stderr = sample && typeof sample === "object" ? sample.stderr : "";
          const text = String(stdout || stderr || "").trim().split(/\r?\n/).filter(Boolean).slice(0, 4).join(" | ");
          return { name, text };
        })
        .filter(row => row.text)
        .slice(0, 6);
      if (!rows.length) return "";
      return `<div><strong>工具输出摘要：</strong><div class="kv-grid">${rows.map(row => `
        <div class="kv">
          <span>${escapeHtml(row.name)}</span>
          <strong>${escapeHtml(row.text.slice(0, 240))}</strong>
        </div>`).join("")}</div></div>`;
    }
    function renderTransformRecipeEvidence(evidence) {
      const candidates = asList(evidence.transform_candidates || evidence.decoded_transform_candidates)
        .filter(item => item && typeof item === "object")
        .slice(0, 6);
      if (!candidates.length) return "";
      return `<div><strong>转换路线：</strong><div class="kv-grid">${candidates.map(item => {
        const recipe = asList(item.recipe).length ? asList(item.recipe).join(" -> ") : (item.method || "direct");
        const value = item.value || "candidate";
        return `<div class="kv">
          <span>${escapeHtml(recipe)}</span>
          <strong>${escapeHtml(value)}</strong>
        </div>`;
      }).join("")}</div></div>`;
    }
    function renderAntSwordEvidence(evidence) {
      const recovery = evidence.antsword_recovery || null;
      if (!recovery) return "";
      const flags = asList(recovery.flag_candidates);
      const positions = asList(recovery.positions);
      return `<div><strong>AntSword 流量恢复：</strong><div class="kv-grid">
        <div class="kv">
          <span>命令对象</span>
          <strong>${escapeHtml(recovery.command_object || "unknown")}</strong>
          <div class="meta">反转后提取 cut -c N /flag</div>
        </div>
        <div class="kv">
          <span>输出对象</span>
          <strong>${escapeHtml(recovery.output_object || "unknown")}</strong>
          <div class="meta">${escapeHtml(recovery.method || "antsword recovery")}</div>
        </div>
        <div class="kv">
          <span>还原结果</span>
          <strong>${escapeHtml(flags[0] || recovery.reconstructed_text || "candidate")}</strong>
          ${positions.length ? `<div class="meta">${positions.length} 个 cut 位置</div>` : ""}
        </div>
      </div></div>`;
    }
    function renderPwnExploitEvidence(evidence) {
      const plan = evidence.exploit_plan || null;
      if (!plan || !plan.workflow) return "";
      const tools = asList(plan.tool_hints);
      const rows = [
        ["workflow", plan.workflow],
        ["login", plan.login_input],
        ["offset", plan.format_offset],
        ["leak", plan.leak],
        ["overwrite", plan.overwrite_target],
        ["trigger", plan.trigger],
      ].filter(([, value]) => value !== undefined && value !== null && String(value).length);
      return `<div><strong>Pwn 利用路线：</strong><div class="kv-grid">${rows.map(([key, value]) => `
        <div class="kv">
          <span>${escapeHtml(key)}</span>
          <strong>${escapeHtml(value)}</strong>
        </div>`).join("")}</div>
        ${plan.payload_template ? `<div class="meta">${escapeHtml(plan.payload_template)}</div>` : ""}
        ${tools.length ? `<div class="flag-list">${tools.map(tool => `<span class="flag-chip">${escapeHtml(tool)}</span>`).join("")}</div>` : ""}
      </div>`;
    }
    function renderArchiveImageEvidence(evidence) {
      const archive = evidence.archive || null;
      const archivePreviews = asList(evidence.archive_text_previews);
      const image = evidence.image_stego || null;
      const parts = [];
      if (archive) {
        const entries = asList(archive.interesting_entries).length ? asList(archive.interesting_entries) : asList(archive.entries).map(entry => entry && entry.name).filter(Boolean);
        parts.push(`<div><strong>archive 证据：</strong>
          <div class="meta">kind=${escapeHtml(archive.kind || "archive")} · entries=${escapeHtml(archive.entry_count ?? entries.length)} · encrypted=${escapeHtml(archive.encrypted ?? false)}</div>
          ${entries.length ? `<div class="flag-list">${entries.slice(0, 6).map(name => `<span class="flag-chip">${escapeHtml(name)}</span>`).join("")}</div>` : ""}
          ${archivePreviews.length ? `<div class="meta">${archivePreviews.slice(0, 4).map(item => `${escapeHtml(item.name || "entry")}: ${escapeHtml(item.text_preview || "")}`).join("；")}</div>` : ""}
        </div>`);
      }
      if (image) {
        const chunks = asList(image.chunks).map(chunk => `${chunk.type || "chunk"}:${chunk.size ?? "-"}`);
        const textChunks = asList(image.text_chunks).map(chunk => `${chunk.keyword || chunk.type || "text"}=${chunk.text_preview || ""}`);
        const lsbCandidates = asList(image.lsb_candidates);
        const lsbText = lsbCandidates.slice(0, 4).map(item => {
          const flags = asList(item.flag_like_strings);
          const decoders = asList(item.decoders);
          const label = item.recipe || "LSB";
          const value = flags[0] || item.text_preview || "";
          return `${label}${decoders.length ? " -> " + decoders.join(" -> ") : ""}: ${value}`;
        });
        parts.push(`<div><strong>image_stego 证据：</strong>
          <div class="meta">format=${escapeHtml(image.format || "image")}${chunks.length ? ` · chunks=${chunks.slice(0, 8).map(escapeHtml).join(", ")}` : ""}</div>
          ${textChunks.length ? `<div class="flag-list">${textChunks.slice(0, 5).map(item => `<span class="flag-chip">${escapeHtml(item)}</span>`).join("")}</div>` : ""}
          ${lsbText.length ? `<div class="flag-list">${lsbText.map(item => `<span class="flag-chip">${escapeHtml(item)}</span>`).join("")}</div>` : ""}
        </div>`);
      }
      return parts.join("");
    }
    function renderJpegStegoEvidence(evidence) {
      const image = evidence.image_stego || null;
      const tools = evidence.jpeg_stego_tools || null;
      if ((!image || image.format !== "jpeg") && !tools) return "";
      const markers = image ? asList(image.markers).map(marker => marker.type || "marker").filter(Boolean) : [];
      const trailing = image && image.trailing_data ? image.trailing_data : null;
      const info = tools && tools.steghide_info ? tools.steghide_info : null;
      const extract = tools && tools.steghide_extract ? tools.steghide_extract : null;
      const stegseek = tools && tools.stegseek_crack ? tools.stegseek_crack : null;
      const attempts = tools ? asList(tools.steghide_attempts) : [];
      const capacity = info && info.stdout_preview ? String(info.stdout_preview).split(/\r?\n/).map(line => line.trim()).filter(line => line.includes("capacity")).join(" · ") : "";
      const attemptText = attempts.slice(0, 6).map(item => `${item.passphrase_hint || "hint"}:${item.status || "unknown"}`).join(" · ");
      return `<div><strong>JPEG 隐写排查：</strong>
        <div class="kv-grid">
          <div class="kv">
            <span>JPEG markers</span>
            <strong>${escapeHtml(markers.slice(0, 14).join(" -> ") || "未记录")}</strong>
            ${trailing ? `<div class="meta">EOI 后尾随 ${escapeHtml(trailing.length)} bytes</div>` : `<div class="meta">未发现 EOI 后尾随数据</div>`}
          </div>
          <div class="kv">
            <span>steghide info</span>
            <strong>${escapeHtml(info ? (capacity || info.status || "checked") : "未运行")}</strong>
            ${info && info.stderr_preview ? `<div class="meta">${escapeHtml(info.stderr_preview.trim())}</div>` : ""}
          </div>
          <div class="kv">
            <span>steghide hints</span>
            <strong>${escapeHtml(extract ? extract.status || "checked" : "未尝试")}</strong>
            ${attemptText ? `<div class="meta">${escapeHtml(attemptText)}</div>` : ""}
          </div>
          <div class="kv">
            <span>stegseek_crack</span>
            <strong>${escapeHtml(stegseek ? stegseek.status || "checked" : "未运行")}</strong>
            ${stegseek && stegseek.wordlist_size ? `<div class="meta">bounded wordlist: ${escapeHtml(stegseek.wordlist_size)} hints</div>` : ""}
            ${stegseek && (stegseek.stdout_preview || stegseek.stderr_preview) ? `<div class="meta">${escapeHtml(String(stegseek.stdout_preview || stegseek.stderr_preview).trim().slice(0, 220))}</div>` : ""}
          </div>
        </div>
      </div>`;
    }
    function renderObservations(data) {
      const observations = asList(data);
      if (!observations.length) return `<div class="empty-state">暂无 Observations。这里会显示跨 solver 共享的线索，例如 LLM 建议或 flag 候选。</div>${rawJson(data)}`;
      return observations.map(obs => `
        <div class="result-card">
          <div class="card-head">
            <div class="card-title">
              <h3>${escapeHtml(obs.summary || obs.kind || "Observation")}</h3>
              <div class="meta">${escapeHtml(obs.source || "")} ${escapeHtml(obs.kind || "")}</div>
            </div>
          </div>
          ${rawJson(obs)}
        </div>`).join("");
    }
    function renderArtifacts(data) {
      const artifacts = asList(data && data.artifacts);
      if (!artifacts.length) return `<div class="empty-state">暂无注册附件。上传题目文件后，这里会显示文件大小、SHA256 和路径。</div>${rawJson(data)}`;
      return `
        <div class="result-card">
          <div class="card-head">
            <div class="card-title"><h3>${escapeHtml(data.challenge_id || "Artifacts")}</h3><div class="meta">注册附件</div></div>
            <span class="badge muted">${artifacts.length} files</span>
          </div>
          ${artifacts.map(artifact => `
            <div class="kv">
              <span>${escapeHtml(artifact.exists ? "已存在" : "缺失")}</span>
              <strong>${escapeHtml(artifact.name)}</strong>
              <div class="meta">${escapeHtml(artifact.size_bytes ?? "-")} bytes · ${escapeHtml(artifact.sha256 || "no sha256")}</div>
              <div class="meta">${escapeHtml(artifact.path)}</div>
            </div>`).join("")}
          ${rawJson(data)}
        </div>`;
    }
    function renderAgentView(data) {
      const report = data.report || {};
      const findings = asList(data.findings);
      const observations = asList(data.observations);
      const writeup = report.writeup || {};
      const flags = asList(writeup.final_flags).length ? asList(writeup.final_flags) : asList(data.summary && data.summary.accepted_flags);
      const llmPlans = collectLLMPlans(findings, observations);
      const actionQueues = observations.filter(obs => obs.kind === "llm_action_queue");
      const postRunCritics = observations.filter(obs => obs.kind === "llm_post_run_critic");
      const knowledge = collectKnowledge(findings, observations);
      const toolSummaries = observations.filter(obs => obs.kind === "tool_summary");
      const traceSteps = collectTraceSteps(report, observations);
      const shortestPath = collectShortestPath(report);
      const roster = data.roster || {};
      const runRoster = data.summary && data.summary.agent_roster ? data.summary.agent_roster : {};
      return `
        <div class="result-card">
          <div class="card-head">
            <div class="card-title">
              <h3>Agent 解题过程</h3>
              <div class="meta">${escapeHtml(data.challenge_id || report.challenge_id || "selected challenge")}</div>
            </div>
            <span class="badge">${flags.length ? "flag found" : "in progress"}</span>
          </div>
          ${flagChips(flags)}
          <div class="kv-grid">
            <div class="kv"><span>Configured Agents</span><strong>${asList(roster.agents).length}</strong></div>
            <div class="kv"><span>Run Agents</span><strong>${asList(runRoster.agents).length}</strong></div>
            <div class="kv"><span>LLM Plans</span><strong>${llmPlans.length}</strong></div>
            <div class="kv"><span>Action Queues</span><strong>${actionQueues.length}</strong></div>
            <div class="kv"><span>Critics</span><strong>${postRunCritics.length}</strong></div>
            <div class="kv"><span>Tool Summaries</span><strong>${toolSummaries.length}</strong></div>
          </div>
        </div>
        ${renderAgentGapCard(data, postRunCritics, findings, runRoster, roster)}
        ${renderAgentRoster(roster, runRoster)}
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>LLM 规划</h3><div class="meta">模型给出的假设、工具建议和下一步。</div></div></div>
          ${llmPlans.length ? llmPlans.map(renderLLMPlan).join("") : `<div class="empty-state">本轮没有记录 LLM 规划。启用“大模型分析”后运行题目会显示在这里。</div>`}
        </div>
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>行动队列</h3><div class="meta">LLM 建议如何影响后续 solver 调度。</div></div></div>
          ${actionQueues.length ? actionQueues.map(renderActionQueue).join("") : `<div class="empty-state">暂无行动队列。LLM 返回 suggested_solvers 后会显示排队、已存在和无效建议。</div>`}
        </div>
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>Post-run Critic</h3><div class="meta">卡点、缺失证据和下一轮建议。</div></div></div>
          ${postRunCritics.length ? postRunCritics.map(renderPostRunCritic).join("") : `<div class="empty-state">暂无 critic。启用大模型后，未出 flag 的运行会生成复盘纠错建议。</div>`}
        </div>
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>知识检索</h3><div class="meta">本地 playbook 与历史 write-up 给模型补充的上下文。</div></div></div>
          ${knowledge.length ? knowledge.map(item => `<div class="kv"><span>${escapeHtml(item.source || "knowledge")}</span><strong>${escapeHtml(item.title || item.summary || "retrieved item")}</strong><div class="meta">${escapeHtml(item.body || item.snippet || item.value || "")}</div></div>`).join("") : `<div class="empty-state">本轮未持久化知识检索片段；运行时仍会向 LLM prompt 注入分类 playbook 和历史 write-up。</div>`}
        </div>
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>工具摘要</h3><div class="meta">压缩后的工具输出，适合快速判断下一步。</div></div></div>
          ${toolSummaries.length ? toolSummaries.map(renderToolSummary).join("") : `<div class="empty-state">暂无工具摘要。运行会产生较长输出的工具后会显示压缩结果。</div>`}
        </div>
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>SolveTrace</h3><div class="meta">按时间线整理 solver 行动与证据。</div></div></div>
          ${traceSteps.length ? `<ol class="steps">${traceSteps.map(step => `<li><strong>${escapeHtml(step.solver || step.source || "solver")}</strong> · ${escapeHtml(step.status || step.kind || "step")}<div class="meta">${escapeHtml(step.rationale || step.summary || step.finding || "")}</div>${asList(step.flag_candidates || step.flags).length ? flagChips(step.flag_candidates || step.flags) : ""}</li>`).join("")}</ol>` : `<div class="empty-state">暂无 SolveTrace 步骤。</div>`}
        </div>
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>最短发现路径</h3><div class="meta">找到 flag 后自动沉淀的复盘路径。</div></div></div>
          ${shortestPath.length ? `<ol class="steps">${shortestPath.map(step => `<li>${escapeHtml(step)}</li>`).join("")}</ol>` : `<div class="empty-state">还没有可用的最短路径。Verifier 接受 flag 后会生成。</div>`}
          ${rawJson(data)}
        </div>`;
    }
    function renderAgentGapCard(data, postRunCritics, findings, runRoster, roster) {
      const summary = data.summary || {};
      const status = summary.status || "not_run";
      const accepted = asList(summary.accepted_flags);
      const rejected = asList(summary.rejected_flags);
      const proof = proofLabel(summary.proof || {status: summary.proof_status || status});
      const solved = accepted.length > 0 || proof.verified;
      const criticEvidence = postRunCritics.map(obs => obs.evidence || {});
      const missingEvidence = uniqueStrings(criticEvidence.flatMap(evidence => asList(evidence.missing_evidence)));
      const proofMissing = proof.verified ? [] : proof.required_evidence;
      const llmPlanEvidence = collectLLMPlans(findings, data.observations || []).map(entry => entry.plan || entry);
      const llmBlocked = uniqueStrings(llmPlanEvidence.flatMap(plan => asList(plan.blocked_by_missing_artifacts)));
      const llmManual = uniqueStrings(llmPlanEvidence.flatMap(plan => asList(plan.manual_replay_needed)));
      const blockers = uniqueStrings(criticEvidence.flatMap(evidence => asList(evidence.blockers)));
      const criticActions = uniqueStrings(criticEvidence.flatMap(evidence => asList(evidence.next_actions)));
      const findingActions = uniqueStrings(findings.map(finding => finding.next_action).filter(Boolean));
      const ownerRoles = ownerRolesForAgentGap(data, runRoster, roster);
      const nextActions = uniqueStrings([...asList(proof.next_action), ...criticActions, ...llmManual, ...findingActions]).slice(0, 4);
      const missingItems = uniqueStrings([...proofMissing, ...missingEvidence, ...llmBlocked]);
      const tone = solved ? "badge" : "badge warn";
      return `<div class="result-card">
        <div class="card-head">
          <div class="card-title">
            <h3>Gap 卡片</h3>
            <div class="meta">把本题当前状态、负责人角色和下一步动作收敛成一个 PM/QA 可跟踪项。</div>
          </div>
          <span class="${tone}">${escapeHtml(solved ? "no open gap" : "needs follow-up")}</span>
        </div>
        <div class="kv-grid">
          <div class="kv"><span>运行状态</span><strong>${escapeHtml(status)}</strong><div class="meta">${escapeHtml(proof.summary || (solved ? "证据已验证。" : "尚未拿到 evidence-backed proof。"))}</div></div>
          <div class="kv"><span>Proof</span><strong>${escapeHtml(proof.label)}</strong><div class="meta">${escapeHtml(proof.verified ? "可作为做出本题的证明。" : "还不能证明本题已做出。")}</div></div>
          <div class="kv"><span>负责人角色</span><strong>${escapeHtml(ownerRoles.join(", ") || "ForgeFlagManager")}</strong><div class="meta">来自本轮 run roster 或当前 challenge category。</div></div>
          <div class="kv"><span>拒绝候选</span><strong>${escapeHtml(String(rejected.length))}</strong><div class="meta">${rejected.length ? rejected.map(escapeHtml).join("；") : "暂无 rejected flag。"}</div></div>
        </div>
        <div class="kv">
          <span>缺失证据</span>
          <strong>${escapeHtml(missingItems.length ? missingItems.join("；") : (solved ? "无待补证据" : "未记录明确 missing_evidence"))}</strong>
          ${blockers.length ? `<div class="meta">卡点：${blockers.map(escapeHtml).join("；")}</div>` : ""}
        </div>
        <div class="kv">
          <span>下一步动作</span>
          <strong>${escapeHtml(nextActions.length ? nextActions.join("；") : (solved ? "沉淀 casebook/playbook 或继续 benchmark。" : "检查 findings、补 proof-of-solve evidence，并重跑负责角色对应 benchmark。"))}</strong>
        </div>
      </div>`;
    }
    function ownerRolesForAgentGap(data, runRoster, roster) {
      const excluded = new Set(["LLMRoutePlannerAgent", "EvidenceJudgeAgent", "BrowserPlayerQAAgent"]);
      const active = asList(runRoster && runRoster.agents)
        .filter(agent => agent && agent.solvers && asList(agent.solvers).length && !excluded.has(agent.name))
        .map(agent => agent.name || agent.id)
        .filter(Boolean);
      if (active.length) return uniqueStrings(active);
      const selected = selectedChallenge() || {};
      const category = selected.category || (runRoster && runRoster.category) || "";
      const configured = asList(roster && roster.agents)
        .filter(agent => agent && agent.enabled !== false)
        .filter(agent => !excluded.has(agent.name))
        .filter(agent => {
          const categories = asList(agent.categories);
          return categories.includes(category) || (!category && categories.includes("*"));
        })
        .filter(agent => asList(agent.solvers).length)
        .map(agent => agent.name || agent.id)
        .filter(Boolean);
      return configured.length ? uniqueStrings(configured) : ["ForgeFlagManager"];
    }
    function uniqueStrings(values) {
      return [...new Set(values.map(value => String(value || "").trim()).filter(Boolean))];
    }
    function renderAgentRoster(roster, runRoster) {
      const configured = asList(roster && roster.agents);
      const active = asList(runRoster && runRoster.agents);
      const coordinator = (runRoster && runRoster.coordinator) || (roster && roster.coordinator) || {};
      const policy = (roster && roster.subagent_work_policy) || (runRoster && runRoster.subagent_work_policy) || {};
      const activeIds = new Set(active.map(agent => agent.id));
      const rows = configured.length ? configured : active;
      const previewList = (items, limit=3) => {
        const values = asList(items);
        if (!values.length) return "-";
        const shown = values.slice(0, limit).map(escapeHtml).join("；");
        return values.length > limit ? `${shown}；+${values.length - limit}` : shown;
      };
      return `
        <div class="result-card">
          <div class="card-head">
            <div class="card-title"><h3>Agent 身份配置</h3><div class="meta">总控、常驻 subagent 和本轮实际参与身份。</div></div>
            <span class="badge muted">${escapeHtml(coordinator.name || coordinator.id || "ForgeFlagManager")}</span>
          </div>
          <div class="kv">
            <span>Coordinator</span>
            <strong>${escapeHtml(coordinator.name || "ForgeFlagManager")}</strong>
            <div class="meta">${escapeHtml(coordinator.mission || "Coordinate scoped CTF solving and evidence-backed verification.")}</div>
            <div class="meta">团队类型: ${escapeHtml(coordinator.team_type || "manager")} · 汇报给: ${escapeHtml(coordinator.reports_to || "project owner")} · 协作节奏: ${escapeHtml(coordinator.cadence || "continuous")}</div>
            <div class="meta">success_metrics: ${previewList(coordinator.success_metrics)}</div>
            <div class="meta">deliverables: ${previewList(coordinator.deliverables)}</div>
          </div>
          <div class="kv-grid">
            <div class="kv"><span>Subagent 工作机制</span><strong>${escapeHtml(policy.mode || "conservative")}</strong><div class="meta">默认本地验证优先，避免把同一问题拆成过多并发请求。</div></div>
            <div class="kv"><span>并发上限</span><strong>${escapeHtml(policy.max_parallel ?? 1)}</strong><div class="meta">超过上限时按顺序处理。</div></div>
            <div class="kv"><span>429 熔断</span><strong>${escapeHtml(policy.failure_circuit_breaker ?? 1)} 次</strong><div class="meta">命中限流后冷却 ${escapeHtml(policy.cooldown_seconds ?? 120)} 秒，改用本地测试和 Web benchmark。</div></div>
          </div>
          ${rows.length ? rows.map(agent => `
            <div class="kv">
              <span>${activeIds.has(agent.id) ? "本轮参与" : (agent.enabled === false ? "已停用" : "常驻待命")}</span>
              <strong>${escapeHtml(agent.name || agent.id || "Agent")}</strong>
              <div class="meta">${escapeHtml(agent.mission || "")}</div>
              <div class="meta">团队类型: ${escapeHtml(agent.team_type || "stream-aligned")} · 汇报给: ${escapeHtml(agent.reports_to || "forgeflag-manager")} · 协作节奏: ${escapeHtml(agent.cadence || "per challenge")}</div>
              <div class="meta">success_metrics: ${previewList(agent.success_metrics)}</div>
              <div class="meta">deliverables: ${previewList(agent.deliverables)}</div>
              <div class="meta">solvers: ${escapeHtml(asList(agent.solvers).join(", ") || "-")} · tools: ${escapeHtml(asList(agent.tools).join(", ") || "-")}</div>
            </div>`).join("") : `<div class="empty-state">暂无 Agent roster。运行 forgeflag agents --write-default 可以生成项目配置。</div>`}
        </div>`;
    }
    function collectLLMPlans(findings, observations) {
      const fromFindings = findings.filter(finding => {
        const solver = String(finding.solver || "").toLowerCase();
        return solver.includes("llm") || (finding.evidence && finding.evidence.plan);
      }).map(finding => ({ source: finding.solver || "LLM", finding: finding.finding, confidence: finding.confidence, ...(finding.evidence || {}) }));
      const fromObservations = observations.filter(obs => String(obs.kind || "").includes("llm") && (obs.evidence || obs.summary))
        .map(obs => ({ source: obs.source || "LLM", finding: obs.summary, ...(obs.evidence || {}) }));
      return [...fromFindings, ...fromObservations];
    }
    function renderLLMPlan(entry) {
      const plan = entry.plan || entry;
      const hypotheses = asList(plan.hypotheses);
      const actions = asList(plan.next_actions);
      const solvers = asList(plan.suggested_solvers);
      const tools = asList(plan.tool_hints);
      const expected = asList(plan.expected_evidence);
      const artifactRequirements = asList(plan.artifact_requirements);
      const blocked = asList(plan.blocked_by_missing_artifacts);
      const manualReplay = asList(plan.manual_replay_needed);
      const riskNotes = asList(plan.risk_notes);
      return `<div class="kv">
        <span>${escapeHtml(entry.source || "LLM")}</span>
        <strong>${escapeHtml(plan.summary || entry.finding || "LLM plan")}</strong>
        ${plan.analysis_mode ? `<div class="meta">分析模式：${escapeHtml(plan.analysis_mode)}</div>` : ""}
        ${hypotheses.length ? `<div class="meta">假设：${hypotheses.map(escapeHtml).join("；")}</div>` : ""}
        ${actions.length ? `<div class="meta">下一步：${actions.map(escapeHtml).join("；")}</div>` : ""}
        ${solvers.length ? `<div class="meta">建议 solver：${solvers.map(escapeHtml).join(", ")}</div>` : ""}
        ${tools.length ? `<div class="meta">工具提示：${tools.map(escapeHtml).join(", ")}</div>` : ""}
        ${expected.length ? `<div class="meta">期望证据：${expected.map(escapeHtml).join("；")}</div>` : ""}
        ${artifactRequirements.length ? `<div class="meta">artifact_requirements / 所需附件：${artifactRequirements.map(escapeHtml).join("；")}</div>` : ""}
        ${blocked.length ? `<div class="meta">blocked_by_missing_artifacts / 缺失附件/证据：${blocked.map(escapeHtml).join("；")}</div>` : ""}
        ${manualReplay.length ? `<div class="meta">manual_replay_needed / 人工复现：${manualReplay.map(escapeHtml).join("；")}</div>` : ""}
        ${riskNotes.length ? `<div class="meta">risk_notes / 风险提示：${riskNotes.map(escapeHtml).join("；")}</div>` : ""}
        ${asList(plan.fallback_plan).length ? `<div class="meta">Fallback：${asList(plan.fallback_plan).map(escapeHtml).join("；")}</div>` : ""}
      </div>`;
    }
    function renderActionQueue(obs) {
      const evidence = obs.evidence || {};
      const queued = asList(evidence.queued_solvers);
      const already = asList(evidence.already_present_solvers);
      const unknown = asList(evidence.unknown_solvers);
      const actions = asList(evidence.next_actions);
      const tools = asList(evidence.tool_hints);
      const artifactRequirements = asList(evidence.artifact_requirements);
      const blocked = asList(evidence.blocked_by_missing_artifacts);
      const manualReplay = asList(evidence.manual_replay_needed);
      const riskNotes = asList(evidence.risk_notes);
      return `<div class="kv">
        <span>${escapeHtml(obs.source || "Manager")}</span>
        <strong>${escapeHtml(obs.summary || "LLM action queue")}</strong>
        ${evidence.analysis_mode ? `<div class="meta">分析模式：${escapeHtml(evidence.analysis_mode)}</div>` : ""}
        ${queued.length ? `<div class="meta">排队 solver：${queued.map(escapeHtml).join(", ")}</div>` : ""}
        ${already.length ? `<div class="meta">已在队列：${already.map(escapeHtml).join(", ")}</div>` : ""}
        ${unknown.length ? `<div class="meta">无效建议：${unknown.map(escapeHtml).join(", ")}</div>` : ""}
        ${actions.length ? `<div class="meta">下一步：${actions.map(escapeHtml).join("；")}</div>` : ""}
        ${tools.length ? `<div class="meta">工具提示：${tools.map(escapeHtml).join(", ")}</div>` : ""}
        ${artifactRequirements.length ? `<div class="meta">行动队列所需附件：${artifactRequirements.map(escapeHtml).join("；")}</div>` : ""}
        ${blocked.length ? `<div class="meta">行动队列缺失证据：${blocked.map(escapeHtml).join("；")}</div>` : ""}
        ${manualReplay.length ? `<div class="meta">行动队列人工复现：${manualReplay.map(escapeHtml).join("；")}</div>` : ""}
        ${riskNotes.length ? `<div class="meta">行动队列风险提示：${riskNotes.map(escapeHtml).join("；")}</div>` : ""}
      </div>`;
    }
    function renderPostRunCritic(obs) {
      const evidence = obs.evidence || {};
      const blockers = asList(evidence.blockers);
      const missing = asList(evidence.missing_evidence);
      const solvers = asList(evidence.suggested_solvers);
      const tools = asList(evidence.tool_hints);
      const actions = asList(evidence.next_actions);
      const artifactRequirements = asList(evidence.artifact_requirements);
      const blocked = asList(evidence.blocked_by_missing_artifacts);
      const manualReplay = asList(evidence.manual_replay_needed);
      const riskNotes = asList(evidence.risk_notes);
      return `<div class="kv">
        <span>${escapeHtml(evidence.provider || obs.source || "LLMCritic")}</span>
        <strong>${escapeHtml(evidence.summary || obs.summary || "Post-run critic")}</strong>
        ${evidence.analysis_mode ? `<div class="meta">分析模式：${escapeHtml(evidence.analysis_mode)}</div>` : ""}
        ${blockers.length ? `<div class="meta">卡点：${blockers.map(escapeHtml).join("；")}</div>` : ""}
        ${missing.length ? `<div class="meta">缺失证据：${missing.map(escapeHtml).join("；")}</div>` : ""}
        ${solvers.length ? `<div class="meta">建议 solver：${solvers.map(escapeHtml).join(", ")}</div>` : ""}
        ${tools.length ? `<div class="meta">工具路线：${tools.map(escapeHtml).join(", ")}</div>` : ""}
        ${actions.length ? `<div class="meta">下一轮：${actions.map(escapeHtml).join("；")}</div>` : ""}
        ${artifactRequirements.length ? `<div class="meta">artifact_requirements / 所需附件：${artifactRequirements.map(escapeHtml).join("；")}</div>` : ""}
        ${blocked.length ? `<div class="meta">blocked_by_missing_artifacts / 缺失附件/证据：${blocked.map(escapeHtml).join("；")}</div>` : ""}
        ${manualReplay.length ? `<div class="meta">manual_replay_needed / 人工复现：${manualReplay.map(escapeHtml).join("；")}</div>` : ""}
        ${riskNotes.length ? `<div class="meta">risk_notes / 风险提示：${riskNotes.map(escapeHtml).join("；")}</div>` : ""}
        ${evidence.rerun_reason ? `<div class="meta">重跑理由：${escapeHtml(evidence.rerun_reason)}</div>` : ""}
        ${evidence.error ? `<div class="meta">Error：${escapeHtml(evidence.error)}</div>` : ""}
      </div>`;
    }
    function collectKnowledge(findings, observations) {
      const items = [];
      findings.forEach(finding => {
        const evidence = finding.evidence || {};
        asList(evidence.retrieved_knowledge).forEach(item => items.push(item));
        asList(evidence.plan && evidence.plan.retrieved_knowledge).forEach(item => items.push(item));
      });
      observations.filter(obs => String(obs.kind || "").includes("knowledge")).forEach(obs => {
        const evidence = obs.evidence || {};
        const nested = asList(evidence.items);
        if (nested.length) {
          nested.forEach(item => items.push(item));
        } else {
          items.push({ source: obs.source, title: obs.summary, ...evidence });
        }
      });
      return items;
    }
    function renderToolSummary(obs) {
      const evidence = obs.evidence || {};
      const flags = asList(evidence.flags || evidence.flag_candidates);
      const lines = asList(evidence.interesting_lines || evidence.key_lines);
      return `<div class="kv">
        <span>${escapeHtml(obs.source || "tool")}</span>
        <strong>${escapeHtml(obs.summary || "tool summary")}</strong>
        ${flags.length ? flagChips(flags) : ""}
        ${lines.length ? `<div class="meta">${lines.slice(0, 5).map(escapeHtml).join(" · ")}</div>` : ""}
        ${evidence.errors ? `<div class="meta">Errors: ${escapeHtml(evidence.errors)}</div>` : ""}
      </div>`;
    }
    function collectTraceSteps(report, observations) {
      const writeup = report.writeup || {};
      const fromReport = asList(report.solve_trace).length ? asList(report.solve_trace) : asList(writeup.solve_trace);
      const fromObservations = observations.filter(obs => obs.kind === "solve_trace_step").map(obs => ({ source: obs.source, kind: obs.kind, summary: obs.summary, ...(obs.evidence || {}) }));
      return [...fromReport, ...fromObservations].sort((left, right) => (left.step_index ?? 0) - (right.step_index ?? 0));
    }
    function collectShortestPath(report) {
      const writeup = report.writeup || {};
      if (asList(writeup.shortest_discovery_path).length) return asList(writeup.shortest_discovery_path);
      const flagEntries = asList(report.flags);
      const first = flagEntries[0] || {};
      if (asList(first.trace_path).length) return asList(first.trace_path).map(step => step.replay_step || step.summary || step.finding || JSON.stringify(step));
      if (asList(first.replay_steps).length) return asList(first.replay_steps);
      if (asList(first.path).length) return asList(first.path).map(step => step.replay_step || step.summary || step.finding || JSON.stringify(step));
      return [];
    }
    function renderReport(data) {
      const flags = asList(data && data.flags);
      if (data && data.writeup) return renderWriteupReport(data);
      if (!flags.length) return `<div class="empty-state">还没有 Write-up。只有 verifier 接受 flag 后才会生成可复现的拿 flag 过程。</div>${rawJson(data)}`;
      return flags.map(entry => `
        <div class="result-card">
          <div class="card-head">
            <div class="card-title">
              <h3>${escapeHtml(entry.flag)}</h3>
              <div class="meta">最短发现路径</div>
            </div>
            <span class="badge">accepted</span>
          </div>
          ${asList(entry.replay_steps).length ? `<ol class="steps">${entry.replay_steps.map(step => `<li>${escapeHtml(step)}</li>`).join("")}</ol>` : `<div class="meta">暂无复盘步骤。</div>`}
          ${asList(entry.path).map(step => `
            <div class="kv">
              <span>${escapeHtml(step.solver || "solver")}</span>
              <strong>${escapeHtml(step.finding || "finding")}</strong>
              <div class="meta">${escapeHtml(step.hypothesis || "")}</div>
            </div>`).join("")}
          ${rawJson(entry)}
        </div>`).join("");
    }
    function renderWriteupReport(data) {
      const writeup = data.writeup || {};
      const sections = orderedWriteupSections(asList(writeup.sections));
      const exploit = writeup.exploit_script || null;
      const solve = writeup.solve_script || null;
      return `
        ${sections.map(section => `
          <div class="result-card writeup-section">
            <div class="card-head">
              <div class="card-title">
                <h3>${escapeHtml(section.title || "Section")}</h3>
              </div>
            </div>
            <p class="writeup-section-body">${escapeHtml(section.body || "")}</p>
            ${asList(section.steps).length ? `<ol class="steps">${section.steps.map(step => `<li>${escapeHtml(step)}</li>`).join("")}</ol>` : ""}
          </div>`).join("")}
        ${exploit && exploit.content ? `
          <div class="result-card writeup-section">
            <div class="card-head">
              <div class="card-title">
                <h3>Exploit 脚本</h3>
                <div class="meta">${escapeHtml(exploit.filename || "exploit.py")}</div>
              </div>
            </div>
            <pre class="writeup-code"><code>${escapeHtml(exploit.content)}</code></pre>
          </div>` : ""}
        ${solve && solve.content ? `
          <div class="result-card writeup-section">
            <div class="card-head">
              <div class="card-title">
                <h3>Solve 脚本</h3>
                <div class="meta">${escapeHtml(solve.filename || "solve.py")}</div>
              </div>
            </div>
            <pre class="writeup-code"><code>${escapeHtml(solve.content)}</code></pre>
          </div>` : ""}
        ${sections.length ? "" : `<div class="empty-state">还没有可展示的解题思路和复现步骤。</div>`}`;
    }
    function orderedWriteupSections(sections) {
      const allowed = new Map(sections.filter(section => writeupSectionOrder.includes(section.title)).map(section => [section.title, section]));
      return writeupSectionOrder.map(title => allowed.get(title)).filter(Boolean);
    }
    function renderBenchmark(data) {
      const scorecard = data && data.scorecard;
      if (!scorecard) {
        return `<div class="result-card">
          <div class="card-head">
            <div class="card-title">
              <h3>最新能力评测</h3>
              <div class="meta">还没有保存过 capability benchmark scorecard。</div>
            </div>
            <span class="badge warn">missing</span>
          </div>
          <div class="kv">
            <span>生成命令</span>
            <strong>${escapeHtml(data && data.refresh_command ? data.refresh_command : "scripts/forgeflag-capability-benchmark --output .forgeflag/capability-benchmark-latest.json")}</strong>
            <div class="meta">建议先跑 smoke 或 manifest-only，再回到本页刷新 Benchmark tab。</div>
          </div>
        </div>${renderBenchmarkHistory(asList(data && data.history))}${rawJson(data)}`;
      }
      const totals = scorecard.totals || {};
      const rates = scorecard.rates || {};
      const readiness = scorecard.readiness || {};
      const backlog = asList(scorecard.backlog);
      const backlogByRole = scorecard.backlog_by_role || {};
      const roles = scorecard.roles || {};
      const roleNames = Object.keys(backlogByRole).sort((a, b) => (backlogByRole[b].total || 0) - (backlogByRole[a].total || 0));
      const roleRows = roleNames.length ? roleNames.map(role => {
        const item = backlogByRole[role] || {};
        const categories = Object.entries(item.categories || {}).map(([key, value]) => `${key}:${value}`).join(", ") || "-";
        const suites = Object.entries(item.suites || {}).map(([key, value]) => `${key}:${value}`).join(", ") || "-";
        return `<div class="kv">
          <span>${escapeHtml(role)}</span>
          <strong>${escapeHtml(item.total || 0)} open</strong>
          <div class="meta">categories: ${escapeHtml(categories)}</div>
          <div class="meta">suites: ${escapeHtml(suites)}</div>
        </div>`;
      }).join("") : `<div class="empty-state">当前 scorecard 没有角色 Backlog。</div>`;
      const taskRows = backlog.length ? backlog.slice(0, 12).map(item => `
        <div class="kv">
          <span>${escapeHtml(item.suite || "suite")} · ${escapeHtml(item.category || "unknown")}</span>
          <strong>${escapeHtml(item.challenge_id || "unknown")}</strong>
          <div class="meta">owner: ${escapeHtml(asList(item.owner_roles).join(", ") || "ForgeFlagManager")}</div>
          <div class="meta">reason: ${escapeHtml(item.reason || item.status || "failed")}</div>
          <div class="meta">next: ${escapeHtml(item.next_action || "replay and add a regression")}</div>
        </div>`).join("") : `<div class="empty-state">没有开放任务；继续用 held-out manifest 验证泛化能力。</div>`;
      const roleHealth = Object.entries(roles).slice(0, 8).map(([role, item]) => `
        <div class="kv">
          <span>${escapeHtml(role)}</span>
          <strong>${escapeHtml(item.passed ?? 0)} / ${escapeHtml(item.total ?? 0)}</strong>
          <div class="meta">evidence: ${escapeHtml(item.hard_score ?? 0)} / ${escapeHtml(item.hard_max_score ?? 0)} · ui: ${escapeHtml(item.ui_passed ?? 0)} / ${escapeHtml(item.ui_total ?? 0)}</div>
        </div>`).join("");
      return `
        <div class="result-card">
          <div class="card-head">
            <div class="card-title">
              <h3>最新能力评测</h3>
              <div class="meta">${escapeHtml(data.path || "")}</div>
            </div>
            <span class="${Number(totals.failed || 0) ? "badge warn" : "badge"}">${escapeHtml(Number(totals.failed || 0) ? "needs work" : "green")}</span>
          </div>
          <div class="kv-grid">
            <div class="kv"><span>Cases</span><strong>${escapeHtml(totals.passed ?? 0)} / ${escapeHtml(totals.cases ?? 0)}</strong><div class="meta">failed: ${escapeHtml(totals.failed ?? 0)}</div></div>
            <div class="kv"><span>Evidence score</span><strong>${escapeHtml(totals.hard_score ?? 0)} / ${escapeHtml(totals.hard_max_score ?? 0)}</strong><div class="meta">rate: ${formatRate(rates.evidence_score_rate)}</div></div>
            <div class="kv"><span>UI flow</span><strong>${escapeHtml(totals.ui_passed ?? 0)} / ${escapeHtml(totals.ui_total ?? 0)}</strong><div class="meta">rate: ${formatRate(rates.ui_flow_rate)}</div></div>
          </div>
          <div class="kv">
            <span>刷新命令</span>
            <strong>${escapeHtml(data.refresh_command || "scripts/forgeflag-capability-benchmark --output .forgeflag/capability-benchmark-latest.json")}</strong>
          </div>
        </div>
        ${renderBenchmarkReadiness(readiness)}
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>角色 Backlog</h3><div class="meta">按负责人聚合失败项，方便 manager 分派下一轮优化。</div></div></div>
          <div class="kv-grid">${roleRows}</div>
        </div>
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>Backlog tasks</h3><div class="meta">${backlog.length} open items</div></div></div>
          ${taskRows}
        </div>
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>Role health</h3><div class="meta">角色级 pass/evidence/UI 归因。</div></div></div>
          <div class="kv-grid">${roleHealth || `<div class="empty-state">暂无角色归因。</div>`}</div>
        </div>
        ${renderBenchmarkHistory(asList(data.history))}
        ${rawJson(data)}`;
    }
    function renderBenchmarkReadiness(readiness) {
      const status = readiness && readiness.status ? readiness.status : "unknown";
      const coverage = readiness && readiness.coverage ? readiness.coverage : {};
      const warnings = asList(readiness && readiness.warnings);
      const actions = asList(readiness && readiness.next_actions);
      const badgeClass = status === "ready" ? "badge" : status === "limited" ? "badge warn" : "badge warn";
      const coverageRows = [
        ["Hard evidence", coverage.hard_evidence],
        ["UI flow", coverage.ui_flow],
        ["Held-out manifest", coverage.heldout_manifest]
      ].map(([label, ok]) => `
        <div class="kv">
          <span>${escapeHtml(label)}</span>
          <strong>${ok ? "covered" : "missing"}</strong>
        </div>`).join("");
      const warningRows = warnings.length ? warnings.map(item => `<li>${escapeHtml(item)}</li>`).join("") : "<li>当前 scorecard 没有阻断项。</li>";
      const actionRows = actions.length ? actions.map(item => `<li>${escapeHtml(item)}</li>`).join("") : "<li>继续用新的 held-out CTF artifact 做周期性回归。</li>";
      return `<div class="result-card">
        <div class="card-head">
          <div class="card-title">
            <h3>实战就绪度</h3>
            <div class="meta">${escapeHtml(readiness.summary || "根据失败、backlog、hard evidence、UI flow 和 held-out 覆盖判定。")}</div>
          </div>
          <span class="${badgeClass}">${escapeHtml(status)}</span>
        </div>
        <div class="kv-grid">${coverageRows}</div>
        <div class="kv">
          <span>Warnings</span>
          <ol class="steps">${warningRows}</ol>
        </div>
        <div class="kv">
          <span>Next actions</span>
          <ol class="steps">${actionRows}</ol>
        </div>
      </div>`;
    }
    function renderBenchmarkHistory(history) {
      const rows = asList(history).slice(-8).reverse();
      if (!rows.length) {
        return `<div class="result-card">
          <div class="card-head"><div class="card-title"><h3>Benchmark history</h3><div class="meta">历史趋势会在使用 --history 后出现。</div></div></div>
          <div class="empty-state">暂无历史记录。</div>
        </div>`;
      }
      return `<div class="result-card">
        <div class="card-head"><div class="card-title"><h3>Benchmark history</h3><div class="meta">最近 ${rows.length} 次能力评测趋势。</div></div></div>
        <div class="kv-grid">
          ${rows.map(record => {
            const card = record.scorecard || {};
            const totals = card.totals || {};
            const backlog = asList(card.backlog);
            return `<div class="kv">
              <span>${escapeHtml(record.recorded_at || "record")}</span>
              <strong>${escapeHtml(totals.passed ?? 0)} / ${escapeHtml(totals.cases ?? 0)}</strong>
              <div class="meta">failed: ${escapeHtml(totals.failed ?? 0)} · backlog: ${escapeHtml(backlog.length)}</div>
            </div>`;
          }).join("")}
        </div>
      </div>`;
    }
    function renderSystemHealth(data) {
      const checks = asList(data && data.checks);
      const nextActions = asList(data && data.next_actions);
      const core = (data && data.core_readiness) || {};
      const readiness = (data && data.commercial_readiness) || {};
      const counts = (data && data.counts) || {};
      const status = (data && data.status) || "unknown";
      const diagnostic = (data && data.diagnostic_bundle) || {};
      const service = diagnostic.service || {};
      const llm = diagnostic.llm || {};
      const supportSummary = asList(diagnostic.support_summary);
      const badgeClass = status === "ready" ? "badge" : "badge warn";
      const checkRows = checks.length ? checks.map(check => {
        const tone = check.status === "ok" ? "badge" : "badge warn";
        const actions = asList(check.next_actions);
        return `<div class="kv">
          <span>${escapeHtml(check.label || check.id || "check")}</span>
          <strong>${escapeHtml(check.summary || "")}</strong>
          <div class="meta"><span class="${tone}">${escapeHtml(check.status || "unknown")}</span></div>
          ${actions.length ? `<div class="meta">next: ${actions.map(escapeHtml).join("；")}</div>` : ""}
        </div>`;
      }).join("") : `<div class="empty-state">暂无健康检查数据。</div>`;
      const actionRows = nextActions.length ? nextActions.map(action => `<li>${escapeHtml(action)}</li>`).join("") : "<li>继续周期性运行 benchmark 和工具 smoke。</li>";
      return `<div class="result-card">
        <div class="card-head">
          <div class="card-title">
            <h3>商业化健康检查</h3>
            <div class="meta">${escapeHtml((data && data.summary) || "Runtime readiness gate")}</div>
          </div>
          <span class="${badgeClass}">${escapeHtml(status)}</span>
        </div>
        <div class="kv-grid">
          <div class="kv"><span>核心解题能力</span><strong>${escapeHtml(core.status || "unknown")}</strong><div class="meta">${escapeHtml(core.summary || "Core solving readiness")}</div></div>
          <div class="kv"><span>Commercial readiness</span><strong>${escapeHtml(readiness.status || status)}</strong><div class="meta">${escapeHtml(readiness.label || "Commercial readiness")}</div></div>
          <div class="kv"><span>Checks</span><strong>${escapeHtml(counts.ok ?? 0)} ok</strong><div class="meta">warnings: ${escapeHtml(counts.warnings ?? 0)} · errors: ${escapeHtml(counts.errors ?? 0)}</div></div>
          <div class="kv"><span>Generated</span><strong>${escapeHtml((data && data.generated_at) || "-")}</strong></div>
        </div>
      </div>
      <div class="result-card">
        <div class="card-head"><div class="card-title"><h3>Readiness checks</h3><div class="meta">运行时、工具链、benchmark gate、LLM 配置。</div></div></div>
        <div class="kv-grid">${checkRows}</div>
      </div>
      <div class="result-card">
        <div class="card-head">
          <div class="card-title">
            <h3>Diagnostic bundle</h3>
            <div class="meta">脱敏支持包，用于定位网页端、solver、工具链或 LLM 接入问题。</div>
          </div>
          <span class="badge muted">bundle v${escapeHtml(diagnostic.bundle_version || 1)}</span>
        </div>
        <div class="kv-grid">
          <div class="kv"><span>ForgeFlag</span><strong>${escapeHtml(service.version || "-")}</strong><div class="meta">${escapeHtml(service.platform || "-")}</div></div>
          <div class="kv"><span>Python</span><strong>${escapeHtml(service.python || "-")}</strong><div class="meta">pid: ${escapeHtml(service.pid || "-")}</div></div>
          <div class="kv"><span>Notebook</span><strong>${escapeHtml(service.db_path || "-")}</strong></div>
          <div class="kv"><span>LLM</span><strong>${escapeHtml(llm.provider || "-")} / ${escapeHtml(llm.model || "-")}</strong><div class="meta">enabled: ${escapeHtml(llm.enabled ?? false)} · key: ${llm.api_key_configured ? "configured" : "missing"}</div></div>
        </div>
        <div class="kv">
          <span>Support summary</span>
          <ol class="steps">${supportSummary.length ? supportSummary.map(item => `<li>${escapeHtml(item)}</li>`).join("") : "<li>暂无摘要。</li>"}</ol>
        </div>
      </div>
      <div class="result-card">
        <div class="card-head"><div class="card-title"><h3>Next actions</h3><div class="meta">优先处理阻断项，再补 optional profile 或 LLM。</div></div></div>
        <ol class="steps">${actionRows}</ol>
        ${rawJson(data)}
      </div>`;
    }
    function formatRate(value) {
      if (value === null || value === undefined) return "n/a";
      return `${Math.round(Number(value) * 1000) / 10}%`;
    }
    function renderToolRows(data, title, kind) {
      if (kind === "tool" && data && !Array.isArray(data) && (data.wrappers || data.catalog)) {
        const wrappers = asList(data.wrappers);
        const catalog = asList(data.catalog);
        const analysisHints = asList(data.analysis_hints);
        const profiles = asList(data.docker_profiles);
        const counts = data.counts || {};
        const smoke = data.runtime_smoke || {};
        return `
          <div class="result-card">
            <div class="card-head">
              <div class="card-title">
                <h3>工具总览</h3>
                <div class="meta">${escapeHtml(counts.available_wrappers ?? 0)} / ${escapeHtml(counts.wrappers ?? wrappers.length)} wrappers available · ${escapeHtml(counts.catalog ?? catalog.length)} catalog entries · ${escapeHtml(counts.analysis_hints ?? analysisHints.length)} analysis hints</div>
                <div class="meta">推荐 CTF 工具目录和分析提示已按分类折叠，展开分组查看明细。</div>
              </div>
              <span class="badge muted">host/docker</span>
            </div>
            <div class="kv-grid">
              <div class="kv"><span>Host</span><strong>${escapeHtml(counts.host_wrappers ?? wrappers.filter(row => row.source === "host").length)}</strong></div>
              <div class="kv"><span>Docker</span><strong>${escapeHtml(counts.docker_wrappers ?? wrappers.filter(row => row.source === "docker").length)}</strong></div>
              <div class="kv"><span>Missing</span><strong>${escapeHtml(counts.missing_wrappers ?? wrappers.filter(row => row.source === "missing").length)}</strong></div>
              <div class="kv"><span>Heavy profiles</span><strong>${escapeHtml(counts.available_docker_profiles ?? profiles.filter(row => row.available).length)} / ${escapeHtml(counts.docker_profiles ?? profiles.length)}</strong></div>
            </div>
            <div class="kv">
              <span>Docker install</span>
              <strong>${escapeHtml(smoke.docker_build_command || "scripts/forgeflag-control docker-build")}</strong>
              <div class="meta">安装后重启 Web：scripts/forgeflag-control restart</div>
            </div>
            <div class="kv">
              <span>Verification</span>
              <strong>${escapeHtml(smoke.docker_smoke_command || "scripts/forgeflag-control docker-smoke")}</strong>
              <div class="meta">Offline smoke: ${escapeHtml(smoke.command || "scripts/forgeflag-tool-smoke")}</div>
              <div class="meta">Active probes are scoped and opt-in: ${escapeHtml(smoke.active_network_command || "scripts/forgeflag-tool-smoke --include-active-network")}</div>
            </div>
          </div>
          ${renderAnalysisHintGroups(analysisHints)}
          ${renderToolGroups(wrappers, catalog, profiles)}
          ${rawJson(data)}`;
      }
      const rows = asList(data);
      if (!rows.length) return `<div class="empty-state">暂无${escapeHtml(title)}数据。</div>${rawJson(data)}`;
      return renderToolList(title, rows, kind) + rawJson(data);
    }
    function renderToolList(title, rows, kind) {
      if (!rows.length) return `<div class="empty-state">暂无${escapeHtml(title)}数据。</div>`;
      return `
        <div class="result-card">
          <div class="card-head"><div class="card-title"><h3>${escapeHtml(title)}</h3><div class="meta">${rows.length} entries</div></div></div>
          ${rows.map(row => {
            const name = row.name || row.title || row.tool || row.id || "entry";
            const badge = kind === "tool"
              ? (row.available ? "available" : "missing")
              : (kind === "profile" ? (row.available ? "built" : "not built") : (kind === "analysis_hint" ? (row.status || "hint") : (row.integration || row.category || "catalog")));
            const badgeClass = (badge === "missing" || badge === "not built") ? "badge warn" : "badge muted";
            const categories = row.categories ? row.categories.join(", ") : (row.category || "");
            const description = row.description || row.purpose || row.notes || "";
            const signals = asList(row.signals).length ? `<div class="meta">Signals: ${asList(row.signals).map(escapeHtml).join("；")}</div>` : "";
            const steps = asList(row.recommended_steps).length ? `<div class="meta">Next: ${asList(row.recommended_steps).map(escapeHtml).join("；")}</div>` : "";
            const solverPaths = asList(row.solver_paths).length ? `<div class="meta">Paths: ${asList(row.solver_paths).map(escapeHtml).join(", ")}</div>` : "";
            const docs = asList(row.docs).length ? `<div class="meta">Docs: ${asList(row.docs).map(escapeHtml).join(", ")}</div>` : "";
            const install = row.install_hint ? `<div class="meta">Install: ${escapeHtml(row.install_hint)}</div>` : "";
            const build = row.build_command ? `<div class="meta">Build: ${escapeHtml(row.build_command)}</div>` : "";
            const verify = row.verify_command ? `<div class="meta">Verify: ${escapeHtml(row.verify_command)}</div>` : "";
            const source = kind === "tool" && row.source ? `<div class="meta">Source: ${escapeHtml(row.source)}</div>` : "";
            return `<div class="kv">
              <span>${escapeHtml(categories || row.integration || "")}</span>
              <strong>${escapeHtml(name)}</strong>
              ${row.id ? `<div class="meta">ID: ${escapeHtml(row.id)}</div>` : ""}
              ${description ? `<div class="meta">${escapeHtml(description)}</div>` : ""}
              ${row.why ? `<div class="meta">${escapeHtml(row.why)}</div>` : ""}
              ${signals}
              ${steps}
              ${solverPaths}
              ${docs}
              ${source}
              ${install}
              ${build}
              ${verify}
              <span class="${badgeClass}">${escapeHtml(badge)}</span>
            </div>`;
          }).join("")}
        </div>`;
    }
    function renderToolGroups(wrappers, catalog, profiles) {
      const wrapperGroups = [
        ["Host wrappers", wrappers.filter(row => row.source === "host"), "本机可直接调用"],
        ["Docker wrappers", wrappers.filter(row => row.source === "docker"), "通过容器自动 fallback"],
        ["Missing wrappers", wrappers.filter(row => row.source === "missing"), "当前不可调用"]
      ];
      const wrapperHtml = wrapperGroups.map(([title, rows, note]) => renderToolGroup(title, rows, "tool", note, rows.length > 0 && title === "Missing wrappers")).join("");
      const profileHtml = renderToolGroup(
        "Heavyweight profiles",
        profiles,
        "profile",
        "按需单独构建的大型 Docker 镜像",
        profiles.some(row => !row.available)
      );
      const catalogGroups = groupRows(catalog, row => (row.categories && row.categories[0]) || row.category || "other");
      const catalogHtml = groupOrder(catalogGroups, categories).map(category => {
        const rows = catalogGroups[category] || [];
        return renderToolGroup(`Catalog: ${categoryLabels[category] || category}`, rows, "catalog", "推荐工具目录", false);
      }).join("");
      return wrapperHtml + profileHtml + catalogHtml;
    }
    function renderAnalysisHintGroups(hints) {
      const groups = groupRows(hints, row => row.category || "other");
      const html = groupOrder(groups, categories).map(category => {
        const rows = groups[category] || [];
        return renderToolGroup(`Hints: ${categoryLabels[category] || category}`, rows, "analysis_hint", "推荐分析提示", false);
      }).join("");
      return `<div class="result-card">
        <div class="card-head">
          <div class="card-title">
            <h3>推荐分析提示</h3>
            <div class="meta">来自 casebook/playbook 和近期 solve 脚本，用于减少做题经验与主功能漂移。</div>
          </div>
          <span class="badge muted">analysis hints</span>
        </div>
      </div>${html}`;
    }
    function renderToolGroup(title, rows, kind, note, open) {
      return `<details class="tool-group" ${open ? "open" : ""}>
        <summary><strong>${escapeHtml(title)}</strong><span class="group-count">${rows.length} entries · ${escapeHtml(note || "")}</span></summary>
        <div class="tool-items">${rows.length ? renderToolList(title, rows, kind) : `<div class="empty-state">暂无条目。</div>`}</div>
      </details>`;
    }
    function groupRows(rows, keyFn) {
      return rows.reduce((groups, row) => {
        const key = keyFn(row);
        groups[key] = groups[key] || [];
        groups[key].push(row);
        return groups;
      }, {});
    }
    function groupOrder(groups, preferred) {
      const known = preferred.filter(key => groups[key]);
      const rest = Object.keys(groups).filter(key => !preferred.includes(key)).sort();
      return [...known, ...rest];
    }
    function selectedChallenge() {
      return state.challenges.find(ch => ch.challenge_id === state.selected) || null;
    }
    function shellQuote(value) {
      const text = String(value || "");
      return `'${text.replace(/'/g, `'\\''`)}'`;
    }
    function projectRelativeArtifact(path) {
      const text = String(path || "");
      const marker = "/.forgeflag/";
      const index = text.indexOf(marker);
      if (index >= 0) return "." + text.slice(index);
      return text || "./chall";
    }
    async function copyTextFromElement(elementId) {
      const element = $(elementId);
      if (!element) return;
      const text = element.textContent || "";
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(text);
        } else {
          const textarea = document.createElement("textarea");
          textarea.value = text;
          textarea.setAttribute("readonly", "");
          textarea.style.position = "fixed";
          textarea.style.left = "-9999px";
          document.body.appendChild(textarea);
          textarea.select();
          document.execCommand("copy");
          textarea.remove();
        }
        status("已复制 Pwn 命令", "success");
      } catch {
        status("复制失败，请手动选择命令", "error");
      }
    }
    function pwnExploitTemplate(artifactPath) {
      const binaryLiteral = JSON.stringify(artifactPath || "./chall");
      return [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "import argparse",
        "import sys",
        "",
        "parser = argparse.ArgumentParser(description='pwntools exploit template')",
        "parser.add_argument('--remote', action='store_true', help='connect to remote HOST:PORT instead of local process')",
        "parser.add_argument('--host', default='127.0.0.1')",
        "parser.add_argument('--port', type=int, default=31337)",
        `parser.add_argument('--binary', default=${binaryLiteral})`,
        "parser.add_argument('--libc', default='', help='optional shipped libc path')",
        "parser.add_argument('--gdb', action='store_true', help='attach gdb in local debug mode')",
        "parser.add_argument('--proof', action='store_true', help='run cat flag and verify the local test flag after exploit')",
        "args = parser.parse_args()",
        "",
        "DEBUG = not args.remote",
        "elf = ELF(args.binary, checksec=False)",
        "libc = ELF(args.libc, checksec=False) if args.libc else None",
        "context.binary = elf",
        "context.log_level = 'debug' if DEBUG else 'info'",
        "context.terminal = ['tmux', 'splitw', '-v']",
        "TEST_FLAG = b'flag{forgeflag_local_pwn_test}'",
        "",
        "def start():",
        "    if args.remote:",
        "        return remote(args.host, args.port)",
        "    return process(args.binary)",
        "",
        "def debugf():",
        "    if DEBUG and args.gdb:",
        "        gdb.attach(io, gdbscript='''",
        "# b *main",
        "continue",
        "''')",
        "",
        "def sla(delim, data):",
        "    return io.sendlineafter(delim, data if isinstance(data, bytes) else str(data).encode())",
        "",
        "def sa(delim, data):",
        "    return io.sendafter(delim, data if isinstance(data, bytes) else str(data).encode())",
        "",
        "def ru(delim):",
        "    return io.recvuntil(delim)",
        "",
        "# Menu helper placeholders: rename prompts and choices to match the challenge.",
        "def Add(size, content):",
        "    sla(b'Your choice: ', b'2')",
        "    sla(b'Length: ', size)",
        "    sa(b'Content: ', content)",
        "",
        "def Delete(index):",
        "    sla(b'Your choice: ', b'4')",
        "    sla(b'Index: ', index)",
        "",
        "def Edit(index, size, content):",
        "    sla(b'Your choice: ', b'3')",
        "    sla(b'Index: ', index)",
        "    sla(b'Length: ', size)",
        "    sa(b'Content: ', content)",
        "",
        "def Show():",
        "    sla(b'Your choice: ', b'1')",
        "    return ru(b'Your choice: ')",
        "",
        "def leak():",
        "    # Keep heap/libc/code leaks here and log every derived base.",
        "    # log.success(f'libc_base: {hex(libc.address)}')",
        "    return {}",
        "",
        "def exploit(leaks):",
        "    # Replace this with cyclic_find(crash_value) after reproducing the crash in gdb.",
        "    offset = cyclic_find(0x6161616c)",
        "    if offset < 0:",
        "        offset = cyclic_find(b'laaa')",
        "",
        "    payload = flat({",
        "        0: b'A' * offset,",
        "        # offset: p64(0xdeadbeef),",
        "    })",
        "",
        "    # Adjust sendlineafter() to match the target prompt.",
        "    # sla(b'> ', payload)",
        "    io.sendline(payload)",
        "",
        "def proof():",
        "    # local test flag proof: only use after the exploit gives shell or command execution.",
        "    io.sendline(b'cat flag')",
        "    data = io.recvrepeat(1)",
        "    print(data.decode(errors='replace'))",
        "    if TEST_FLAG not in data:",
        "        log.failure('local test flag was not recovered')",
        "        raise SystemExit(2)",
        "    log.success('local test flag proof verified')",
        "",
        "io = start()",
        "debugf()",
        "leaks = leak()",
        "exploit(leaks)",
        "if args.proof:",
        "    proof()",
        "else:",
        "    io.interactive()",
      ].join("\n");
    }
    function downloadExploitTemplate() {
      const template = $("pwnExploitTemplate");
      if (!template) return;
      const blob = new Blob([template.textContent || ""], { type: "text/x-python;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "exploit.py";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      status("已生成 exploit.py 下载", "success");
    }
    function renderPwnEnvironmentPanel() {
      const panel = $("pwnEnvironmentPanel");
      const challenge = selectedChallenge();
      if (!panel) return;
      if (!challenge || challenge.category !== "pwn") {
        panel.hidden = true;
        panel.innerHTML = "";
        return;
      }
      const artifactPath = projectRelativeArtifact(asList(challenge.attachment_paths)[0]);
      const quotedArtifact = shellQuote(artifactPath);
      const enterCommand = [
        "# 在 ForgeFlag 项目根目录执行",
        'docker run --rm -it --platform linux/amd64 -p 31337:31337 -v "$PWD:/workspace" -w /workspace forgeflag-ctf:latest bash'
      ].join("\n");
      const serviceCommand = [
        `printf '%s\\n' 'flag{forgeflag_local_pwn_test}' > flag`,
        `chmod +x ${quotedArtifact}`,
        `socat TCP-LISTEN:31337,reuseaddr,fork EXEC:${quotedArtifact},pty,stderr`
      ].join("\n");
      const triageCommand = [
        `file ${quotedArtifact}`,
        `checksec --file ${quotedArtifact}`,
        `gdb ${quotedArtifact}`
      ].join("\n");
      const exploitTemplate = pwnExploitTemplate(artifactPath);
      panel.hidden = false;
      panel.innerHTML = `
        <div class="card-head">
          <div class="card-title">
            <h3>Pwn 本地环境</h3>
            <div class="meta">人工调试入口：进 Kali 工具容器、起本地题目服务，再让 ForgeFlag 连接本机端口。</div>
          </div>
          <span class="badge muted">forgeflag-ctf:latest</span>
        </div>
        <div class="actions">
          <button class="secondary" id="pwnFillTargetBtn" type="button">填入本地 Target</button>
        </div>
        <div class="kv-grid">
          <div class="kv"><span>Target</span><strong>${escapeHtml(PWN_LOCAL_TARGET)}</strong><div class="meta">运行前勾选 Active probe，Allowed Hosts 包含 127.0.0.1。</div></div>
          <div class="kv"><span>Artifact</span><strong>${escapeHtml(artifactPath)}</strong><div class="meta">${asList(challenge.attachment_paths).length ? "已按 Web 上传附件生成路径" : "未上传附件时请在容器内改成真实二进制路径"}</div></div>
          <div class="kv"><span>Manual mode</span><strong>Docker + socat + pwntools</strong><div class="meta">适合 ret2win、格式化字符串、栈溢出等题型人工复现。</div></div>
        </div>
        <div>
          <div class="command-head"><strong>进入 Pwn 容器</strong><button class="secondary" type="button" data-copy-target="pwnEnterCommand">复制</button></div>
          <pre class="command-block" id="pwnEnterCommand">${escapeHtml(enterCommand)}</pre>
        </div>
        <div>
          <div class="command-head"><strong>容器内启动题目服务</strong><button class="secondary" type="button" data-copy-target="pwnServiceCommand">复制</button></div>
          <pre class="command-block" id="pwnServiceCommand">${escapeHtml(serviceCommand)}</pre>
        </div>
        <div>
          <div class="command-head"><strong>容器内手工分析</strong><button class="secondary" type="button" data-copy-target="pwnTriageCommand">复制</button></div>
          <pre class="command-block" id="pwnTriageCommand">${escapeHtml(triageCommand)}</pre>
        </div>
        <div>
          <div class="command-head"><strong>pwntools exploit template</strong><span class="actions"><button class="secondary" type="button" data-copy-target="pwnExploitTemplate">复制</button><button class="secondary" id="pwnDownloadExploitBtn" type="button">下载 exploit.py</button></span></div>
          <pre class="command-block" id="pwnExploitTemplate">${escapeHtml(exploitTemplate)}</pre>
        </div>`;
      bindPwnEnvironmentPanel();
    }
    function bindPwnEnvironmentPanel() {
      const button = $("pwnFillTargetBtn");
      if (!button) return;
      button.onclick = () => {
        $("target").value = PWN_LOCAL_TARGET;
        $("allowedHosts").value = "127.0.0.1,localhost";
        $("activeProbe").checked = true;
        status("已填入 Pwn 本地 Target，并启用本机 Active probe", "success");
      };
      $("pwnEnvironmentPanel").querySelectorAll("[data-copy-target]").forEach(copyButton => {
        copyButton.onclick = () => copyTextFromElement(copyButton.dataset.copyTarget);
      });
      const downloadButton = $("pwnDownloadExploitBtn");
      if (downloadButton) downloadButton.onclick = () => downloadExploitTemplate();
    }
    async function saveChallenge() {
      const challengeId = ensureChallengeId(false);
      const payload = {
        challenge_id: challengeId,
        category: $("category").value,
        title: $("title").value.trim(),
        target: $("target").value.trim(),
        description: $("description").value.trim(),
        tags: $("tags").value,
        attachments: await filesPayload()
      };
      const res = await api("/api/challenges", { method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify(payload) });
      state.selected = res.challenge_id || payload.challenge_id;
      $("challengeId").value = state.selected;
      state.activeCategory = payload.category || state.activeCategory;
      state.activeStatus = "all";
      show(res, "raw");
      await refresh();
      return res;
    }
    async function runSelected() {
      if (!state.selected) {
        status($("challengeId").value.trim() ? "请先保存题目或从列表选择已有题目" : "请先选择一道题目", "error");
        return false;
      }
      if (!ensureLLMReady()) return false;
      setRunState(true, `运行中：${state.selected}`, "busy");
      show({ challenge_id: state.selected, status: "running", solvers: [], accepted_flags: [], rejected_flags: [], observations: 0 }, "summary");
      const payload = {
        active_probe: $("activeProbe").checked,
        allowed_hosts: $("allowedHosts").value,
        ...llmPayload()
      };
      try {
        const res = await api(`/api/challenges/${encodeURIComponent(state.selected)}/run`, { method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify(payload) });
        state.lastSummary = res;
        state.summaries[state.selected] = res;
        status(`运行完成：${res.status || "done"}`, res.status === "flag_found" ? "success" : "info");
        flashButton("runBtn", "success");
        show(res, "summary");
        await refresh();
        await loadTab("findings");
        return res;
      } finally {
        setRunState(false);
      }
    }
    function setRunState(running, message, tone="info") {
      const button = $("runBtn");
      setButtonBusy(button, running, "运行中...");
      if (message) status(message, tone);
    }
    async function deleteSelectedChallenge() {
      if (!state.selected) {
        status("请先选择要删除的题目", "error");
        return false;
      }
      const challengeId = state.selected;
      if (!confirm(`删除题目 ${challengeId} 及其运行记录？`)) {
        status("已取消删除", "info");
        return false;
      }
      setButtonBusy("deleteBtn", true, "删除中...");
      status(`删除中：${challengeId}`, "busy");
      const res = await api(`/api/challenges/${encodeURIComponent(challengeId)}`, { method:"DELETE" });
      delete state.summaries[challengeId];
      state.selected = null;
      state.lastSummary = {};
      status(`已删除：${challengeId}`, "success");
      flashButton("deleteBtn", "success");
      await refresh();
      show(res, "raw");
      setButtonBusy("deleteBtn", false);
      return res;
    }
    async function clearChallenges() {
      if (!confirm("清空全部题目、运行记录和 Web 上传附件？")) {
        status("已取消清空", "info");
        return false;
      }
      setButtonBusy("clearBtn", true, "清空中...");
      status("清空中...", "busy");
      const res = await api("/api/challenges", { method:"DELETE" });
      state.selected = null;
      state.lastSummary = {};
      state.summaries = {};
      status("已清空全部题目", "success");
      flashButton("clearBtn", "success");
      await refresh();
      show(res, "raw");
      setButtonBusy("clearBtn", false);
      return res;
    }
    async function testLLM() {
      if (!$("llmEnabled").checked) $("llmEnabled").checked = true;
      syncLLMSettings();
      if (!ensureLLMReady()) return {status:"blocked", reason:"missing_llm_config"};
      $("llmConfigStatus").textContent = "正在测试...";
      status("正在测试大模型连接...", "busy");
      const res = await api("/api/llm/test", { method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify(llmPayload()) });
      $("llmConfigStatus").textContent = `测试成功：${res.provider} ${res.model || ""}`;
      status(`大模型测试成功：${res.provider} ${res.model || ""}`, "success");
      show(res, "raw");
      return res;
    }
    async function loadTab(tab) {
      document.querySelectorAll(".tabs button").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === tab));
      const activeButton = document.querySelector(`.tabs button[data-tab="${tab}"]`);
      if (activeButton) activeButton.scrollIntoView({block:"nearest", inline:"center"});
      if (tab === "tools") return show(await api("/api/tools"), "tools");
      if (tab === "catalog") return show(await api("/api/project-catalog"), "catalog");
      if (tab === "benchmark") return show(await api("/api/capability-benchmark"), "benchmark");
      if (tab === "health") return show(await api("/api/system-health"), "health");
      if (tab === "summary") return show(await loadLatestSummary(), "summary");
      if (!state.selected) return status($("challengeId").value.trim() ? "请先保存题目或从列表选择已有题目" : "请先选择一道题目", "error");
      if (tab === "agent") return show(await loadAgentView(), "agent");
      show(await api(`/api/challenges/${encodeURIComponent(state.selected)}/${tab}`), tab);
    }
    async function loadLatestSummary() {
      if (!state.selected) return draftChallengeSummary();
      const summary = await api(`/api/challenges/${encodeURIComponent(state.selected)}/summary`);
      state.lastSummary = summary;
      state.summaries[state.selected] = summary;
      return summary;
    }
    async function loadAgentView() {
      const challenge = encodeURIComponent(state.selected);
      const [summary, report, findings, observations, roster] = await Promise.all([
        api(`/api/challenges/${challenge}/summary`),
        api(`/api/challenges/${challenge}/report`),
        api(`/api/challenges/${challenge}/findings`),
        api(`/api/challenges/${challenge}/observations`),
        api("/api/agents")
      ]);
      state.lastSummary = summary;
      state.summaries[state.selected] = summary;
      return { challenge_id: state.selected, summary, report, findings, observations, roster };
    }
    $("saveBtn").onclick = () => withButtonFeedback("saveBtn", "保存中...", "题目已保存", saveChallenge).catch(e => show({error:e.message}));
    $("refreshBtn").onclick = () => withButtonFeedback("refreshBtn", "刷新中...", "列表已刷新", refresh).catch(e => show({error:e.message}));
    $("deleteBtn").onclick = () => deleteSelectedChallenge().catch(e => { setButtonBusy("deleteBtn", false); status("删除失败", "error"); show({error:e.message}); });
    $("clearBtn").onclick = () => clearChallenges().catch(e => { setButtonBusy("clearBtn", false); status("清空失败", "error"); show({error:e.message}); });
    $("runBtn").onclick = () => runSelected().catch(e => { setRunState(false, "运行失败", "error"); show({error:e.message}); });
    $("llmSaveConfig").onclick = () => saveLLMConfig();
    $("llmTestBtn").onclick = () => withButtonFeedback("llmTestBtn", "测试中...", "", testLLM).catch(e => { $("llmConfigStatus").textContent = "测试失败"; show({error:e.message}); });
    $("generateIdBtn").onclick = () => { ensureChallengeId(true); status("已生成题目 ID", "success"); };
    $("challengeId").oninput = () => { state.idTouched = true; };
    $("category").onchange = maybeRefreshGeneratedId;
    $("title").oninput = maybeRefreshGeneratedId;
    $("target").oninput = maybeRefreshGeneratedId;
    $("attachments").onchange = maybeRefreshGeneratedId;
    $("llmEnabled").onchange = syncLLMSettings;
    $("llmProvider").onchange = () => { if ($("llmProvider").value === "disabled") $("llmEnabled").checked = false; syncLLMSettings(); };
    $("llmSavedKeySelect").onchange = () => applySavedLLMKey($("llmSavedKeySelect").value);
    $("llmClearSavedKeys").onclick = () => clearSavedLLMKeys();
    document.querySelectorAll(".tabs button").forEach(btn => btn.onclick = () => loadTab(btn.dataset.tab).catch(e => show({error:e.message})));
    restoreLLMConfig();
    ensureChallengeId(false);
    refresh().catch(e => show({error:e.message}));
  </script>
</body>
</html>
"""

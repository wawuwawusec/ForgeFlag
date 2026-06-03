from __future__ import annotations

import base64
import json
import shutil
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from forgeflag.artifacts import ArtifactWorkspace, summarize_artifact_paths
from forgeflag.domain import DEFAULT_ZHIPU_MODEL, Challenge, ChallengeCategory, LLMConfig, RunConfig
from forgeflag.llm import build_llm_provider
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.project_catalog import recommended_projects
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
            if path == "/api/challenges":
                self._send_json(self.handle_list_challenges())
                return
            if path == "/api/tools":
                self._send_json(self.handle_tools())
                return
            if path == "/api/project-catalog":
                self._send_json(self.handle_project_catalog())
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
                        "accepted_flags": accepted_flags,
                        "accepted_flag_count": len(accepted_flags),
                    }
                )
            return rows

        @classmethod
        def handle_tools(cls) -> dict[str, Any]:
            wrappers = ToolRunner(ScopePolicy()).inventory()
            catalog = recommended_projects()
            host_wrappers = sum(1 for row in wrappers if row.get("source") == "host")
            docker_wrappers = sum(1 for row in wrappers if row.get("source") == "docker")
            missing_wrappers = sum(1 for row in wrappers if row.get("source") == "missing")
            return {
                "wrappers": wrappers,
                "catalog": catalog,
                "counts": {
                    "wrappers": len(wrappers),
                    "available_wrappers": sum(1 for row in wrappers if row.get("available")),
                    "host_wrappers": host_wrappers,
                    "docker_wrappers": docker_wrappers,
                    "missing_wrappers": missing_wrappers,
                    "catalog": len(catalog),
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
            challenge_id = _required_string(payload, "challenge_id")
            category = ChallengeCategory(str(payload.get("category") or ChallengeCategory.UNKNOWN.value))
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
                return summary
            # Validate that the challenge exists and return a stable empty run shape.
            cls.notebook.get_challenge(challenge_id)
            return {
                "challenge_id": challenge_id,
                "status": "not_run",
                "solvers": [],
                "accepted_flags": [],
                "rejected_flags": [],
                "observations": len(cls.notebook.observations_for(challenge_id)),
            }

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
            return (summary or {}).get("replay_report") or {}

        @classmethod
        def handle_project_catalog(cls) -> list[dict[str, Any]]:
            return recommended_projects()

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
        )
    return LLMConfig(
        provider=provider,
        model=_optional_string(payload.get("llm_model")) or base.model or _default_llm_model(provider),
        api_key=_optional_string(payload.get("llm_api_key")) or base.api_key,
        base_url=_optional_string(payload.get("llm_base_url")) or _default_llm_base_url(provider, base.base_url),
        timeout_seconds=_int_value(payload.get("llm_timeout_seconds"), base.timeout_seconds),
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
  <title>ForgeFlag Console</title>
  <style>
    :root { color-scheme: light; --ink:#172026; --muted:#5d6b75; --line:#d9e0e5; --panel:#f7f9fb; --accent:#126b56; --warn:#9b4d13; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: #fff; }
    header { padding: 18px 24px; border-bottom: 1px solid var(--line); display: flex; justify-content: space-between; gap: 16px; align-items: center; }
    h1 { margin: 0; font-size: 22px; }
    h2 { margin: 0 0 12px; font-size: 16px; }
    main { display: grid; grid-template-columns: 380px 1fr; min-height: calc(100vh - 64px); }
    aside { border-right: 1px solid var(--line); padding: 18px; background: var(--panel); }
    section { padding: 18px 24px; }
    label { display: block; margin: 10px 0 4px; font-size: 13px; color: var(--muted); }
    input, select, textarea { width: 100%; border: 1px solid var(--line); border-radius: 6px; padding: 9px 10px; font: inherit; background: #fff; }
    textarea { min-height: 76px; resize: vertical; }
    button { border: 1px solid #0f5d4c; background: var(--accent); color: white; border-radius: 6px; padding: 9px 12px; font: inherit; cursor: pointer; transition: transform .08s ease, box-shadow .12s ease, opacity .12s ease, background-color .12s ease; }
    button.secondary { background: white; color: var(--ink); border-color: var(--line); }
    button.warn { background: var(--warn); border-color: var(--warn); }
    button:active { transform: translateY(1px); }
    button:focus-visible { outline: 3px solid #9fd8c7; outline-offset: 2px; }
    button:disabled { opacity: .58; cursor: wait; }
    button.is-busy { position: relative; padding-left: 32px; }
    button.is-busy::before { content: ""; position: absolute; left: 11px; top: 50%; width: 12px; height: 12px; margin-top: -6px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 999px; animation: spin .75s linear infinite; }
    button.just-done { box-shadow: 0 0 0 3px rgba(18,107,86,.18); }
    button.just-error { box-shadow: 0 0 0 3px rgba(155,77,19,.22); }
    @keyframes spin { to { transform: rotate(360deg); } }
    .row { display: flex; gap: 8px; align-items: center; }
    .row > * { flex: 1; }
    .actions { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
    .run-panel { display: grid; gap: 10px; border-bottom: 1px solid var(--line); padding-bottom: 16px; }
    .runtime-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .inline-check { display: flex; align-items: center; gap: 8px; margin: 0; color: var(--ink); }
    .inline-check input { width: auto; }
    .llm-settings { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .llm-settings[hidden] { display: none; }
    .llm-actions { grid-column: 1 / -1; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .llm-status { color: var(--muted); font-size: 12px; }
    .category-bar, .status-bar { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin: 12px 0 16px; }
    .category-pill, .status-pill { background: white; color: var(--ink); border-color: var(--line); display: flex; justify-content: space-between; align-items: center; padding: 8px 10px; }
    .category-pill.active, .status-pill.active { background: var(--accent); color: white; border-color: var(--accent); }
    .category-pill span:last-child, .status-pill span:last-child { font-size: 12px; opacity: .85; }
    .list { display: grid; gap: 8px; margin-top: 12px; }
    .item { border: 1px solid var(--line); background: white; border-radius: 6px; padding: 10px; cursor: pointer; }
    .item.active { border-color: var(--accent); box-shadow: inset 3px 0 0 var(--accent); }
    .item-head { display: flex; justify-content: space-between; gap: 8px; align-items: center; }
    .category-group, .tool-group { border: 1px solid var(--line); border-radius: 6px; background: white; overflow: hidden; }
    .category-group summary, .tool-group summary { list-style: none; cursor: pointer; padding: 10px 12px; display: flex; justify-content: space-between; gap: 10px; align-items: center; }
    .category-group summary::-webkit-details-marker, .tool-group summary::-webkit-details-marker { display: none; }
    .category-group summary::before, .tool-group summary::before { content: "›"; color: var(--muted); font-size: 16px; transition: transform .15s ease; }
    .category-group[open] summary::before, .tool-group[open] summary::before { transform: rotate(90deg); }
    .category-items, .tool-items { display: grid; gap: 8px; padding: 0 10px 10px; }
    .group-count { color: var(--muted); font-size: 12px; margin-left: auto; }
    .meta { color: var(--muted); font-size: 12px; margin-top: 4px; overflow-wrap: anywhere; }
    .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--line); margin-bottom: 14px; }
    .tabs button { background: white; color: var(--ink); border-color: var(--line); border-bottom: 0; border-radius: 6px 6px 0 0; }
    .tabs button.active { background: var(--accent); color: white; }
    .result-view { display: grid; gap: 12px; min-height: 420px; }
    .empty-state { border: 1px dashed var(--line); border-radius: 6px; padding: 18px; color: var(--muted); background: #fbfcfd; }
    .result-card { border: 1px solid var(--line); border-radius: 6px; background: white; padding: 14px; display: grid; gap: 10px; }
    .result-card h3 { margin: 0; font-size: 15px; }
    .writeup-hero { border-color: #b9d8cc; background: #f7fcfa; }
    .writeup-section-body { margin: 0; line-height: 1.65; color: #2f3b43; }
    .writeup-section-body:empty { display: none; }
    .writeup-section .steps li { margin: 8px 0; line-height: 1.55; }
    .tab-intro { border: 1px solid #cfe4dc; border-radius: 6px; background: #f2faf7; color: #24463d; padding: 10px 12px; font-size: 13px; }
    .tab-intro strong { display: block; margin-bottom: 3px; color: var(--ink); }
    .card-head { display: flex; justify-content: space-between; gap: 12px; align-items: start; flex-wrap: wrap; }
    .card-title { display: grid; gap: 4px; min-width: 0; }
    .badge { display: inline-flex; width: fit-content; align-items: center; border-radius: 999px; padding: 3px 8px; font-size: 12px; background: #eaf4f0; color: #0f5d4c; border: 1px solid #cfe4dc; }
    .badge.warn { background: #fff5eb; color: #8b4210; border-color: #f1d5b7; }
    .badge.muted { background: #eef2f5; color: var(--muted); border-color: var(--line); }
    .flag-list { display: flex; gap: 8px; flex-wrap: wrap; }
    .flag-chip { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: #111820; color: #e7eef4; border-radius: 6px; padding: 5px 8px; overflow-wrap: anywhere; }
    .tag-row { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 6px; }
    .tag-chip { border: 1px solid var(--line); border-radius: 999px; background: #fbfcfd; color: var(--muted); padding: 2px 7px; font-size: 11px; }
    .kv-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
    .kv { border: 1px solid var(--line); border-radius: 6px; padding: 9px 10px; background: #fbfcfd; min-width: 0; }
    .kv span { display: block; color: var(--muted); font-size: 12px; margin-bottom: 4px; }
    .kv strong { overflow-wrap: anywhere; }
    .steps { margin: 0; padding-left: 20px; }
    .steps li { margin: 5px 0; }
    details.raw { border-top: 1px solid var(--line); padding-top: 8px; }
    details.raw summary { color: var(--muted); cursor: pointer; font-size: 13px; }
    pre.raw-json { margin: 8px 0 0; white-space: pre-wrap; overflow-wrap: anywhere; background: #111820; color: #e7eef4; border-radius: 6px; padding: 12px; max-height: 360px; overflow: auto; }
    .status { font-size: 13px; color: var(--muted); }
    .status[data-tone="busy"] { color: #0f5d4c; }
    .status[data-tone="success"] { color: #126b56; }
    .status[data-tone="error"] { color: #9b2c13; }
    .action-toast { position: fixed; right: 18px; top: 74px; z-index: 10; max-width: min(420px, calc(100vw - 36px)); border: 1px solid #cfe4dc; border-radius: 6px; background: #f2faf7; color: #24463d; padding: 10px 12px; font-size: 13px; box-shadow: 0 10px 24px rgba(23,32,38,.12); }
    .action-toast[data-tone="busy"] { border-color: #b9d8cc; }
    .action-toast[data-tone="success"] { border-color: #a8d5c5; background: #eefaf5; }
    .action-toast[data-tone="error"] { border-color: #f1c5b7; background: #fff3ef; color: #7d2d18; }
    .action-toast[hidden] { display: none; }
    @media (max-width: 860px) { main { grid-template-columns: 1fr; } aside { border-right: 0; border-bottom: 1px solid var(--line); } .runtime-grid, .llm-settings, .kv-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <h1>ForgeFlag Console</h1>
    <div class="status" id="status">ready</div>
  </header>
  <div class="action-toast" id="actionToast" role="status" aria-live="polite" hidden></div>
  <main>
    <aside>
      <h2>新建 / 更新题目</h2>
      <label>Challenge ID</label>
      <input id="challengeId" placeholder="forensics-01">
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
        <button class="secondary" id="refreshBtn">刷新列表</button>
        <button class="warn" id="deleteBtn">删除选中</button>
        <button class="warn" id="clearBtn">清空全部</button>
      </div>
      <h2 style="margin-top:22px">分类工作台</h2>
      <div class="category-bar" id="categoryFilters"></div>
      <div class="meta" id="categoryCounts"></div>
      <h2 style="margin-top:22px">状态筛选</h2>
      <div class="status-bar" id="statusFilters"></div>
      <div class="meta" id="statusCounts"></div>
      <h2 style="margin-top:22px">题目列表</h2>
      <div class="list" id="challengeList"></div>
    </aside>
    <section>
      <div class="run-panel">
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
        <div class="llm-settings" id="llmSettings" hidden>
          <div>
            <label>Model</label>
            <input id="llmModel" placeholder="gpt-4.1">
          </div>
          <div>
            <label>API Key</label>
            <input id="llmApiKey" type="password" autocomplete="off" placeholder="sk-...">
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
            <button class="secondary" id="llmSaveConfig">保存配置</button>
            <button class="secondary" id="llmTestBtn">测试大模型</button>
            <label class="inline-check"><input id="llmRememberKey" type="checkbox"> 记住 API Key</label>
            <span class="llm-status" id="llmConfigStatus">配置未保存</span>
          </div>
        </div>
      </div>
      <div class="tabs" style="margin-top:18px">
        <button class="active" data-tab="summary">Summary</button>
        <button data-tab="report">Write-up</button>
        <button data-tab="agent">Agent</button>
        <button data-tab="findings">Findings</button>
        <button data-tab="observations">Observations</button>
        <button data-tab="artifacts">Artifacts</button>
        <button data-tab="tools">Tools</button>
        <button data-tab="catalog">Catalog</button>
      </div>
      <div id="output" class="result-view"><div class="empty-state">选择题目并运行后，这里会显示可读的解题结果。</div></div>
    </section>
  </main>
  <script>
    const categories = ["unknown","web","pwn","reverse","crypto","forensics","traffic","misc","infra"];
    const categoryLabels = { all:"全部", unknown:"未知", web:"Web", pwn:"Pwn", reverse:"Reverse", crypto:"Crypto", forensics:"Forensics", traffic:"Traffic", misc:"Misc", infra:"Infra" };
    const statusFilters = ["all","solved","ran","not_run"];
    const statusLabels = { all:"全部", solved:"已出 flag", ran:"已运行未出", not_run:"未运行" };
    const state = { selected: null, activeCategory: "all", activeStatus: "all", challenges: [], lastSummary: {}, summaries: {} };
    const writeupSectionOrder = ["解题思路", "复现步骤"];
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
    const DEFAULT_ZHIPU_MODEL = "glm-5.1";
    categories.forEach(c => { const o = document.createElement("option"); o.value = c; o.textContent = c; $("category").appendChild(o); });
    function syncLLMSettings() {
      $("llmSettings").hidden = !$("llmEnabled").checked;
      if ($("llmEnabled").checked && $("llmProvider").value === "disabled") $("llmProvider").value = "zhipu";
      const zhipu = $("llmProvider").value === "zhipu";
      $("llmModel").placeholder = zhipu ? DEFAULT_ZHIPU_MODEL : "gpt-4.1";
      if (zhipu && !$("llmModel").value.trim()) $("llmModel").value = DEFAULT_ZHIPU_MODEL;
      $("llmApiKey").placeholder = zhipu ? "ZAI_API_KEY" : "sk-...";
      $("llmBaseUrl").placeholder = zhipu ? "https://open.bigmodel.cn/api/paas/v4" : "https://api.openai.com/v1";
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
      const saved = {
        llm_enabled: payload.llm_enabled,
        llm_provider: payload.llm_provider,
        llm_model: payload.llm_model,
        llm_base_url: payload.llm_base_url,
        llm_timeout_seconds: payload.llm_timeout_seconds,
        remember_key: $("llmRememberKey").checked,
        llm_api_key: $("llmRememberKey").checked ? payload.llm_api_key : ""
      };
      localStorage.setItem(LLM_CONFIG_KEY, JSON.stringify(saved));
      $("llmConfigStatus").textContent = saved.remember_key ? "配置已保存到本浏览器（含 Key）" : "配置已保存到本浏览器（不含 Key）";
      flashButton("llmSaveConfig", "success");
      status("大模型配置已保存", "success");
    }
    function restoreLLMConfig() {
      const raw = localStorage.getItem(LLM_CONFIG_KEY);
      if (!raw) return syncLLMSettings();
      try {
        const saved = JSON.parse(raw);
        $("llmEnabled").checked = !!saved.llm_enabled;
        $("llmProvider").value = saved.llm_provider || "zhipu";
        $("llmModel").value = saved.llm_model || "";
        $("llmBaseUrl").value = saved.llm_base_url || "";
        $("llmTimeout").value = saved.llm_timeout_seconds || "30";
        $("llmRememberKey").checked = !!saved.remember_key;
        $("llmApiKey").value = saved.remember_key ? (saved.llm_api_key || "") : "";
        $("llmConfigStatus").textContent = saved.remember_key ? "已载入本浏览器配置（含 Key）" : "已载入本浏览器配置（不含 Key）";
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
      renderCategoryFilters(challenges);
      renderStatusFilters(challenges);
      renderChallengeList();
      show(challenges, "raw");
    }
    function renderChallengeList() {
      const list = $("challengeList");
      list.innerHTML = "";
      const visible = state.challenges.filter(ch => (state.activeCategory === "all" || ch.category === state.activeCategory) && statusMatches(ch));
      if (!visible.length) {
        list.innerHTML = `<div class="empty-state">当前筛选暂无题目。</div>`;
        return;
      }
      list.innerHTML = renderChallengeGroups(visible);
      list.querySelectorAll("[data-challenge-id]").forEach(item => {
        item.onclick = () => {
          state.selected = item.dataset.challengeId;
          renderChallengeList();
          loadTab(document.querySelector(".tabs button.active").dataset.tab).catch(e => show({error:e.message}));
        };
      });
    }
    function renderChallengeGroups(challenges) {
      const groups = groupRows(challenges, ch => ch.category || "unknown");
      return groupOrder(groups, categories).map(category => {
        const rows = groups[category] || [];
        const selectedInGroup = rows.some(ch => ch.challenge_id === state.selected);
        const shouldOpen = state.activeCategory !== "all" || selectedInGroup;
        return `<details class="category-group" ${shouldOpen ? "open" : ""}>
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
    function statusLabel(challenge) {
      const status = challenge.latest_status || "not_run";
      const count = challenge.accepted_flag_count || 0;
      const badgeClass = status === "flag_found" ? "badge" : (status === "not_run" ? "badge muted" : "badge warn");
      const suffix = count ? ` · ${count} flag` : "";
      return `<span class="${badgeClass}">${escapeHtml(status)}${escapeHtml(suffix)}</span>`;
    }
    function tagChips(tags) {
      const values = asList(tags).filter(Boolean).slice(0, 5);
      if (!values.length) return "";
      return `<div class="tag-row">${values.map(tag => `<span class="tag-chip">${escapeHtml(tag)}</span>`).join("")}</div>`;
    }
    function statusBucket(challenge) {
      if ((challenge.accepted_flag_count || 0) > 0 || challenge.latest_status === "flag_found") return "solved";
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
      const statusClass = data.status === "flag_found" ? "badge" : "badge muted";
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
          ${rejected.length ? `<div class="meta">被拒候选：${rejected.map(escapeHtml).join(", ")}</div>` : ""}
          ${rawJson(data)}
        </div>`;
    }
    function renderFindings(data) {
      const findings = asList(data);
      if (!findings.length) return `<div class="empty-state">暂无 Findings。运行题目后，这里会按 solver 展示发现、证据和下一步。</div>${rawJson(data)}`;
      return findings.map(finding => {
        const confidence = typeof finding.confidence === "number" ? Math.round(finding.confidence * 100) + "%" : "n/a";
        const evidence = finding.evidence || {};
        const candidates = evidence.transform_candidates || evidence.flag_candidates || evidence.decoded_http_artifacts || [];
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
            ${Array.isArray(candidates) && candidates.length ? `<div><strong>关键候选：</strong><div class="flag-list">${candidates.slice(0, 6).map(item => `<span class="flag-chip">${escapeHtml(item.value || item)}</span>`).join("")}</div></div>` : ""}
            ${rawJson(finding)}
          </div>`;
      }).join("");
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
            <div class="kv"><span>LLM Plans</span><strong>${llmPlans.length}</strong></div>
            <div class="kv"><span>Action Queues</span><strong>${actionQueues.length}</strong></div>
            <div class="kv"><span>Critics</span><strong>${postRunCritics.length}</strong></div>
            <div class="kv"><span>Tool Summaries</span><strong>${toolSummaries.length}</strong></div>
          </div>
        </div>
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
      return `<div class="kv">
        <span>${escapeHtml(entry.source || "LLM")}</span>
        <strong>${escapeHtml(plan.summary || entry.finding || "LLM plan")}</strong>
        ${hypotheses.length ? `<div class="meta">假设：${hypotheses.map(escapeHtml).join("；")}</div>` : ""}
        ${actions.length ? `<div class="meta">下一步：${actions.map(escapeHtml).join("；")}</div>` : ""}
        ${solvers.length ? `<div class="meta">建议 solver：${solvers.map(escapeHtml).join(", ")}</div>` : ""}
        ${tools.length ? `<div class="meta">工具提示：${tools.map(escapeHtml).join(", ")}</div>` : ""}
        ${expected.length ? `<div class="meta">期望证据：${expected.map(escapeHtml).join("；")}</div>` : ""}
        ${plan.fallback_plan ? `<div class="meta">Fallback：${escapeHtml(plan.fallback_plan)}</div>` : ""}
      </div>`;
    }
    function renderActionQueue(obs) {
      const evidence = obs.evidence || {};
      const queued = asList(evidence.queued_solvers);
      const already = asList(evidence.already_present_solvers);
      const unknown = asList(evidence.unknown_solvers);
      const actions = asList(evidence.next_actions);
      const tools = asList(evidence.tool_hints);
      return `<div class="kv">
        <span>${escapeHtml(obs.source || "Manager")}</span>
        <strong>${escapeHtml(obs.summary || "LLM action queue")}</strong>
        ${queued.length ? `<div class="meta">排队 solver：${queued.map(escapeHtml).join(", ")}</div>` : ""}
        ${already.length ? `<div class="meta">已在队列：${already.map(escapeHtml).join(", ")}</div>` : ""}
        ${unknown.length ? `<div class="meta">无效建议：${unknown.map(escapeHtml).join(", ")}</div>` : ""}
        ${actions.length ? `<div class="meta">下一步：${actions.map(escapeHtml).join("；")}</div>` : ""}
        ${tools.length ? `<div class="meta">工具提示：${tools.map(escapeHtml).join(", ")}</div>` : ""}
      </div>`;
    }
    function renderPostRunCritic(obs) {
      const evidence = obs.evidence || {};
      const blockers = asList(evidence.blockers);
      const missing = asList(evidence.missing_evidence);
      const solvers = asList(evidence.suggested_solvers);
      const tools = asList(evidence.tool_hints);
      const actions = asList(evidence.next_actions);
      return `<div class="kv">
        <span>${escapeHtml(evidence.provider || obs.source || "LLMCritic")}</span>
        <strong>${escapeHtml(evidence.summary || obs.summary || "Post-run critic")}</strong>
        ${blockers.length ? `<div class="meta">卡点：${blockers.map(escapeHtml).join("；")}</div>` : ""}
        ${missing.length ? `<div class="meta">缺失证据：${missing.map(escapeHtml).join("；")}</div>` : ""}
        ${solvers.length ? `<div class="meta">建议 solver：${solvers.map(escapeHtml).join(", ")}</div>` : ""}
        ${tools.length ? `<div class="meta">工具路线：${tools.map(escapeHtml).join(", ")}</div>` : ""}
        ${actions.length ? `<div class="meta">下一轮：${actions.map(escapeHtml).join("；")}</div>` : ""}
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
        ${sections.length ? "" : `<div class="empty-state">还没有可展示的解题思路和复现步骤。</div>`}`;
    }
    function orderedWriteupSections(sections) {
      const allowed = new Map(sections.filter(section => writeupSectionOrder.includes(section.title)).map(section => [section.title, section]));
      return writeupSectionOrder.map(title => allowed.get(title)).filter(Boolean);
    }
    function renderToolRows(data, title, kind) {
      if (kind === "tool" && data && !Array.isArray(data) && (data.wrappers || data.catalog)) {
        const wrappers = asList(data.wrappers);
        const catalog = asList(data.catalog);
        const counts = data.counts || {};
        const smoke = data.runtime_smoke || {};
        return `
          <div class="result-card">
            <div class="card-head">
              <div class="card-title">
                <h3>工具总览</h3>
                <div class="meta">${escapeHtml(counts.available_wrappers ?? 0)} / ${escapeHtml(counts.wrappers ?? wrappers.length)} wrappers available · ${escapeHtml(counts.catalog ?? catalog.length)} catalog entries</div>
                <div class="meta">推荐 CTF 工具目录已按分类折叠，展开分组查看明细。</div>
              </div>
              <span class="badge muted">host/docker</span>
            </div>
            <div class="kv-grid">
              <div class="kv"><span>Host</span><strong>${escapeHtml(counts.host_wrappers ?? wrappers.filter(row => row.source === "host").length)}</strong></div>
              <div class="kv"><span>Docker</span><strong>${escapeHtml(counts.docker_wrappers ?? wrappers.filter(row => row.source === "docker").length)}</strong></div>
              <div class="kv"><span>Missing</span><strong>${escapeHtml(counts.missing_wrappers ?? wrappers.filter(row => row.source === "missing").length)}</strong></div>
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
          ${renderToolGroups(wrappers, catalog)}
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
            const name = row.name || row.tool || "entry";
            const badge = kind === "tool" ? (row.available ? "available" : "missing") : (row.integration || row.category || "catalog");
            const badgeClass = badge === "missing" ? "badge warn" : "badge muted";
            const categories = row.categories ? row.categories.join(", ") : (row.category || "");
            const description = row.description || row.purpose || row.notes || "";
            const install = row.install_hint ? `<div class="meta">Install: ${escapeHtml(row.install_hint)}</div>` : "";
            const source = kind === "tool" && row.source ? `<div class="meta">Source: ${escapeHtml(row.source)}</div>` : "";
            return `<div class="kv">
              <span>${escapeHtml(categories || row.integration || "")}</span>
              <strong>${escapeHtml(name)}</strong>
              <div class="meta">${escapeHtml(description)}</div>
              ${row.why ? `<div class="meta">${escapeHtml(row.why)}</div>` : ""}
              ${source}
              ${install}
              <span class="${badgeClass}">${escapeHtml(badge)}</span>
            </div>`;
          }).join("")}
        </div>`;
    }
    function renderToolGroups(wrappers, catalog) {
      const wrapperGroups = [
        ["Host wrappers", wrappers.filter(row => row.source === "host"), "本机可直接调用"],
        ["Docker wrappers", wrappers.filter(row => row.source === "docker"), "通过容器自动 fallback"],
        ["Missing wrappers", wrappers.filter(row => row.source === "missing"), "当前不可调用"]
      ];
      const wrapperHtml = wrapperGroups.map(([title, rows, note]) => renderToolGroup(title, rows, "tool", note, rows.length > 0 && title === "Missing wrappers")).join("");
      const catalogGroups = groupRows(catalog, row => (row.categories && row.categories[0]) || row.category || "other");
      const catalogHtml = groupOrder(catalogGroups, categories).map(category => {
        const rows = catalogGroups[category] || [];
        return renderToolGroup(`Catalog: ${categoryLabels[category] || category}`, rows, "catalog", "推荐工具目录", false);
      }).join("");
      return wrapperHtml + catalogHtml;
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
    async function saveChallenge() {
      const payload = {
        challenge_id: $("challengeId").value.trim(),
        category: $("category").value,
        title: $("title").value.trim(),
        target: $("target").value.trim(),
        description: $("description").value.trim(),
        tags: $("tags").value,
        attachments: await filesPayload()
      };
      const res = await api("/api/challenges", { method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify(payload) });
      state.selected = payload.challenge_id;
      state.activeCategory = payload.category || state.activeCategory;
      state.activeStatus = "all";
      show(res, "raw");
      await refresh();
      return res;
    }
    async function runSelected() {
      if (!state.selected) {
        status("请先选择一道题目", "error");
        return false;
      }
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
      if (tab === "tools") return show(await api("/api/tools"), "tools");
      if (tab === "catalog") return show(await api("/api/project-catalog"), "catalog");
      if (!state.selected) return status("请先选择一道题目", "error");
      if (tab === "summary") return show(await loadLatestSummary(), "summary");
      if (tab === "agent") return show(await loadAgentView(), "agent");
      show(await api(`/api/challenges/${encodeURIComponent(state.selected)}/${tab}`), tab);
    }
    async function loadLatestSummary() {
      if (!state.selected) return state.lastSummary || {};
      const summary = await api(`/api/challenges/${encodeURIComponent(state.selected)}/summary`);
      state.lastSummary = summary;
      state.summaries[state.selected] = summary;
      return summary;
    }
    async function loadAgentView() {
      const challenge = encodeURIComponent(state.selected);
      const [summary, report, findings, observations] = await Promise.all([
        api(`/api/challenges/${challenge}/summary`),
        api(`/api/challenges/${challenge}/report`),
        api(`/api/challenges/${challenge}/findings`),
        api(`/api/challenges/${challenge}/observations`)
      ]);
      state.lastSummary = summary;
      state.summaries[state.selected] = summary;
      return { challenge_id: state.selected, summary, report, findings, observations };
    }
    $("saveBtn").onclick = () => withButtonFeedback("saveBtn", "保存中...", "题目已保存", saveChallenge).catch(e => show({error:e.message}));
    $("refreshBtn").onclick = () => withButtonFeedback("refreshBtn", "刷新中...", "列表已刷新", refresh).catch(e => show({error:e.message}));
    $("deleteBtn").onclick = () => deleteSelectedChallenge().catch(e => { setButtonBusy("deleteBtn", false); status("删除失败", "error"); show({error:e.message}); });
    $("clearBtn").onclick = () => clearChallenges().catch(e => { setButtonBusy("clearBtn", false); status("清空失败", "error"); show({error:e.message}); });
    $("runBtn").onclick = () => runSelected().catch(e => { setRunState(false, "运行失败", "error"); show({error:e.message}); });
    $("llmSaveConfig").onclick = () => saveLLMConfig();
    $("llmTestBtn").onclick = () => withButtonFeedback("llmTestBtn", "测试中...", "", testLLM).catch(e => { $("llmConfigStatus").textContent = "测试失败"; show({error:e.message}); });
    $("llmEnabled").onchange = syncLLMSettings;
    $("llmProvider").onchange = () => { if ($("llmProvider").value === "disabled") $("llmEnabled").checked = false; syncLLMSettings(); };
    document.querySelectorAll(".tabs button").forEach(btn => btn.onclick = () => loadTab(btn.dataset.tab).catch(e => show({error:e.message})));
    restoreLLMConfig();
    refresh().catch(e => show({error:e.message}));
  </script>
</body>
</html>
"""

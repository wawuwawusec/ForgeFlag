from __future__ import annotations

import base64
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from forgeflag.artifacts import ArtifactWorkspace
from forgeflag.domain import Challenge, ChallengeCategory, LLMConfig, RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
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
                self._send_json(ToolRunner(ScopePolicy()).inventory())
                return
            challenge_id, suffix = _challenge_route(path)
            if challenge_id and suffix == "findings":
                self._send_json(self.handle_findings(challenge_id))
                return
            if challenge_id and suffix == "observations":
                self._send_json(self.handle_observations(challenge_id))
                return
            if challenge_id and suffix == "report":
                self._send_json(self.handle_report(challenge_id))
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
                challenge_id, suffix = _challenge_route(path)
                if challenge_id and suffix == "run":
                    self._send_json(self.handle_run_challenge(challenge_id, payload))
                    return
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except Exception as exc:  # noqa: BLE001 - API should return JSON errors to the UI.
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        @classmethod
        def handle_list_challenges(cls) -> list[dict[str, Any]]:
            return [
                {
                    "challenge_id": challenge.challenge_id,
                    "category": challenge.category.value,
                    "title": challenge.title,
                    "target": challenge.target,
                    "description": challenge.description,
                    "tags": list(challenge.tags),
                    "attachment_paths": list(challenge.attachment_paths),
                }
                for challenge in cls.notebook.list_challenges()
            ]

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
        def handle_report(cls, challenge_id: str) -> dict[str, Any]:
            summary = cls.notebook.latest_run_summary(challenge_id)
            return (summary or {}).get("replay_report") or {}

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
        model=_optional_string(payload.get("llm_model")) or base.model,
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
    button { border: 1px solid #0f5d4c; background: var(--accent); color: white; border-radius: 6px; padding: 9px 12px; font: inherit; cursor: pointer; }
    button.secondary { background: white; color: var(--ink); border-color: var(--line); }
    button.warn { background: var(--warn); border-color: var(--warn); }
    .row { display: flex; gap: 8px; align-items: center; }
    .row > * { flex: 1; }
    .actions { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
    .run-panel { display: grid; gap: 10px; border-bottom: 1px solid var(--line); padding-bottom: 16px; }
    .runtime-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .inline-check { display: flex; align-items: center; gap: 8px; margin: 0; color: var(--ink); }
    .inline-check input { width: auto; }
    .llm-settings { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .llm-settings[hidden] { display: none; }
    .category-bar { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin: 12px 0 16px; }
    .category-pill { background: white; color: var(--ink); border-color: var(--line); display: flex; justify-content: space-between; align-items: center; padding: 8px 10px; }
    .category-pill.active { background: var(--accent); color: white; border-color: var(--accent); }
    .category-pill span:last-child { font-size: 12px; opacity: .85; }
    .list { display: grid; gap: 8px; margin-top: 12px; }
    .item { border: 1px solid var(--line); background: white; border-radius: 6px; padding: 10px; cursor: pointer; }
    .item.active { border-color: var(--accent); box-shadow: inset 3px 0 0 var(--accent); }
    .meta { color: var(--muted); font-size: 12px; margin-top: 4px; overflow-wrap: anywhere; }
    .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--line); margin-bottom: 14px; }
    .tabs button { background: white; color: var(--ink); border-color: var(--line); border-bottom: 0; border-radius: 6px 6px 0 0; }
    .tabs button.active { background: var(--accent); color: white; }
    pre { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; background: #111820; color: #e7eef4; border-radius: 6px; padding: 14px; min-height: 420px; }
    .status { font-size: 13px; color: var(--muted); }
    @media (max-width: 860px) { main { grid-template-columns: 1fr; } aside { border-right: 0; border-bottom: 1px solid var(--line); } .runtime-grid, .llm-settings { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <h1>ForgeFlag Console</h1>
    <div class="status" id="status">ready</div>
  </header>
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
      </div>
      <h2 style="margin-top:22px">分类工作台</h2>
      <div class="category-bar" id="categoryFilters"></div>
      <div class="meta" id="categoryCounts"></div>
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
        </div>
      </div>
      <div class="tabs" style="margin-top:18px">
        <button class="active" data-tab="summary">Summary</button>
        <button data-tab="findings">Findings</button>
        <button data-tab="observations">Observations</button>
        <button data-tab="report">Report</button>
        <button data-tab="tools">Tools</button>
      </div>
      <pre id="output">{}</pre>
    </section>
  </main>
  <script>
    const categories = ["unknown","web","pwn","reverse","crypto","forensics","traffic","misc","infra"];
    const categoryLabels = { all:"全部", unknown:"未知", web:"Web", pwn:"Pwn", reverse:"Reverse", crypto:"Crypto", forensics:"Forensics", traffic:"Traffic", misc:"Misc", infra:"Infra" };
    const state = { selected: null, activeCategory: "all", challenges: [], lastSummary: {} };
    const $ = (id) => document.getElementById(id);
    const status = (text) => $("status").textContent = text;
    const show = (data) => $("output").textContent = JSON.stringify(data, null, 2);
    categories.forEach(c => { const o = document.createElement("option"); o.value = c; o.textContent = c; $("category").appendChild(o); });
    function syncLLMSettings() {
      $("llmSettings").hidden = !$("llmEnabled").checked;
      if ($("llmEnabled").checked && $("llmProvider").value === "disabled") $("llmProvider").value = "zhipu";
      const zhipu = $("llmProvider").value === "zhipu";
      $("llmModel").placeholder = zhipu ? "glm-4.7" : "gpt-4.1";
      $("llmApiKey").placeholder = zhipu ? "ZAI_API_KEY" : "sk-...";
      $("llmBaseUrl").placeholder = zhipu ? "https://open.bigmodel.cn/api/paas/v4" : "https://api.openai.com/v1";
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
        };
        filters.appendChild(btn);
      });
      $("categoryCounts").textContent = `当前分类：${categoryLabels[state.activeCategory] || state.activeCategory}，题目数：${counts[state.activeCategory] || 0}`;
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
      renderChallengeList();
      show(challenges);
    }
    function renderChallengeList() {
      const list = $("challengeList");
      list.innerHTML = "";
      const visible = state.challenges.filter(ch => state.activeCategory === "all" || ch.category === state.activeCategory);
      visible.forEach(ch => {
        const item = document.createElement("div");
        item.className = "item" + (state.selected === ch.challenge_id ? " active" : "");
        item.innerHTML = `<strong>${ch.challenge_id}</strong><div class="meta">${ch.category} ${ch.target || ""}</div><div class="meta">${(ch.attachment_paths||[]).join(", ")}</div>`;
        item.onclick = () => { state.selected = ch.challenge_id; refresh(); loadTab(document.querySelector(".tabs button.active").dataset.tab); };
        list.appendChild(item);
      });
    }
    async function saveChallenge() {
      status("saving...");
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
      status("saved");
      show(res);
      await refresh();
    }
    async function runSelected() {
      if (!state.selected) return status("select a challenge first");
      status("running...");
      const llmEnabled = $("llmEnabled").checked;
      const payload = {
        active_probe: $("activeProbe").checked,
        allowed_hosts: $("allowedHosts").value,
        llm_enabled: llmEnabled,
        llm_provider: llmEnabled ? $("llmProvider").value : "disabled",
        llm_model: $("llmModel").value.trim(),
        llm_api_key: $("llmApiKey").value.trim(),
        llm_base_url: $("llmBaseUrl").value.trim(),
        llm_timeout_seconds: $("llmTimeout").value
      };
      const res = await api(`/api/challenges/${encodeURIComponent(state.selected)}/run`, { method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify(payload) });
      state.lastSummary = res;
      status(res.status || "done");
      show(res);
    }
    async function loadTab(tab) {
      document.querySelectorAll(".tabs button").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === tab));
      if (tab === "summary") return show(state.lastSummary);
      if (tab === "tools") return show(await api("/api/tools"));
      if (!state.selected) return status("select a challenge first");
      show(await api(`/api/challenges/${encodeURIComponent(state.selected)}/${tab}`));
    }
    $("saveBtn").onclick = () => saveChallenge().catch(e => { status("error"); show({error:e.message}); });
    $("refreshBtn").onclick = () => refresh().catch(e => show({error:e.message}));
    $("runBtn").onclick = () => runSelected().catch(e => { status("error"); show({error:e.message}); });
    $("llmEnabled").onchange = syncLLMSettings;
    $("llmProvider").onchange = () => { if ($("llmProvider").value === "disabled") $("llmEnabled").checked = false; syncLLMSettings(); };
    document.querySelectorAll(".tabs button").forEach(btn => btn.onclick = () => loadTab(btn.dataset.tab).catch(e => show({error:e.message})));
    syncLLMSettings();
    refresh().catch(e => show({error:e.message}));
  </script>
</body>
</html>
"""

from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from forgeflag.domain import ToolResult
from forgeflag.safety import ScopePolicy


class HttpProbeTool:
    name = "http_probe"

    def __init__(self, scope: ScopePolicy, timeout_seconds: int = 8) -> None:
        self.scope = scope
        self.timeout_seconds = timeout_seconds

    def run(self, target: str) -> ToolResult:
        self.scope.require_active_allowed(target)
        request = Request(target, headers={"User-Agent": "ForgeFlag/0.1 CTF-Agent"})
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read(4096)
                content_type = response.headers.get("content-type", "")
                status_code = response.status
        except HTTPError as exc:
            body = exc.read(4096)
            content_type = exc.headers.get("content-type", "")
            status_code = exc.code
        except URLError as exc:
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                evidence=[f"network error: {exc.reason}"],
            )

        hints = []
        text = body.decode("utf-8", errors="ignore").lower()
        if "<form" in text:
            hints.append("html form detected; route to WebSolver")
        if "flag{" in text or "ctf{" in text:
            hints.append("possible flag-like token in first response bytes")

        return ToolResult(
            tool=self.name,
            target=target,
            status="success",
            evidence=[f"http_status={status_code}", f"content_type={content_type}", f"bytes_sampled={len(body)}"],
            next_hints=hints,
            raw={"status_code": status_code, "content_type": content_type, "sample": body.decode("utf-8", errors="ignore")},
        )


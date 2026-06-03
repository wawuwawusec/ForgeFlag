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
                headers = _bounded_headers(response.headers.items())
        except HTTPError as exc:
            body = exc.read(4096)
            content_type = exc.headers.get("content-type", "")
            status_code = exc.code
            headers = _bounded_headers(exc.headers.items())
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
        header_text = _headers_text(headers).lower()
        if "flag{" in header_text or "ctf{" in header_text:
            hints.append("possible flag-like token in response headers or cookies")

        return ToolResult(
            tool=self.name,
            target=target,
            status="success",
            evidence=[f"http_status={status_code}", f"content_type={content_type}", f"bytes_sampled={len(body)}"],
            next_hints=hints,
            raw={
                "status_code": status_code,
                "content_type": content_type,
                "headers": headers,
                "set_cookie_names": _set_cookie_names(headers),
                "sample": body.decode("utf-8", errors="ignore"),
            },
        )


def _bounded_headers(items: object, limit: int = 40, value_limit: int = 500) -> dict[str, str]:
    headers: dict[str, str] = {}
    for index, (name, value) in enumerate(items):
        if index >= limit:
            break
        headers[str(name)] = str(value)[:value_limit]
    return headers


def _headers_text(headers: dict[str, str]) -> str:
    return "\n".join(f"{name}: {value}" for name, value in headers.items())


def _set_cookie_names(headers: dict[str, str]) -> list[str]:
    names: list[str] = []
    for name, value in headers.items():
        if name.lower() != "set-cookie":
            continue
        cookie_name = value.split("=", 1)[0].strip()
        if cookie_name:
            names.append(cookie_name)
    return names

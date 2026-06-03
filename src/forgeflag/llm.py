from __future__ import annotations

from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
import json
import random
import threading
import time
from typing import Any, Protocol
from urllib import request
from urllib.error import HTTPError

from forgeflag.domain import LLMConfig


@dataclass(frozen=True)
class LLMResponse:
    content: str
    raw: dict[str, Any] = field(default_factory=dict)


class LLMProvider(Protocol):
    name: str
    model: str | None
    enabled: bool

    def generate(self, instructions: str, prompt: str) -> LLMResponse:
        ...


class DisabledLLMProvider:
    name = "disabled"
    model = None
    enabled = False

    def generate(self, instructions: str, prompt: str) -> LLMResponse:
        return LLMResponse(content="", raw={"status": "disabled"})


class UnavailableLLMProvider:
    enabled = True

    def __init__(self, name: str, model: str | None, error: str) -> None:
        self.name = name
        self.model = model
        self.error = error

    def generate(self, instructions: str, prompt: str) -> LLMResponse:
        return LLMResponse(
            content=f"LLM planning unavailable: {self.error}",
            raw={"status": "unavailable", "error": self.error},
        )


class OpenAIResponsesProvider:
    name = "openai"

    def __init__(self, config: LLMConfig) -> None:
        if not config.api_key:
            raise ValueError("OPENAI_API_KEY or FORGEFLAG_LLM_API_KEY is required for provider=openai")
        if not config.model:
            raise ValueError("FORGEFLAG_LLM_MODEL is required for provider=openai")
        self.config = config
        self.model = config.model
        self.enabled = True

    def generate(self, instructions: str, prompt: str) -> LLMResponse:
        payload = {
            "model": self.config.model,
            "instructions": instructions,
            "input": prompt,
        }
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.config.base_url.rstrip('/')}/responses",
            data=data,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
        )
        with _open_llm_request(req, self.config, _cooldown_key(self.name, self.config.model, req.full_url)) as response:
            raw = json.loads(response.read().decode("utf-8"))
        return LLMResponse(content=_extract_output_text(raw), raw=raw)


class ZhipuChatCompletionsProvider:
    name = "zhipu"

    def __init__(self, config: LLMConfig) -> None:
        if not config.api_key:
            raise ValueError("ZAI_API_KEY, ZHIPU_API_KEY, or FORGEFLAG_LLM_API_KEY is required for provider=zhipu")
        if not config.model:
            raise ValueError("FORGEFLAG_LLM_MODEL is required for provider=zhipu")
        self.config = config
        self.base_url = (
            "https://open.bigmodel.cn/api/paas/v4"
            if config.base_url == "https://api.openai.com/v1"
            else config.base_url
        )
        self.model = config.model
        self.enabled = True

    def generate(self, instructions: str, prompt: str) -> LLMResponse:
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": instructions},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = request.Request(
            f"{self.base_url.rstrip('/')}/chat/completions",
            data=data,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
        )
        with _open_llm_request(req, self.config, _cooldown_key(self.name, self.config.model, req.full_url)) as response:
            raw = json.loads(response.read().decode("utf-8"))
        return LLMResponse(content=_extract_chat_completion_text(raw), raw=raw)


def build_llm_provider(config: LLMConfig) -> LLMProvider:
    if not config.enabled:
        return DisabledLLMProvider()
    if config.provider == "openai":
        return OpenAIResponsesProvider(config)
    if config.provider == "zhipu":
        return ZhipuChatCompletionsProvider(config)
    raise ValueError(f"unknown LLM provider: {config.provider}")


_REQUEST_LOCK = threading.Lock()
_COOLDOWNS: dict[str, float] = {}


def _open_llm_request(req: request.Request, config: LLMConfig, cooldown_key: str) -> Any:
    attempts = max(1, config.max_retries + 1)
    last_error: RuntimeError | None = None
    with _REQUEST_LOCK:
        for attempt in range(attempts):
            _raise_if_cooling_down(cooldown_key)
            try:
                return request.urlopen(req, timeout=config.timeout_seconds)
            except HTTPError as exc:
                status = int(exc.code or 0)
                body = _read_http_error_body(exc)
                if not _should_retry_http_error(status, body) or attempt >= attempts - 1:
                    if status == 429:
                        _enter_cooldown(cooldown_key, config.cooldown_seconds)
                    raise _llm_http_error(status, body, config, cooldown_key) from exc
                delay = _retry_delay(exc, attempt, config)
                last_error = _llm_http_error(status, body, config, cooldown_key)
                if delay > 0:
                    time.sleep(delay)
        if last_error is not None:
            raise last_error
        raise RuntimeError("LLM request failed before it could be sent")


def _cooldown_key(provider: str, model: str | None, url: str) -> str:
    return f"{provider}:{model or '-'}:{url}"


def _raise_if_cooling_down(cooldown_key: str) -> None:
    until = _COOLDOWNS.get(cooldown_key, 0)
    remaining = int(max(0, until - time.monotonic()))
    if remaining > 0:
        raise RuntimeError(f"LLM provider cooling down after rate limit; retry after {remaining}s")


def _enter_cooldown(cooldown_key: str, cooldown_seconds: int) -> None:
    if cooldown_seconds <= 0:
        return
    _COOLDOWNS[cooldown_key] = time.monotonic() + cooldown_seconds


def _read_http_error_body(exc: HTTPError) -> str:
    try:
        data = exc.read()
    except Exception:  # noqa: BLE001 - error formatting should not hide the HTTP status.
        return ""
    if not data:
        return ""
    try:
        return data.decode("utf-8", errors="replace")
    except AttributeError:
        return str(data)


def _should_retry_http_error(status: int, body: str) -> bool:
    if status in {500, 502, 503, 504}:
        return True
    if status != 429:
        return False
    lowered = body.lower()
    non_retryable_markers = (
        "insufficient",
        "balance",
        "billing",
        "quota exhausted",
        "account exception",
        "account abnormal",
        "余额",
        "欠费",
        "账户异常",
    )
    return not any(marker in lowered for marker in non_retryable_markers)


def _retry_delay(exc: HTTPError, attempt: int, config: LLMConfig) -> int:
    retry_after = _retry_after_seconds(exc.headers.get("Retry-After") if exc.headers else None)
    if retry_after is not None:
        return min(config.retry_max_seconds, max(0, retry_after))
    base = max(0, config.retry_initial_seconds)
    if base <= 0:
        return 0
    jitter = random.uniform(0, min(0.5, base / 2))
    return min(config.retry_max_seconds, int(base * (2**attempt) + jitter))


def _retry_after_seconds(value: str | None) -> int | None:
    if not value:
        return None
    stripped = value.strip()
    try:
        return max(0, int(float(stripped)))
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(stripped)
    except (TypeError, ValueError):
        return None
    return max(0, int(parsed.timestamp() - time.time()))


def _llm_http_error(status: int, body: str, config: LLMConfig, cooldown_key: str) -> RuntimeError:
    cleaned = _compact_error_body(body)
    detail = f": {cleaned}" if cleaned else ""
    cooldown = f"; cooling down {config.cooldown_seconds}s" if status == 429 and config.cooldown_seconds > 0 else ""
    return RuntimeError(f"LLM HTTP {status} rate limit/error for {cooldown_key}{detail}{cooldown}")


def _compact_error_body(body: str) -> str:
    if not body:
        return ""
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return body[:300]
    if isinstance(parsed, dict):
        error = parsed.get("error")
        if isinstance(error, dict):
            message = error.get("message") or error.get("msg") or error.get("code")
            if message:
                return str(message)[:300]
        message = parsed.get("message") or parsed.get("msg") or parsed.get("code")
        if message:
            return str(message)[:300]
    return body[:300]


def _extract_output_text(raw: dict[str, Any]) -> str:
    output_text = raw.get("output_text")
    if isinstance(output_text, str):
        return output_text

    texts: list[str] = []
    for item in raw.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text":
                text = content.get("text")
                if isinstance(text, str):
                    texts.append(text)
    return "\n".join(texts).strip()


def _extract_chat_completion_text(raw: dict[str, Any]) -> str:
    texts: list[str] = []
    for choice in raw.get("choices", []):
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                texts.append(content)
    return "\n".join(texts).strip()

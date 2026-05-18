from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Protocol
from urllib import request

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
        with request.urlopen(req, timeout=self.config.timeout_seconds) as response:
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
        with request.urlopen(req, timeout=self.config.timeout_seconds) as response:
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

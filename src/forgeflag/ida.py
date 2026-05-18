from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from forgeflag.domain import IDAMCPConfig


@dataclass(frozen=True)
class IDAToolCall:
    name: str
    status: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IDAAnalysis:
    status: str
    tool_calls: tuple[IDAToolCall, ...] = ()
    function_names: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()
    notes: str | None = None


class IDAAdapter(Protocol):
    enabled: bool

    def analyze_binary(self, path: str, mode: str) -> IDAAnalysis:
        ...


class DisabledIDAAdapter:
    enabled = False

    def analyze_binary(self, path: str, mode: str) -> IDAAnalysis:
        return IDAAnalysis(status="disabled", notes="IDA MCP is disabled.")


class IDAMCPAdapter:
    enabled = True

    def __init__(self, config: IDAMCPConfig) -> None:
        self.config = config

    def analyze_binary(self, path: str, mode: str) -> IDAAnalysis:
        try:
            return asyncio.run(self._analyze_binary(path, mode))
        except Exception as exc:  # pragma: no cover - exercised only with a live external MCP server.
            return IDAAnalysis(
                status="error",
                tool_calls=(IDAToolCall(name="ida_mcp", status="error", evidence={"error": str(exc)}),),
                notes="IDA MCP call failed.",
            )

    async def _analyze_binary(self, path: str, mode: str) -> IDAAnalysis:
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:
            return IDAAnalysis(
                status="missing_dependency",
                tool_calls=(
                    IDAToolCall(
                        name="ida_mcp",
                        status="missing_dependency",
                        evidence={"error": str(exc), "install": "pip install -e '.[mcp]'"},
                    ),
                ),
                notes="The Python MCP client dependency is not installed.",
            )

        command, *args = self.config.command
        params = StdioServerParameters(command=command, args=list(args))
        resolved = str(Path(path).expanduser().resolve())
        calls: list[IDAToolCall] = []

        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await asyncio.wait_for(session.initialize(), timeout=self.config.timeout_seconds)
                available = await asyncio.wait_for(_available_tools(session), timeout=self.config.timeout_seconds)

                open_tool = _first_available(available, ("open_idb", "open_database", "open_binary"))
                if open_tool:
                    calls.append(await _call_tool(session, open_tool, {"path": resolved}, self.config.timeout_seconds))

                strings_tool = _first_available(available, ("strings", "list_strings", "get_strings"))
                strings: tuple[str, ...] = ()
                if strings_tool:
                    call = await _call_tool(session, strings_tool, {"limit": 80}, self.config.timeout_seconds)
                    calls.append(call)
                    strings = tuple(_collect_strings(call.evidence))[:80]

                functions_tool = _first_available(available, ("list_functions", "get_functions", "functions"))
                function_names: tuple[str, ...] = ()
                if functions_tool:
                    call = await _call_tool(session, functions_tool, {"limit": 80}, self.config.timeout_seconds)
                    calls.append(call)
                    function_names = tuple(dict.fromkeys(_collect_strings(call.evidence)))[:80]

                pivot_name = _pivot_function(function_names)
                if pivot_name:
                    disasm_tool = _first_available(available, ("disasm_by_name", "decompile", "decompile_function"))
                    if disasm_tool:
                        calls.append(
                            await _call_tool(
                                session,
                                disasm_tool,
                                {"name": pivot_name},
                                self.config.timeout_seconds,
                            )
                        )

        status = "success" if any(call.status == "success" for call in calls) else "no_supported_tools"
        return IDAAnalysis(status=status, tool_calls=tuple(calls), function_names=function_names, strings=strings)


def build_ida_adapter(config: IDAMCPConfig) -> IDAAdapter:
    if not config.enabled:
        return DisabledIDAAdapter()
    return IDAMCPAdapter(config)


async def _available_tools(session) -> set[str]:
    tools = await session.list_tools()
    return {tool.name for tool in getattr(tools, "tools", ())}


async def _call_tool(session, name: str, arguments: dict[str, Any], timeout: int) -> IDAToolCall:
    try:
        result = await asyncio.wait_for(session.call_tool(name, arguments), timeout=timeout)
    except Exception as exc:
        return IDAToolCall(name=name, status="error", evidence={"error": str(exc), "arguments": arguments})
    return IDAToolCall(name=name, status="success", evidence=_tool_result_payload(result))


def _tool_result_payload(result) -> dict[str, Any]:
    payload: dict[str, Any] = {"content": []}
    for item in getattr(result, "content", ()) or ():
        if hasattr(item, "model_dump"):
            payload["content"].append(item.model_dump())
        elif hasattr(item, "dict"):
            payload["content"].append(item.dict())
        else:
            payload["content"].append(str(item))
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        payload["structured"] = structured
    return payload


def _first_available(available: set[str], candidates: tuple[str, ...]) -> str | None:
    for candidate in candidates:
        if candidate in available:
            return candidate
    return None


def _collect_strings(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            found.extend(_collect_strings(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.extend(_collect_strings(item))
    return found


def _pivot_function(function_names: tuple[str, ...]) -> str | None:
    preferred = ("main", "check", "check_flag", "verify", "win", "vuln")
    lowered = {name.lower(): name for name in function_names}
    for needle in preferred:
        for lower_name, original in lowered.items():
            if needle in lower_name:
                return original
    return function_names[0] if function_names else None

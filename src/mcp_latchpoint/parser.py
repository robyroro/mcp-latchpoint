"""Parsers for supported MCP client configuration layouts."""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from mcp_latchpoint.jsonc import strip_jsonc
from mcp_latchpoint.model import NormalizedServer


class ConfigParseError(ValueError):
    """A safe parse error that never includes configuration content."""


class _DuplicateKeyError(ValueError):
    pass


class _InvalidConstantError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ParsedConfig:
    servers: tuple[NormalizedServer, ...]
    layout: str


def _is_jsonc_path(path: Path) -> bool:
    return path.suffix.lower() == ".jsonc" or (
        path.name.lower() == "mcp.json" and path.parent.name.lower() == ".vscode"
    )


def _read_bounded(path: Path, max_bytes: int) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ConfigParseError("cannot stat file") from exc
    if size > max_bytes:
        raise ConfigParseError(f"file exceeds the {max_bytes}-byte size limit")
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise ConfigParseError("cannot read file") from exc
    if len(data) > max_bytes:
        raise ConfigParseError(f"file exceeds the {max_bytes}-byte size limit")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigParseError("file is not valid UTF-8") from exc


def _layout_for_json(path: Path, data: dict[str, Any]) -> tuple[str, str]:
    lowered = [part.lower() for part in path.parts]
    if "servers" in data:
        return "vscode", "servers"
    if "mcpServers" not in data:
        raise ConfigParseError("no supported MCP server container found")
    if path.name == ".mcp.json":
        return "portable-mcp", "mcpServers"
    if ".cursor" in lowered:
        return "cursor", "mcpServers"
    if "claude" in lowered or path.name.lower() == "claude_desktop_config.json":
        return "claude-desktop", "mcpServers"
    return "generic-mcp-json", "mcpServers"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _invalid_constant(_value: str) -> NoReturn:
    raise _InvalidConstantError


def _string_map(value: object, field: str, invalid: list[str]) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        invalid.append(field)
        return {}
    result: dict[str, str] = {}
    for key, item in value.items():
        if isinstance(key, str) and isinstance(item, str):
            result[key] = item
        else:
            invalid.append(field)
    return result


def _normalize_entry(
    *, name: str, source: Path, layout: str, location: str, entry: object
) -> NormalizedServer:
    if not isinstance(entry, dict):
        return NormalizedServer(
            name=name,
            source=source,
            layout=layout,
            location=location,
            transport=None,
            command=None,
            args=(),
            url=None,
            env={},
            headers={},
            options={},
            invalid_fields=("server entry",),
        )

    invalid: list[str] = []
    command_value = entry.get("command")
    command = command_value if isinstance(command_value, str) else None
    if command_value is not None and command is None:
        invalid.append("command")

    args_value = entry.get("args", [])
    args: tuple[str, ...] = ()
    if isinstance(args_value, list) and all(isinstance(item, str) for item in args_value):
        args = tuple(args_value)
    elif args_value is not None:
        invalid.append("args")

    url_value = entry.get("url", entry.get("endpoint"))
    url = url_value if isinstance(url_value, str) else None
    if url_value is not None and url is None:
        invalid.append("url")

    transport_value = entry.get("type", entry.get("transport"))
    transport = transport_value.lower() if isinstance(transport_value, str) else None
    if transport_value is not None and transport is None:
        invalid.append("transport")

    headers_value = entry.get("headers", entry.get("http_headers"))
    known = {
        "command",
        "args",
        "url",
        "endpoint",
        "env",
        "headers",
        "http_headers",
        "env_http_headers",
        "type",
        "transport",
    }
    options = {str(key): value for key, value in entry.items() if key not in known}
    return NormalizedServer(
        name=name,
        source=source,
        layout=layout,
        location=location,
        transport=transport,
        command=command,
        args=args,
        url=url,
        env=_string_map(entry.get("env"), "env", invalid),
        headers=_string_map(headers_value, "headers", invalid),
        options=options,
        invalid_fields=tuple(sorted(set(invalid))),
    )


def _parse_json(path: Path, text: str) -> ParsedConfig:
    candidate = strip_jsonc(text) if _is_jsonc_path(path) else text
    try:
        data = json.loads(
            candidate,
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except json.JSONDecodeError as exc:
        raise ConfigParseError(f"invalid JSON at line {exc.lineno}, column {exc.colno}") from exc
    except _DuplicateKeyError as exc:
        raise ConfigParseError("JSON contains a duplicate object key") from exc
    except _InvalidConstantError as exc:
        raise ConfigParseError("JSON contains a non-standard numeric constant") from exc
    except RecursionError as exc:
        raise ConfigParseError("JSON nesting is too deep") from exc
    if not isinstance(data, dict):
        raise ConfigParseError("top-level value must be an object")
    if path.name.lower() == ".claude.json":
        return _parse_claude_code_user(path, data)
    layout, container_key = _layout_for_json(path, data)
    container = data.get(container_key)
    if not isinstance(container, dict):
        raise ConfigParseError(f"{container_key} must be an object")
    servers = tuple(
        _normalize_entry(
            name=str(name),
            source=path,
            layout=layout,
            location=f"/{container_key}/{_pointer_escape(str(name))}",
            entry=entry,
        )
        for name, entry in sorted(container.items(), key=lambda item: str(item[0]))
    )
    return ParsedConfig(servers=servers, layout=layout)


def _parse_claude_code_user(path: Path, data: dict[str, Any]) -> ParsedConfig:
    servers: list[NormalizedServer] = []
    top_level = data.get("mcpServers")
    if top_level is not None:
        if not isinstance(top_level, dict):
            raise ConfigParseError("mcpServers must be an object")
        servers.extend(
            _normalize_entry(
                name=str(name),
                source=path,
                layout="claude-code",
                location=f"/mcpServers/{_pointer_escape(str(name))}",
                entry=entry,
            )
            for name, entry in sorted(top_level.items(), key=lambda item: str(item[0]))
        )

    projects = data.get("projects")
    if projects is not None and not isinstance(projects, dict):
        raise ConfigParseError("projects must be an object")
    if isinstance(projects, dict):
        for project, project_data in sorted(projects.items(), key=lambda item: str(item[0])):
            if not isinstance(project_data, dict) or "mcpServers" not in project_data:
                continue
            container = project_data["mcpServers"]
            if not isinstance(container, dict):
                raise ConfigParseError("project mcpServers must be an object")
            project_pointer = _pointer_escape(str(project))
            servers.extend(
                _normalize_entry(
                    name=str(name),
                    source=path,
                    layout="claude-code",
                    location=(
                        f"/projects/{project_pointer}/mcpServers/{_pointer_escape(str(name))}"
                    ),
                    entry=entry,
                )
                for name, entry in sorted(container.items(), key=lambda item: str(item[0]))
            )
    if top_level is None and not servers:
        raise ConfigParseError("no supported MCP server container found")
    return ParsedConfig(servers=tuple(servers), layout="claude-code")


def _parse_toml(path: Path, text: str) -> ParsedConfig:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigParseError("invalid TOML") from exc
    except RecursionError as exc:
        raise ConfigParseError("TOML nesting is too deep") from exc
    container = data.get("mcp_servers")
    if not isinstance(container, dict):
        raise ConfigParseError("mcp_servers must be a table")
    servers = tuple(
        _normalize_entry(
            name=str(name),
            source=path,
            layout="codex",
            location=f"mcp_servers.{name}",
            entry=entry,
        )
        for name, entry in sorted(container.items(), key=lambda item: str(item[0]))
    )
    return ParsedConfig(servers=servers, layout="codex")


def _pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def parse_config(path: Path, max_bytes: int) -> ParsedConfig:
    text = _read_bounded(path, max_bytes)
    if path.suffix.lower() == ".toml":
        return _parse_toml(path, text)
    if path.suffix.lower() in {".json", ".jsonc"}:
        return _parse_json(path, text)
    raise ConfigParseError("unsupported file type; expected JSON, JSONC, or TOML")

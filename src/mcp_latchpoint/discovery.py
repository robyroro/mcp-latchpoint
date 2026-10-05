"""Known MCP configuration locations. Discovery checks these paths only."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _environment_path(environ: dict[str, str], name: str, fallback: Path) -> Path:
    value = environ.get(name)
    return Path(value) if value else fallback


def candidate_paths(
    *,
    home: Path | None = None,
    cwd: Path | None = None,
    platform: str | None = None,
    environ: dict[str, str] | None = None,
) -> tuple[Path, ...]:
    home = home or Path.home()
    cwd = cwd or Path.cwd()
    platform = platform or sys.platform
    environ = environ or dict(os.environ)
    paths = [
        home / ".claude.json",
        home / ".cursor" / "mcp.json",
        home / ".codex" / "config.toml",
        cwd / ".mcp.json",
        cwd / ".codex" / "config.toml",
        cwd / ".cursor" / "mcp.json",
        cwd / ".vscode" / "mcp.json",
    ]
    copilot_home = _environment_path(environ, "COPILOT_HOME", home / ".copilot")
    paths.append(copilot_home / "mcp-config.json")
    if platform == "win32":
        appdata = _environment_path(environ, "APPDATA", home / "AppData" / "Roaming")
        paths.extend(
            [
                appdata / "Claude" / "claude_desktop_config.json",
                appdata / "Code" / "User" / "mcp.json",
            ]
        )
    elif platform == "darwin":
        support = home / "Library" / "Application Support"
        paths.extend(
            [
                support / "Claude" / "claude_desktop_config.json",
                support / "Code" / "User" / "mcp.json",
            ]
        )
    else:
        config = _environment_path(environ, "XDG_CONFIG_HOME", home / ".config")
        paths.append(config / "Code" / "User" / "mcp.json")
    return tuple(sorted(set(paths), key=lambda item: str(item)))


def discover_existing(
    *,
    home: Path | None = None,
    cwd: Path | None = None,
    platform: str | None = None,
    environ: dict[str, str] | None = None,
) -> tuple[Path, ...]:
    candidates = candidate_paths(home=home, cwd=cwd, platform=platform, environ=environ)
    return tuple(path for path in candidates if path.is_file())

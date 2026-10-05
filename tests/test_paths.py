from __future__ import annotations

import os
from pathlib import Path

import pytest

from mcp_latchpoint.discovery import candidate_paths
from mcp_latchpoint.scanner import PathPolicyError, ScanOptions, enforce_containment, scan_paths


def test_path_inside_root_is_accepted(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    config = root / "mcp.json"
    config.write_text('{"mcpServers":{}}', encoding="utf-8")

    assert enforce_containment(config, (root,)) == config.resolve()


def test_traversal_outside_root_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"mcpServers":{}}', encoding="utf-8")

    with pytest.raises(PathPolicyError, match="outside"):
        enforce_containment(root / ".." / "outside.json", (root,))


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"mcpServers":{}}', encoding="utf-8")
    link = root / "mcp.json"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks are not available: {exc}")

    report = scan_paths([link], options=ScanOptions(allowed_roots=(root,)))

    assert not report.scanned_files
    assert report.errors[0].message == "path is outside the allowed roots"


def test_directory_scan_ignores_unrecognized_files(tmp_path: Path) -> None:
    recognized = tmp_path / "mcp.json"
    ignored = tmp_path / "notes.json"
    recognized.write_text('{"mcpServers":{}}', encoding="utf-8")
    ignored.write_text('{"mcpServers":{"x":{"url":"http://bad.example"}}}', encoding="utf-8")

    report = scan_paths([tmp_path])

    assert report.scanned_files == [recognized.resolve()]


def test_discovery_candidates_are_exact_and_platform_specific(tmp_path: Path) -> None:
    home = tmp_path / "home"
    cwd = tmp_path / "project"
    appdata = tmp_path / "roaming"
    paths = candidate_paths(
        home=home,
        cwd=cwd,
        platform="win32",
        environ={"APPDATA": os.fspath(appdata)},
    )

    assert appdata / "Claude" / "claude_desktop_config.json" in paths
    assert cwd / ".vscode" / "mcp.json" in paths
    assert cwd / ".codex" / "config.toml" in paths
    assert home / ".codex" / "config.toml" in paths
    assert home / ".copilot" / "mcp-config.json" in paths
    assert all("Library" not in path.parts for path in paths)

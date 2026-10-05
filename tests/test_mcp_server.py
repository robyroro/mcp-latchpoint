from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from mcp_latchpoint.mcp_server import create_server


@pytest.mark.anyio
async def test_mcp_tools_list_rules_and_scan_without_raw_config(tmp_path: Path) -> None:
    secret = "mcp-tool-private-value"
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "url": "http://remote.example/mcp",
                        "env": {"API_TOKEN": secret},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    server = create_server(tmp_path)

    async with Client(server, raise_exceptions=True) as client:
        listed = await client.call_tool("list_rules", {})
        scanned = await client.call_tool("scan", {"path": "mcp.json"})

    assert listed.structured_content is not None
    assert len(listed.structured_content["rules"]) == 7
    assert scanned.structured_content is not None
    assert scanned.structured_content["summary"]["findings"] == 2
    assert secret not in json.dumps(scanned.structured_content)


@pytest.mark.anyio
async def test_mcp_scan_rejects_outside_path(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"mcpServers":{}}', encoding="utf-8")
    server = create_server(root)

    async with Client(server) as client:
        result = await client.call_tool("scan", {"path": str(outside)})

    assert result.is_error is True
    assert result.structured_content is None


@pytest.mark.anyio
async def test_mcp_scan_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"mcpServers":{}}', encoding="utf-8")
    link = root / "mcp.json"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks are not available: {exc}")
    server = create_server(root)

    async with Client(server) as client:
        result = await client.call_tool("scan", {"path": "mcp.json"})

    assert result.is_error is True


@pytest.mark.anyio
async def test_stdio_entrypoint_has_a_clean_protocol_stream(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers":{}}', encoding="utf-8")
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_latchpoint.mcp_server", "--root", str(tmp_path)],
    )

    async with Client(parameters) as client:
        listed = await client.list_tools()
        scanned = await client.call_tool("scan", {"path": "mcp.json"})

    assert {tool.name for tool in listed.tools} == {"list_rules", "scan"}
    assert scanned.is_error is False
    assert scanned.structured_content is not None
    assert scanned.structured_content["summary"]["files_scanned"] == 1

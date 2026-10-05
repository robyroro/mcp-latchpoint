"""Read-only MCP stdio server with a mandatory filesystem boundary."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

from mcp_latchpoint.rules import RULES
from mcp_latchpoint.scanner import DEFAULT_MAX_BYTES, ScanOptions, enforce_containment, scan_paths


def create_server(root: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> MCPServer:
    allowed_root = root.expanduser().resolve(strict=True)
    if not allowed_root.is_dir():
        raise ValueError("allowed root must be a directory")
    server = MCPServer(
        "mcp-latchpoint",
        instructions=(
            "Read-only static auditing of MCP configuration files. "
            "Only paths inside the configured root are accepted."
        ),
        log_level="WARNING",
    )

    @server.tool()
    def list_rules() -> dict[str, Any]:
        """List stable audit rule IDs, severity, descriptions, and remediation."""

        return {
            "rules": [rule.to_dict() for rule in RULES],
            "limitations": [
                "Rules use static configuration evidence only.",
                "No configured command is executed and no endpoint is contacted.",
            ],
        }

    @server.tool()
    def scan(path: str) -> dict[str, Any]:
        """Scan a config file or directory inside the server's allowed root."""

        requested = Path(path)
        if not requested.is_absolute():
            requested = allowed_root / requested
        resolved = enforce_containment(requested, (allowed_root,))
        report = scan_paths(
            [resolved],
            options=ScanOptions(allowed_roots=(allowed_root,), max_bytes=max_bytes),
        )
        return report.to_dict()

    return server


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-latchpoint-server",
        description="Run the read-only mcp-latchpoint stdio server.",
    )
    parser.add_argument("--root", required=True, type=Path, help="only scan inside this directory")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.max_bytes < 1:
        _parser().error("max-bytes must be positive")
    server = create_server(args.root, max_bytes=args.max_bytes)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

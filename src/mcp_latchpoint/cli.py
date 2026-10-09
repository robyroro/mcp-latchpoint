"""Command-line interface for mcp-latchpoint."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from mcp_latchpoint.model import SEVERITY_RANK, Finding, Severity
from mcp_latchpoint.output import report_json, report_sarif, report_text, rule_text, rules_text
from mcp_latchpoint.rules import RULE_INDEX, RULES
from mcp_latchpoint.scanner import DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES, ScanOptions, scan_paths


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-latchpoint",
        description="Audit MCP client configurations without executing them.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.1")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan explicit files or known config paths")
    scan.add_argument("paths", nargs="*", type=Path, help="config file or directory")
    scan.add_argument(
        "--discover",
        action="store_true",
        help="also check documented client config locations that exist",
    )
    scan.add_argument(
        "--allowed-root",
        action="append",
        default=[],
        type=Path,
        help="reject explicit paths outside this root; repeatable",
    )
    scan.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    scan.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument(
        "--fail-on",
        choices=("none", "info", "low", "medium", "high", "critical"),
        default="none",
        help="exit 1 when a finding at or above this severity exists",
    )

    rules = subparsers.add_parser("rules", help="list the built-in rules")
    rules.add_argument("--format", choices=("text", "json"), default="text")

    explain = subparsers.add_parser("explain", help="show one rule in detail")
    explain.add_argument("rule_id", help="stable rule ID, for example MCP001")
    explain.add_argument("--format", choices=("text", "json"), default="text")

    serve = subparsers.add_parser("serve", help="run the read-only MCP stdio server")
    serve.add_argument("--root", required=True, type=Path, help="only scan inside this directory")
    serve.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    return parser


def _scan_exit_code(report_findings: list[Finding], fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[Severity(fail_on)]
    return int(any(SEVERITY_RANK[finding.severity] >= threshold for finding in report_findings))


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "rules":
        if args.format == "json":
            sys.stdout.write(json.dumps([rule.to_dict() for rule in RULES], indent=2) + "\n")
        else:
            sys.stdout.write(rules_text())
        return 0
    if args.command == "explain":
        rule = RULE_INDEX.get(args.rule_id.upper())
        if rule is None:
            parser.error(f"unknown rule ID: {args.rule_id}")
        if args.format == "json":
            sys.stdout.write(json.dumps(rule.to_dict(), indent=2) + "\n")
        else:
            sys.stdout.write(rule_text(rule))
        return 0

    if args.command == "serve":
        from mcp_latchpoint.mcp_server import main as server_main

        return server_main(["--root", str(args.root), "--max-bytes", str(args.max_bytes)])

    if not args.paths and not args.discover:
        parser.error("scan requires at least one path or --discover")
    try:
        options = ScanOptions(
            allowed_roots=tuple(args.allowed_root),
            max_bytes=args.max_bytes,
            max_files=args.max_files,
        )
    except ValueError as exc:
        parser.error(str(exc))
    report = scan_paths(args.paths, options=options, discover=args.discover)
    renderer = {"text": report_text, "json": report_json, "sarif": report_sarif}[args.format]
    sys.stdout.write(renderer(report))
    if report.errors:
        return 2
    return _scan_exit_code(report.findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())

"""Read-only orchestration, containment, and deterministic result handling."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp_latchpoint.discovery import discover_existing
from mcp_latchpoint.model import Finding, ScanError, ScanReport
from mcp_latchpoint.parser import ConfigParseError, parse_config
from mcp_latchpoint.rules import evaluate

DEFAULT_MAX_BYTES = 1_048_576
DEFAULT_MAX_FILES = 256
_RECOGNIZED_NAMES = {
    ".mcp.json",
    "claude_desktop_config.json",
    "mcp.json",
    "mcp-config.json",
}


class PathPolicyError(ValueError):
    """A path violates an explicit read boundary."""


@dataclass(frozen=True, slots=True)
class ScanOptions:
    allowed_roots: tuple[Path, ...] = ()
    max_bytes: int = DEFAULT_MAX_BYTES
    max_files: int = DEFAULT_MAX_FILES

    def __post_init__(self) -> None:
        if self.max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        if self.max_files < 1:
            raise ValueError("max_files must be positive")


def _resolved(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PathPolicyError("path does not exist or cannot be resolved") from exc


def enforce_containment(path: Path, roots: tuple[Path, ...]) -> Path:
    resolved = _resolved(path)
    if not roots:
        return resolved
    resolved_roots = tuple(_resolved(root) for root in roots)
    if not any(resolved == root or resolved.is_relative_to(root) for root in resolved_roots):
        raise PathPolicyError("path is outside the allowed roots")
    return resolved


def _directory_files(directory: Path, roots: tuple[Path, ...], max_files: int) -> list[Path]:
    files: list[Path] = []
    for item in sorted(directory.rglob("*"), key=lambda path: str(path)):
        if item.is_symlink():
            try:
                resolved = enforce_containment(item, roots)
            except PathPolicyError:
                continue
            if not resolved.is_file():
                continue
        elif not item.is_file():
            continue
        if item.name.lower() not in _RECOGNIZED_NAMES and not (
            item.name.lower() == "config.toml" and item.parent.name.lower() == ".codex"
        ):
            continue
        files.append(enforce_containment(item, roots))
        if len(files) > max_files:
            raise PathPolicyError(f"directory contains more than {max_files} recognized files")
    return files


def _collect_files(paths: list[Path], options: ScanOptions) -> tuple[list[Path], list[ScanError]]:
    files: list[Path] = []
    errors: list[ScanError] = []
    for path in paths:
        try:
            resolved = enforce_containment(path, options.allowed_roots)
            if resolved.is_dir():
                files.extend(_directory_files(resolved, options.allowed_roots, options.max_files))
            elif resolved.is_file():
                files.append(resolved)
            else:
                raise PathPolicyError("path is not a regular file or directory")
        except PathPolicyError as exc:
            errors.append(ScanError(str(path), str(exc)))
    unique = sorted(set(files), key=lambda path: str(path))
    if len(unique) > options.max_files:
        errors.append(ScanError("<input>", f"more than {options.max_files} files were selected"))
        unique = unique[: options.max_files]
    return unique, errors


def scan_paths(
    paths: list[Path],
    *,
    options: ScanOptions | None = None,
    discover: bool = False,
) -> ScanReport:
    options = options or ScanOptions()
    selected = list(paths)
    if discover:
        selected.extend(discover_existing())
    files, errors = _collect_files(selected, options)
    findings: list[Finding] = []
    scanned: list[Path] = []
    for path in files:
        try:
            parsed = parse_config(path, options.max_bytes)
        except ConfigParseError as exc:
            errors.append(ScanError(str(path), str(exc)))
            continue
        scanned.append(path)
        for server in parsed.servers:
            findings.extend(evaluate(server))

    deduplicated = {finding.dedupe_key(): finding for finding in findings}
    ordered_findings = sorted(deduplicated.values(), key=Finding.sort_key)
    ordered_errors = sorted(errors, key=lambda error: (error.source, error.message))
    return ScanReport(
        findings=ordered_findings,
        scanned_files=sorted(scanned, key=lambda path: str(path)),
        errors=ordered_errors,
    )

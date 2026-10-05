"""Deterministic rules for normalized MCP server entries."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from pathlib import PureWindowsPath
from urllib.parse import parse_qsl, urlsplit

from mcp_latchpoint.model import Finding, NormalizedServer, RuleDefinition, Severity

RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        "MCP001",
        "Remote transport uses plain HTTP",
        Severity.HIGH,
        "A non-loopback MCP endpoint uses HTTP without transport encryption.",
        "Use HTTPS, or bind the service to a loopback address when it is intentionally local.",
    ),
    RuleDefinition(
        "MCP002",
        "Shell wrapper or inline shell command",
        Severity.HIGH,
        "The server launch uses a command shell or shell control syntax.",
        "Launch the executable directly and pass each argument as a separate array item.",
    ),
    RuleDefinition(
        "MCP003",
        "Package runner dependency is not pinned",
        Severity.MEDIUM,
        "An identifiable npx or uvx package does not use an exact version.",
        "Pin the package to an exact reviewed version and update it deliberately.",
    ),
    RuleDefinition(
        "MCP004",
        "Credential appears embedded in configuration",
        Severity.HIGH,
        "A credential-like environment, header, argument, or URL field contains a literal value.",
        "Store the secret outside the configuration and reference it through the client's "
        "supported secret mechanism.",
    ),
    RuleDefinition(
        "MCP005",
        "Broad filesystem root is exposed",
        Severity.HIGH,
        "A server argument or root option appears to expose a filesystem or home root.",
        "Grant the smallest dedicated directory needed by the server.",
    ),
    RuleDefinition(
        "MCP006",
        "Wildcard host or overbroad scope",
        Severity.MEDIUM,
        "A recognizable host, tool, or scope option allows every value or every interface.",
        "Replace wildcards and all-interface binds with explicit hosts, tools, or scopes.",
    ),
    RuleDefinition(
        "MCP007",
        "Ambiguous or invalid transport configuration",
        Severity.MEDIUM,
        "The entry has conflicting, unsupported, missing, or incorrectly typed transport fields.",
        "Choose one transport and use the fields required by that client layout.",
    ),
)

RULE_INDEX = {rule.rule_id: rule for rule in RULES}
_SECRET_KEY = re.compile(
    r"(?:^|[_-])"
    r"(secret|token|password|passwd|api[_-]?key|private[_-]?key|credential|authorization|cookie)"
    r"(?:$|[_-])",
    re.IGNORECASE,
)
_SENSITIVE_HEADER = re.compile(
    r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key)$", re.I
)
_ARG_SECRET = re.compile(
    r"^--?(?P<name>(?:api[-_]?key|token|secret|password|passwd|authorization|credential))",
    re.IGNORECASE,
)
_INLINE_SECRET = re.compile(
    r"--?(?P<name>(?:api[-_]?key|token|secret|password|passwd|authorization|credential))"
    r"(?:=|\s+)(?P<value>[^\s;&|]+)",
    re.IGNORECASE,
)
_EXACT_NPM = re.compile(
    r"^(?:@[a-z0-9_.-]+/[a-z0-9_.-]+|[a-z0-9_.-]+)@v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$",
    re.IGNORECASE,
)
_EXACT_UV = re.compile(
    r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==\d+(?:\.\d+)+(?:[A-Za-z0-9_.+-]*)$"
)
_INLINE_NPX = re.compile(
    r"(?:^|\s)npx(?:\.cmd)?(?:\s+(?:--yes|-y))*\s+"
    r"(?P<package>(?:@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)(?:@[^\s;&|]+)?)",
    re.IGNORECASE,
)
_INLINE_UVX = re.compile(
    r"(?:^|\s)uvx(?:\.exe)?\s+(?P<package>[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?(?:==[^\s;&|]+)?)",
    re.IGNORECASE,
)
_INLINE_ROOT = re.compile(
    r"(?:^|\s)--?(?:root|workspace|directory|dir)(?:=|\s+)"
    r"(?P<path>/|~/?|[A-Za-z]:[\\/]?)(?:\s|$)",
    re.IGNORECASE,
)
_WILDCARD_KEYS = {
    "allowedhosts",
    "allowhosts",
    "scopes",
    "scope",
    "tools",
    "enabledtools",
    "enabled_tools",
}
_ROOT_KEYS = {
    "root",
    "roots",
    "allowedroot",
    "allowedroots",
    "alloweddirectories",
    "allowed_directories",
    "filesystemroots",
    "cwd",
}
_NORMALIZED_ROOT_KEYS = {key.lower().replace("-", "").replace("_", "") for key in _ROOT_KEYS}
_NORMALIZED_WILDCARD_KEYS = {
    key.lower().replace("-", "").replace("_", "") for key in _WILDCARD_KEYS
}
_ENV_REFERENCE = re.compile(
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$env:[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)",
    re.IGNORECASE,
)


def _finding(
    server: NormalizedServer,
    rule_id: str,
    field: str,
    evidence: str,
    *,
    confidence: str = "high",
    uncertainty: str | None = None,
) -> Finding:
    rule = RULE_INDEX[rule_id]
    separator = "/" if server.location.startswith("/") else "."
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        source=server.source,
        server=server.name,
        location=f"{server.location}{separator}{field}",
        evidence=evidence,
        remediation=rule.remediation,
        confidence=confidence,
        uncertainty=uncertainty,
    )


def _command_name(command: str | None) -> str:
    if not command:
        return ""
    normalized = command.replace("\\", "/")
    return normalized.rsplit("/", 1)[-1].lower()


def _is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    hostname = hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _placeholder(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    without_scheme = re.sub(r"^(?:bearer|basic)\s+", "", stripped, flags=re.IGNORECASE)
    return (
        not stripped
        or bool(_ENV_REFERENCE.fullmatch(without_scheme))
        or lowered.startswith(("env:", "your_", "your-"))
        or (stripped.startswith("<") and stripped.endswith(">"))
        or lowered in {"changeme", "replace-me", "redacted", "***"}
    )


def _url_secret_findings(server: NormalizedServer, value: str, field: str) -> list[Finding]:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return []
    findings: list[Finding] = []
    if parsed.username is not None or parsed.password is not None:
        findings.append(_finding(server, "MCP004", field, "URL contains redacted user information"))
    for key, query_value in parse_qsl(parsed.query, keep_blank_values=True):
        credential_key = _SECRET_KEY.search(key) or _SENSITIVE_HEADER.search(key)
        if credential_key and not _placeholder(query_value):
            findings.append(
                _finding(server, "MCP004", field, f"URL query parameter {key}=<redacted>")
            )
    return findings


def _remote_http(server: NormalizedServer) -> Iterable[Finding]:
    if not server.url:
        return
    try:
        parsed = urlsplit(server.url)
    except ValueError:
        return
    if parsed.scheme.lower() == "http" and not _is_loopback(parsed.hostname):
        host = parsed.hostname or "<missing-host>"
        yield _finding(server, "MCP001", "url", f"remote endpoint uses http://{host}")


def _shell(server: NormalizedServer) -> Iterable[Finding]:
    name = _command_name(server.command)
    shells = {
        "sh",
        "bash",
        "dash",
        "zsh",
        "fish",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
    }
    if name in shells:
        yield _finding(server, "MCP002", "command", f"shell wrapper: {name}")
    elif server.command and re.search(r"(?:&&|\|\||[|;`])", server.command):
        yield _finding(server, "MCP002", "command", "command contains shell control syntax")


def _runner_package(server: NormalizedServer) -> Iterable[Finding]:
    command = _command_name(server.command)
    if command in {"npx", "npx.cmd"}:
        package: str | None = None
        consume_next = False
        for argument in server.args:
            if consume_next:
                package = argument
                consume_next = False
                break
            if argument in {"--package", "-p"}:
                consume_next = True
                continue
            if argument.startswith("--package="):
                package = argument.split("=", 1)[1]
                break
            if not argument.startswith("-"):
                package = argument
                break
        if package and not _EXACT_NPM.fullmatch(package):
            yield _finding(
                server,
                "MCP003",
                "args",
                "npx package has no exact version",
            )
    elif command in {"uvx", "uvx.exe"}:
        package = None
        consume_next = False
        for argument in server.args:
            if consume_next:
                package = argument
                break
            if argument == "--from":
                consume_next = True
            elif argument.startswith("--from="):
                package = argument.split("=", 1)[1]
                break
            elif not argument.startswith("-"):
                package = argument
                break
        if package and not _EXACT_UV.fullmatch(package):
            yield _finding(
                server,
                "MCP003",
                "args",
                "uvx package has no exact version",
            )
    if command not in {"npx", "npx.cmd"}:
        for index, argument in enumerate(server.args):
            match = _INLINE_NPX.search(argument)
            if match and not _EXACT_NPM.fullmatch(match.group("package")):
                yield _finding(
                    server,
                    "MCP003",
                    f"args/{index}",
                    "inline npx package has no exact version",
                    confidence="medium",
                    uncertainty="The argument is interpreted as a command only by some launchers.",
                )
    if command not in {"uvx", "uvx.exe"}:
        for index, argument in enumerate(server.args):
            match = _INLINE_UVX.search(argument)
            if match and not _EXACT_UV.fullmatch(match.group("package")):
                yield _finding(
                    server,
                    "MCP003",
                    f"args/{index}",
                    "inline uvx package has no exact version",
                    confidence="medium",
                    uncertainty="The argument is interpreted as a command only by some launchers.",
                )


def _secrets(server: NormalizedServer) -> Iterable[Finding]:
    for key, value in sorted(server.env.items()):
        if _SECRET_KEY.search(key) and not _placeholder(value):
            yield _finding(server, "MCP004", f"env/{key}", f"env.{key}=<redacted>")
    for key, value in sorted(server.headers.items()):
        if (_SENSITIVE_HEADER.search(key) or _SECRET_KEY.search(key)) and not _placeholder(value):
            yield _finding(server, "MCP004", f"headers/{key}", f"header {key}=<redacted>")
        yield from _url_secret_findings(server, value, f"headers/{key}")
    if server.url:
        yield from _url_secret_findings(server, server.url, "url")

    expect_secret = False
    for index, argument in enumerate(server.args):
        if expect_secret:
            if not _placeholder(argument):
                yield _finding(server, "MCP004", f"args/{index}", "credential argument <redacted>")
            expect_secret = False
            continue
        match = _ARG_SECRET.match(argument)
        if match:
            if "=" in argument:
                value = argument.split("=", 1)[1]
                if not _placeholder(value):
                    yield _finding(
                        server,
                        "MCP004",
                        f"args/{index}",
                        f"--{match.group('name')}=<redacted>",
                    )
            else:
                expect_secret = True
        for inline_match in _INLINE_SECRET.finditer(argument):
            if match and inline_match.start() == 0:
                continue
            if not _placeholder(inline_match.group("value")):
                yield _finding(
                    server,
                    "MCP004",
                    f"args/{index}",
                    f"inline --{inline_match.group('name')}=<redacted>",
                )
        yield from _url_secret_findings(server, argument, f"args/{index}")


def _is_broad_root(value: str) -> bool:
    stripped = value.strip()
    if stripped in {"/", "~", "~/", "\\"}:
        return True
    if re.fullmatch(r"[A-Za-z]:[\\/]?", stripped):
        return True
    try:
        windows = PureWindowsPath(stripped)
        return bool(windows.anchor and windows == PureWindowsPath(windows.anchor))
    except ValueError:
        return False


def _option_values(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        yield from (item for item in value if isinstance(item, str))


def _broad_roots(server: NormalizedServer) -> Iterable[Finding]:
    for index, argument in enumerate(server.args):
        candidate = argument
        if "=" in argument:
            flag, candidate = argument.split("=", 1)
            normalized_flag = flag.lower().lstrip("-").replace("-", "").replace("_", "")
            if normalized_flag not in _NORMALIZED_ROOT_KEYS:
                continue
        if _is_broad_root(candidate):
            yield _finding(
                server,
                "MCP005",
                f"args/{index}",
                "argument grants a filesystem root",
                confidence="medium",
                uncertainty="Argument meaning depends on the launched server.",
            )
        inline_root = _INLINE_ROOT.search(argument)
        if inline_root and _is_broad_root(inline_root.group("path")):
            yield _finding(
                server,
                "MCP005",
                f"args/{index}",
                "inline argument grants a filesystem root",
                confidence="medium",
                uncertainty="The argument is interpreted as a command only by some launchers.",
            )
    for key, value in sorted(server.options.items()):
        normalized_key = key.lower().replace("-", "").replace("_", "")
        if normalized_key in _NORMALIZED_ROOT_KEYS:
            for item in _option_values(value):
                if _is_broad_root(item):
                    yield _finding(server, "MCP005", key, f"{key} grants a filesystem root")


def _is_wildcard(value: str) -> bool:
    return value.strip().lower() in {"*", "0.0.0.0", "::", "[::]"}


def _wildcards(server: NormalizedServer) -> Iterable[Finding]:
    for key, value in sorted(server.options.items()):
        normalized_key = key.lower().replace("-", "").replace("_", "")
        wildcard_option = normalized_key in _NORMALIZED_WILDCARD_KEYS
        if wildcard_option or normalized_key in {
            "host",
            "bind",
            "listen",
        }:
            for item in _option_values(value):
                if _is_wildcard(item):
                    yield _finding(server, "MCP006", key, f"{key} uses a wildcard value")
    expect_wildcard_value = False
    for index, argument in enumerate(server.args):
        if expect_wildcard_value:
            if _is_wildcard(argument):
                yield _finding(
                    server,
                    "MCP006",
                    f"args/{index}",
                    "argument uses a wildcard host or scope",
                    confidence="medium",
                    uncertainty="Argument meaning depends on the launched server.",
                )
            expect_wildcard_value = False
            continue
        match = re.match(
            r"^--?(?:host|bind|listen|scope|scopes|allow-hosts?|allowed-hosts?)(?:=(.*))?$",
            argument,
            re.IGNORECASE,
        )
        if match and match.group(1) is None:
            expect_wildcard_value = True
        elif match and _is_wildcard(match.group(1)):
            yield _finding(
                server,
                "MCP006",
                f"args/{index}",
                "argument uses a wildcard host or scope",
                confidence="medium",
                uncertainty="Argument meaning depends on the launched server.",
            )


def _transport(server: NormalizedServer) -> Iterable[Finding]:
    for field in server.invalid_fields:
        yield _finding(server, "MCP007", field.replace(" ", "_"), f"{field} has an invalid type")
    if server.command and server.url:
        yield _finding(server, "MCP007", "transport", "both command and url are configured")
    elif not server.command and not server.url:
        yield _finding(server, "MCP007", "transport", "neither command nor url is configured")

    transport = server.transport
    supported = {"stdio", "http", "sse", "streamable-http", "streamable_http"}
    if transport and transport not in supported:
        yield _finding(server, "MCP007", "type", "unsupported transport type")
    elif transport == "stdio" and server.url:
        yield _finding(server, "MCP007", "type", "stdio transport is paired with a URL")
    elif transport in {"http", "sse", "streamable-http", "streamable_http"} and server.command:
        yield _finding(server, "MCP007", "type", f"{transport} transport is paired with a command")
    if server.url:
        try:
            scheme = urlsplit(server.url).scheme.lower()
        except ValueError:
            scheme = ""
        if scheme not in {"http", "https"}:
            evidence = f"unsupported URL scheme: {scheme or '<missing>'}"
            yield _finding(server, "MCP007", "url", evidence)


def evaluate(server: NormalizedServer) -> list[Finding]:
    findings: list[Finding] = []
    for check in (
        _remote_http,
        _shell,
        _runner_package,
        _secrets,
        _broad_roots,
        _wildcards,
        _transport,
    ):
        findings.extend(check(server))
    return findings

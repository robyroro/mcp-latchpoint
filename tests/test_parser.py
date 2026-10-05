from __future__ import annotations

from pathlib import Path

import pytest

from mcp_latchpoint.parser import ConfigParseError, parse_config


def test_vscode_jsonc_supports_comments_and_trailing_commas(tmp_path: Path) -> None:
    vscode = tmp_path / ".vscode"
    vscode.mkdir()
    path = vscode / "mcp.json"
    path.write_text(
        """
        {
          // project server
          "servers": {
            "local": {
              "type": "stdio",
              "command": "python", /* comments preserve positions */
              "args": ["server.py",],
            },
          },
        }
        """,
        encoding="utf-8",
    )

    parsed = parse_config(path, 100_000)

    assert parsed.layout == "vscode"
    assert parsed.servers[0].name == "local"
    assert parsed.servers[0].args == ("server.py",)


def test_regular_json_remains_strict(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"mcpServers": { /* no */ }}', encoding="utf-8")

    with pytest.raises(ConfigParseError, match=r"invalid JSON at line 1, column"):
        parse_config(path, 100_000)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('{"mcpServers":{},"mcpServers":{}}', "duplicate object key"),
        ('{"mcpServers":{"x":{"value":NaN}}}', "non-standard numeric constant"),
    ],
)
def test_nonstandard_or_ambiguous_json_is_rejected(
    tmp_path: Path, content: str, message: str
) -> None:
    path = tmp_path / "config.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigParseError, match=message):
        parse_config(path, 100_000)


def test_jsonc_does_not_treat_comment_markers_inside_strings_as_comments(tmp_path: Path) -> None:
    path = tmp_path / "config.jsonc"
    path.write_text(
        '{"mcpServers":{"remote":{"url":"https://example.com/a//b?x=/*ok*/"}}}',
        encoding="utf-8",
    )

    parsed = parse_config(path, 100_000)

    assert parsed.servers[0].url == "https://example.com/a//b?x=/*ok*/"


def test_codex_toml_is_normalized(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[mcp_servers.demo]\ncommand = "uvx"\nargs = ["demo==1.2.3"]\n',
        encoding="utf-8",
    )

    parsed = parse_config(path, 100_000)

    assert parsed.layout == "codex"
    assert parsed.servers[0].location == "mcp_servers.demo"
    assert parsed.servers[0].command == "uvx"


def test_claude_code_user_file_includes_project_scoped_servers(tmp_path: Path) -> None:
    path = tmp_path / ".claude.json"
    path.write_text(
        """
        {
          "mcpServers": {"user-server": {"command": "user-tool"}},
          "projects": {
            "/work/example": {
              "mcpServers": {"local-server": {"command": "local-tool"}}
            }
          }
        }
        """,
        encoding="utf-8",
    )

    parsed = parse_config(path, 100_000)

    assert parsed.layout == "claude-code"
    assert [server.name for server in parsed.servers] == ["user-server", "local-server"]
    assert parsed.servers[1].location == "/projects/~1work~1example/mcpServers/local-server"


def test_parser_records_invalid_field_types_without_echoing_values(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        '{"mcpServers":{"bad":{"command":42,"args":"private-value","env":[]}}}',
        encoding="utf-8",
    )

    parsed = parse_config(path, 100_000)

    assert parsed.servers[0].invalid_fields == ("args", "command", "env")
    assert "private-value" not in repr(parsed.servers[0])


def test_size_limit_is_checked_before_parse(tmp_path: Path) -> None:
    path = tmp_path / "large.json"
    path.write_text("x" * 100, encoding="utf-8")

    with pytest.raises(ConfigParseError, match="size limit"):
        parse_config(path, 10)


def test_malformed_toml_error_does_not_echo_source(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    secret = "do-not-echo-this-value"
    path.write_text(f'[mcp_servers.bad]\ntoken = "{secret}\n', encoding="utf-8")

    with pytest.raises(ConfigParseError) as exc_info:
        parse_config(path, 100_000)

    assert secret not in str(exc_info.value)

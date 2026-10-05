from __future__ import annotations

import json
from pathlib import Path

from mcp_latchpoint.scanner import scan_paths


def _scan_data(tmp_path: Path, data: dict[str, object]):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return scan_paths([path])


def test_risky_entry_produces_precise_rules_and_never_leaks_secrets(tmp_path: Path) -> None:
    secret = "very-private-token-123"
    report = _scan_data(
        tmp_path,
        {
            "mcpServers": {
                "risky": {
                    "command": "npx",
                    "args": [
                        "example-package",
                        "--api-key",
                        secret,
                        f"run --token={secret}",
                        "--root=/",
                    ],
                    "env": {"SERVICE_TOKEN": secret},
                    "headers": {"Authorization": f"Bearer {secret}"},
                },
                "remote": {"url": f"http://remote.example/path?access_token={secret}"},
            }
        },
    )

    ids = [finding.rule_id for finding in report.findings]
    rendered = json.dumps(report.to_dict())
    assert {"MCP001", "MCP003", "MCP004", "MCP005"}.issubset(ids)
    assert secret not in rendered
    assert "<redacted>" in rendered


def test_loopback_http_and_placeholders_are_not_flagged(tmp_path: Path) -> None:
    report = _scan_data(
        tmp_path,
        {
            "mcpServers": {
                "local": {
                    "url": "http://127.0.0.1:8123/mcp",
                    "headers": {"Authorization": "Bearer ${LOCAL_TOKEN}"},
                },
                "local-v6": {"url": "http://[::1]:8123/mcp"},
            }
        },
    )

    assert not report.findings


def test_environment_reference_with_literal_default_is_treated_as_embedded(tmp_path: Path) -> None:
    secret = "private-default-value"
    report = _scan_data(
        tmp_path,
        {
            "mcpServers": {
                "local": {
                    "command": "server",
                    "env": {"API_TOKEN": f"${{API_TOKEN:-{secret}}}"},
                }
            }
        },
    )

    assert [finding.rule_id for finding in report.findings] == ["MCP004"]
    assert secret not in json.dumps(report.to_dict())


def test_exact_npx_and_uvx_versions_are_not_flagged(tmp_path: Path) -> None:
    report = _scan_data(
        tmp_path,
        {
            "mcpServers": {
                "npm": {"command": "npx", "args": ["-y", "@scope/server@1.2.3"]},
                "python": {"command": "uvx", "args": ["server-tool==2.4.1"]},
            }
        },
    )

    assert "MCP003" not in {finding.rule_id for finding in report.findings}


def test_shell_and_transport_conflicts_are_reported(tmp_path: Path) -> None:
    report = _scan_data(
        tmp_path,
        {
            "mcpServers": {
                "shell": {"type": "http", "command": "powershell.exe", "args": ["-Command"]},
                "both": {"command": "server", "url": "https://example.com/mcp"},
                "missing": {"type": "stdio"},
            }
        },
    )

    ids = [finding.rule_id for finding in report.findings]
    assert "MCP002" in ids
    assert ids.count("MCP007") >= 3


def test_inline_shell_payload_has_bounded_package_and_root_detection(tmp_path: Path) -> None:
    report = _scan_data(
        tmp_path,
        {
            "mcpServers": {
                "shell": {
                    "command": "sh",
                    "args": ["-c", "npx @scope/server --root /"],
                }
            }
        },
    )

    ids = {finding.rule_id for finding in report.findings}
    assert {"MCP002", "MCP003", "MCP005"}.issubset(ids)
    assert all(
        finding.confidence == "medium"
        for finding in report.findings
        if finding.rule_id in {"MCP003", "MCP005"}
    )


def test_wildcard_fields_are_specific_but_unrelated_stars_are_ignored(tmp_path: Path) -> None:
    report = _scan_data(
        tmp_path,
        {
            "mcpServers": {
                "broad": {
                    "command": "server",
                    "allowedHosts": ["*"],
                    "args": ["--host", "0.0.0.0"],
                },
                "unrelated": {"command": "server", "pattern": "*"},
            }
        },
    )

    wildcard_servers = [
        finding.server for finding in report.findings if finding.rule_id == "MCP006"
    ]
    assert wildcard_servers == ["broad", "broad"]


def test_findings_are_deterministic(tmp_path: Path) -> None:
    data = {
        "mcpServers": {
            "z": {"url": "http://z.example/mcp"},
            "a": {"url": "http://a.example/mcp"},
        }
    }

    first = _scan_data(tmp_path, data).to_dict()
    second = scan_paths([tmp_path / "config.json"]).to_dict()

    assert first == second

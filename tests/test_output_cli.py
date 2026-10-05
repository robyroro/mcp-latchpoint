from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator

from mcp_latchpoint.cli import main
from mcp_latchpoint.output import report_sarif
from mcp_latchpoint.scanner import scan_paths

SARIF_CORE_SCHEMA = {
    "type": "object",
    "required": ["$schema", "version", "runs"],
    "properties": {
        "version": {"const": "2.1.0"},
        "runs": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["tool", "results"],
                "properties": {
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": ["name", "rules"],
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["ruleId", "level", "message", "locations"],
                        },
                    },
                },
            },
        },
    },
}


def _risky_config(tmp_path: Path) -> Path:
    path = tmp_path / "risky.json"
    path.write_text(
        '{"mcpServers":{"remote":{"url":"http://remote.example/mcp"}}}',
        encoding="utf-8",
    )
    return path


def test_sarif_has_valid_core_shape_and_known_rule_references(tmp_path: Path) -> None:
    data = json.loads(report_sarif(scan_paths([_risky_config(tmp_path)])))

    Draft7Validator(SARIF_CORE_SCHEMA).validate(data)
    driver_rules = {rule["id"] for rule in data["runs"][0]["tool"]["driver"]["rules"]}
    assert all(result["ruleId"] in driver_rules for result in data["runs"][0]["results"])
    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"


def test_cli_severity_threshold_controls_exit_code(tmp_path: Path, capsys) -> None:
    path = _risky_config(tmp_path)

    assert main(["scan", str(path), "--fail-on", "high"]) == 1
    first = capsys.readouterr()
    assert "MCP001" in first.out
    assert main(["scan", str(path), "--fail-on", "critical"]) == 0


def test_cli_parse_error_is_exit_two_and_json_is_machine_readable(tmp_path: Path, capsys) -> None:
    path = tmp_path / "broken.json"
    path.write_text("not json", encoding="utf-8")

    code = main(["scan", str(path), "--format", "json"])
    output = json.loads(capsys.readouterr().out)

    assert code == 2
    assert output["summary"]["errors"] == 1


def test_rules_and_explain_commands(capsys) -> None:
    assert main(["rules", "--format", "json"]) == 0
    rules = json.loads(capsys.readouterr().out)
    assert [rule["id"] for rule in rules] == [f"MCP00{number}" for number in range(1, 8)]

    assert main(["explain", "mcp004"]) == 0
    assert "Credential appears embedded" in capsys.readouterr().out

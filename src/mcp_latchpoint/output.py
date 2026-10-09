"""Human, JSON, and SARIF serialization."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from mcp_latchpoint.model import Finding, RuleDefinition, ScanReport, Severity
from mcp_latchpoint.rules import RULES


def report_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


def report_text(report: ScanReport) -> str:
    lines: list[str] = []
    if not report.findings:
        lines.append("No findings.")
    for finding in report.findings:
        lines.extend(
            [
                f"{finding.severity.value.upper():8} {finding.rule_id} {finding.title}",
                f"  {finding.source} :: {finding.server} :: {finding.location}",
                f"  Evidence: {finding.evidence}",
                f"  Fix: {finding.remediation}",
            ]
        )
        if finding.uncertainty:
            lines.append(f"  Uncertainty: {finding.uncertainty}")
    for error in report.errors:
        lines.append(f"ERROR    {error.source}: {error.message}")
    lines.append(
        f"Summary: {len(report.findings)} finding(s), "
        f"{len(report.scanned_files)} file(s), {len(report.errors)} error(s)."
    )
    lines.append("Limitations:")
    lines.extend(f"  - {limitation}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def rules_text(rules: tuple[RuleDefinition, ...] = RULES) -> str:
    return (
        "\n".join(f"{rule.rule_id}  {rule.severity.value.upper():8} {rule.title}" for rule in rules)
        + "\n"
    )


def rule_text(rule: RuleDefinition) -> str:
    return (
        f"{rule.rule_id}: {rule.title}\n"
        f"Severity: {rule.severity.value}\n"
        f"What it detects: {rule.description}\n"
        f"Remediation: {rule.remediation}\n"
    )


def _artifact_uri(path: Path) -> str:
    try:
        return path.resolve().as_uri()
    except ValueError:
        return str(path).replace("\\", "/")


def _sarif_result(finding: Finding) -> dict[str, Any]:
    level = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }[finding.severity]
    fingerprint_source = "\0".join(finding.dedupe_key()).encode()
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": f"{finding.title}: {finding.evidence}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(finding.source)},
                },
                "logicalLocations": [
                    {"name": finding.server, "fullyQualifiedName": finding.location}
                ],
            }
        ],
        "fingerprints": {
            "mcpLatchpoint/v1": hashlib.sha256(fingerprint_source).hexdigest(),
        },
        "properties": {
            "confidence": finding.confidence,
            "remediation": finding.remediation,
            "severity": finding.severity.value,
        },
    }
    if finding.uncertainty:
        result["properties"]["uncertainty"] = finding.uncertainty
    return result


def report_sarif(report: ScanReport) -> str:
    rules = [
        {
            "id": rule.rule_id,
            "name": rule.title.replace(" ", ""),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "defaultConfiguration": {
                "level": "error"
                if rule.severity in {Severity.CRITICAL, Severity.HIGH}
                else "warning"
                if rule.severity is Severity.MEDIUM
                else "note"
            },
            "help": {"text": rule.remediation},
            "properties": {"security-severity": str(float(SeverityRank[rule.severity]))},
        }
        for rule in RULES
    ]
    notifications = [
        {
            "descriptor": {"id": "scan-error"},
            "level": "error",
            "message": {"text": f"{error.source}: {error.message}"},
        }
        for error in report.errors
    ]
    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-latchpoint",
                        "semanticVersion": "0.1.1",
                        "rules": rules,
                    }
                },
                "results": [_sarif_result(finding) for finding in report.findings],
                "invocations": [
                    {
                        "executionSuccessful": not report.errors,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "properties": {"limitations": list(report.limitations)},
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True) + "\n"


SeverityRank = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 8,
    Severity.CRITICAL: 10,
}

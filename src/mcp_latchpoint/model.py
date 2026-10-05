"""Safe public result types and private normalized configuration types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    rule_id: str
    title: str
    severity: Severity
    description: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    source: Path
    server: str
    location: str
    evidence: str
    remediation: str
    confidence: str = "high"
    uncertainty: str | None = None

    def sort_key(self) -> tuple[int, str, str, str, str, str]:
        return (
            -SEVERITY_RANK[self.severity],
            self.rule_id,
            str(self.source),
            self.server,
            self.location,
            self.evidence,
        )

    def dedupe_key(self) -> tuple[str, str, str, str, str]:
        return (self.rule_id, str(self.source), self.server, self.location, self.evidence)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "source": str(self.source),
            "server": self.server,
            "location": self.location,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "confidence": self.confidence,
        }
        if self.uncertainty:
            data["uncertainty"] = self.uncertainty
        return data


@dataclass(slots=True)
class NormalizedServer:
    """Normalized server entry. Sensitive fields are deliberately excluded from repr."""

    name: str
    source: Path
    layout: str
    location: str
    transport: str | None
    command: str | None = field(repr=False)
    args: tuple[str, ...] = field(repr=False)
    url: str | None = field(repr=False)
    env: dict[str, str] = field(repr=False)
    headers: dict[str, str] = field(repr=False)
    options: dict[str, Any] = field(repr=False)
    invalid_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanError:
    source: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "message": self.message}


DEFAULT_LIMITATIONS = (
    "Static analysis only: commands are never executed and endpoints are never contacted.",
    "Referenced environment variables, included files, runtime policy, and server behavior "
    "are not resolved.",
    "A missing finding does not prove that a configuration or MCP server is safe.",
)


@dataclass(slots=True)
class ScanReport:
    findings: list[Finding]
    scanned_files: list[Path]
    errors: list[ScanError]
    limitations: tuple[str, ...] = DEFAULT_LIMITATIONS

    def to_dict(self) -> dict[str, Any]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return {
            "version": 1,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": {
                "findings": len(self.findings),
                "files_scanned": len(self.scanned_files),
                "errors": len(self.errors),
                "by_severity": counts,
            },
            "scanned_files": [str(path) for path in self.scanned_files],
            "errors": [error.to_dict() for error in self.errors],
            "limitations": list(self.limitations),
        }

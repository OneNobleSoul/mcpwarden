"""Finding types shared across the detectors and reporters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _ORDER.index(self)

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            allowed = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (use one of: {allowed})") from exc


_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    title: str
    detail: str
    server: str | None = None
    # file path, tool name, env key -- whatever pins the finding down
    location: str | None = None

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "server": self.server,
            "location": self.location,
        }


def highest(findings: list[Finding]) -> Severity | None:
    if not findings:
        return None
    return max(f.severity for f in findings)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    # worst first, then group by server so the report reads sanely
    return sorted(findings, key=lambda f: (-f.severity.rank, f.server or "", f.rule))

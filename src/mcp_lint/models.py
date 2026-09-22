"""Typed domain models for mcp-lint.

The linter boundary is intentionally small: a :class:`Tool` is the normalized
shape every loader produces, and a :class:`Finding` is the normalized shape every
rule emits. Keeping both frozen and JSON-serializable makes the output stable
across runs, which is what lets CI diff two reports meaningfully.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.Enum):
    """Ordered severity levels. ``value`` doubles as the CI-gating rank."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()

    @classmethod
    def from_str(cls, raw: str) -> Severity:
        try:
            return cls[raw.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {raw!r}; expected one of {valid}") from exc


@dataclass(frozen=True)
class Tool:
    """A single MCP tool, normalized from whatever source produced it.

    ``server`` records which MCP server the tool came from (or ``"<inline>"`` for
    a raw tools export), so cross-server name shadowing can be detected.
    """

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    server: str = "<inline>"

    @property
    def qualified_name(self) -> str:
        return f"{self.server}:{self.name}"


@dataclass(frozen=True)
class Finding:
    """One rule violation, tied to a specific tool and rule id."""

    rule_id: str
    severity: Severity
    tool: str
    message: str
    hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = str(self.severity)
        return data


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic order: severity desc, then rule id, then tool name.

    Rules may run in any order and in parallel in the future; sorting here keeps
    the report byte-stable so CI diffs stay meaningful.
    """

    return sorted(
        findings,
        key=lambda f: (-f.severity.value, f.rule_id, f.tool),
    )

"""The linter: run rules over tools, apply selection/suppression, sort output."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_lint.models import Finding, Severity, Tool, sort_findings
from mcp_lint.rules import RULES


@dataclass
class Linter:
    """Runs a selected set of rules and applies ignore filters.

    ``select`` / ``ignore`` operate on rule ids (e.g. ``"MCPL002"``). ``ignore``
    wins over ``select``. When ``select`` is empty every registered rule runs.
    """

    select: frozenset[str] = frozenset()
    ignore: frozenset[str] = frozenset()

    def active_rules(self) -> list[str]:
        chosen = set(self.select) if self.select else set(RULES)
        chosen -= set(self.ignore)
        unknown = (set(self.select) | set(self.ignore)) - set(RULES)
        if unknown:
            valid = ", ".join(sorted(RULES))
            raise ValueError(
                f"unknown rule id(s): {', '.join(sorted(unknown))}; valid ids: {valid}"
            )
        return sorted(chosen)

    def run(self, tools: list[Tool]) -> list[Finding]:
        findings: list[Finding] = []
        for rule_id in self.active_rules():
            findings.extend(RULES[rule_id](tools))
        return sort_findings(findings)


def lint_tools(
    tools: list[Tool],
    *,
    select: frozenset[str] | set[str] | None = None,
    ignore: frozenset[str] | set[str] | None = None,
) -> list[Finding]:
    """Convenience wrapper for a one-shot lint."""

    return Linter(
        select=frozenset(select or ()),
        ignore=frozenset(ignore or ()),
    ).run(tools)


def max_severity(findings: list[Finding]) -> Severity | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: s.value)

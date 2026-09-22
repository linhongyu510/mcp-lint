"""Report renderers. ``text`` for humans, ``json`` for machines/CI diffing."""

from __future__ import annotations

import json
from typing import Any

from mcp_lint.models import Finding
from mcp_lint.rules import RULE_TITLES

# ANSI colors, disabled automatically when not writing to a TTY (handled by CLI).
_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
    "reset": "\033[0m",
}


def render_text(findings: list[Finding], *, tool_count: int, color: bool = True) -> str:
    lines: list[str] = []

    def paint(sev: str, text: str) -> str:
        if not color:
            return text
        return f"{_COLORS.get(sev, '')}{text}{_COLORS['reset']}"

    if not findings:
        lines.append(f"mcp-lint: scanned {tool_count} tool(s) — no findings.")
        return "\n".join(lines)

    counts: dict[str, int] = {}
    for f in findings:
        counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1

    for f in findings:
        sev = str(f.severity)
        title = RULE_TITLES.get(f.rule_id, f.rule_id)
        header = paint(sev, f"{sev.upper():>8}  {f.rule_id}  {f.tool}")
        lines.append(header)
        lines.append(f"          {f.message}")
        lines.append(f"          ({title})")
        if f.hint:
            lines.append(f"          hint: {f.hint}")
        lines.append("")

    summary = ", ".join(f"{counts[k]} {k}" for k in ("critical", "high", "medium", "low", "info") if k in counts)
    lines.append(f"mcp-lint: scanned {tool_count} tool(s), {len(findings)} finding(s): {summary}")
    return "\n".join(lines)


def render_json(findings: list[Finding], *, tool_count: int) -> str:
    payload: dict[str, Any] = {
        "tool_version": _version(),
        "tools_scanned": tool_count,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)


def _version() -> str:
    from mcp_lint import __version__

    return __version__

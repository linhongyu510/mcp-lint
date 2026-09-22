"""Command-line entry point: ``mcp-lint <file.json> [...]``.

Exit codes make the tool CI-gateable:

* ``0`` — no finding at or above ``--fail-level`` (default: ``high``)
* ``1`` — at least one finding at or above ``--fail-level``
* ``2`` — usage / load error

So ``mcp-lint mcp.json`` in a CI step fails the build on any HIGH/CRITICAL signal,
while ``--fail-level critical`` only blocks on the worst class.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mcp_lint import __version__
from mcp_lint.linter import Linter
from mcp_lint.loaders import LoadError, load_path
from mcp_lint.models import Finding, Severity
from mcp_lint.report import render_json, render_text
from mcp_lint.rules import RULE_TITLES


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-lint",
        description="Offline, deterministic static linter for MCP tool definitions.",
    )
    p.add_argument("paths", nargs="*", help="MCP config or tools-export JSON file(s)")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument(
        "--fail-level",
        default="high",
        help="minimum severity that causes a non-zero exit (default: high)",
    )
    p.add_argument("--select", default="", help="comma-separated rule ids to run exclusively")
    p.add_argument("--ignore", default="", help="comma-separated rule ids to skip")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--list-rules", action="store_true", help="print the rule catalog and exit")
    p.add_argument("--version", action="version", version=f"mcp-lint {__version__}")
    return p


def _split(csv: str) -> set[str]:
    return {x.strip() for x in csv.split(",") if x.strip()}


def _list_rules() -> str:
    lines = ["mcp-lint rules:"]
    for rule_id, title in RULE_TITLES.items():
        lines.append(f"  {rule_id}  {title}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.list_rules:
        print(_list_rules())
        return 0

    if not args.paths:
        print("mcp-lint: no input files (try --list-rules or -h)", file=sys.stderr)
        return 2

    try:
        fail_level = Severity.from_str(args.fail_level)
    except ValueError as exc:
        print(f"mcp-lint: {exc}", file=sys.stderr)
        return 2

    try:
        linter = Linter(select=frozenset(_split(args.select)), ignore=frozenset(_split(args.ignore)))
        linter.active_rules()  # validate ids early
    except ValueError as exc:
        print(f"mcp-lint: {exc}", file=sys.stderr)
        return 2

    all_findings: list[Finding] = []
    total_tools = 0
    for path in args.paths:
        try:
            tools = load_path(Path(path))
        except LoadError as exc:
            print(f"mcp-lint: {exc}", file=sys.stderr)
            return 2
        total_tools += len(tools)
        all_findings.extend(linter.run(tools))

    all_findings.sort(key=lambda f: (-f.severity.value, f.rule_id, f.tool))

    color = sys.stdout.isatty() and not args.no_color
    if args.format == "json":
        print(render_json(all_findings, tool_count=total_tools))
    else:
        print(render_text(all_findings, tool_count=total_tools, color=color))

    blocking = [f for f in all_findings if f.severity.value >= fail_level.value]
    return 1 if blocking else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

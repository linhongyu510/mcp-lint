"""mcp-lint: a deterministic, offline static linter for MCP tool definitions.

mcp-lint reads Model Context Protocol (MCP) tool definitions — either a client
config (Claude Desktop / Cursor / Windsurf style ``mcpServers`` blocks) or a raw
``tools/list`` JSON export — and flags security and quality problems *before* the
server is ever connected to an agent: tool-poisoning text hidden in descriptions,
prompt-injection phrasing, undeclared shell / file-write capability, unconstrained
input schemas, secret-leak sinks, and tool-name shadowing.

Everything is rule-based and deterministic. No model is called, no network access
is required, and the same input always produces the same findings — so it can gate
a CI pipeline the way ``ruff`` or ``eslint`` do.
"""

from mcp_lint.linter import Linter, lint_tools
from mcp_lint.models import Finding, Severity, Tool

__all__ = ["Finding", "Severity", "Tool", "Linter", "lint_tools"]
__version__ = "0.1.0"

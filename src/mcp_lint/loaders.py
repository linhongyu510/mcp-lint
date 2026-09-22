"""Loaders that normalize MCP inputs into :class:`~mcp_lint.models.Tool` objects.

Two shapes are supported:

* **Client config** — the ``mcpServers`` block used by Claude Desktop, Cursor and
  Windsurf. These files describe *how to launch* servers (command / args / env)
  but do not themselves list tools, so the loader emits one synthetic
  launch-surface "tool" per server carrying the command line in its description.
  That is enough for the config-hygiene rules (secrets in env, ``0.0.0.0`` binds,
  unpinned ``@latest`` packages) to fire.
* **Tools export** — a ``tools/list`` response, either the raw ``{"tools": [...]}``
  envelope or a bare list. Each entry becomes one :class:`Tool`.

The loader guesses the shape from the top-level keys, but callers can force one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_lint.models import Tool


class LoadError(ValueError):
    """Raised when input cannot be parsed into tools."""


def _as_tool(entry: dict[str, Any], server: str) -> Tool:
    if not isinstance(entry, dict):
        raise LoadError(f"tool entry must be an object, got {type(entry).__name__}")
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise LoadError("tool entry is missing a non-empty 'name'")
    schema = entry.get("inputSchema") or entry.get("input_schema") or {}
    if not isinstance(schema, dict):
        raise LoadError(f"inputSchema for tool {name!r} must be an object")
    return Tool(
        name=name,
        description=str(entry.get("description") or ""),
        input_schema=schema,
        server=server,
    )


def load_tools_export(payload: Any, server: str = "<inline>") -> list[Tool]:
    """Load a ``tools/list`` export (``{"tools": [...]}`` or a bare list)."""

    if isinstance(payload, dict) and "tools" in payload:
        payload = payload["tools"]
    if not isinstance(payload, list):
        raise LoadError("tools export must be a list or an object with a 'tools' key")
    return [_as_tool(entry, server) for entry in payload]


def load_client_config(payload: dict[str, Any]) -> list[Tool]:
    """Load an ``mcpServers`` client config into launch-surface tools."""

    servers = payload.get("mcpServers")
    if not isinstance(servers, dict):
        raise LoadError("client config must contain an 'mcpServers' object")
    tools: list[Tool] = []
    for server_name, spec in servers.items():
        if not isinstance(spec, dict):
            raise LoadError(f"server {server_name!r} spec must be an object")
        command = spec.get("command", "")
        args = spec.get("args", []) or []
        url = spec.get("url", "")
        env = spec.get("env", {}) or {}
        parts = [command, *[str(a) for a in args]]
        if url:
            parts.append(str(url))
        # Fold env values into the description so secret-leak / bind rules can see
        # them without a dedicated env-only rule surface.
        env_repr = " ".join(f"{k}={v}" for k, v in env.items())
        description = " ".join(p for p in [*parts, env_repr] if p)
        tools.append(
            Tool(
                name="<launch>",
                description=description,
                input_schema={},
                server=server_name,
            )
        )
    return tools


def detect_and_load(payload: Any) -> list[Tool]:
    """Guess the input shape and load accordingly."""

    if isinstance(payload, dict) and "mcpServers" in payload:
        return load_client_config(payload)
    return load_tools_export(payload)


def load_path(path: str | Path) -> list[Tool]:
    """Read and load a JSON file from disk."""

    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise LoadError(f"cannot read {p}: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LoadError(f"{p} is not valid JSON: {exc}") from exc
    return detect_and_load(payload)

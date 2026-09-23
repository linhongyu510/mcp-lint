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
from http.client import HTTPException
from pathlib import Path
from typing import Any, TextIO
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

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


def detect_and_load(payload: Any, server: str = "<inline>") -> list[Tool]:
    """Guess the input shape and load accordingly."""

    if isinstance(payload, dict) and "mcpServers" in payload:
        return load_client_config(payload)
    return load_tools_export(payload, server=server)


def _load_json(raw: str | bytes, source: str, server: str = "<inline>") -> list[Tool]:
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise LoadError(f"{source} is not valid JSON: {exc}") from exc
    return detect_and_load(payload, server=server)


def load_stdin(stream: TextIO) -> list[Tool]:
    """Read a JSON document from an explicitly supplied standard-input stream."""
    try:
        raw = stream.read()
    except (OSError, UnicodeError) as exc:
        raise LoadError(f"cannot read <stdin>: {exc}") from exc
    return _load_json(raw, "<stdin>", server="<stdin>")


def _validate_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("only http/https URLs with a host are supported")
        _ = parsed.port  # Validate malformed port numbers before opening a connection.
    except ValueError as exc:
        raise LoadError(f"invalid URL: {exc}") from exc


class _HTTPOnlyRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def load_url(url: str, *, timeout: float = 10, max_bytes: int = 5 * 1024 * 1024) -> list[Tool]:
    """Fetch JSON over HTTP(S), with a socket timeout and bounded response body."""
    _validate_url(url)
    if timeout <= 0 or max_bytes <= 0:
        raise LoadError("URL timeout and size limit must be positive")
    try:
        with build_opener(_HTTPOnlyRedirectHandler()).open(url, timeout=timeout) as response:
            raw = response.read(max_bytes + 1)
    except (URLError, OSError, HTTPException, ValueError) as exc:
        raise LoadError(f"cannot fetch URL: {exc}") from exc
    if len(raw) > max_bytes:
        raise LoadError(f"URL response exceeds {max_bytes} bytes")
    return _load_json(raw, "URL response", server=url)


def load_path(path: str | Path) -> list[Tool]:
    """Read and load a JSON file from disk."""

    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise LoadError(f"cannot read {p}: {exc}") from exc
    return _load_json(raw, str(p))

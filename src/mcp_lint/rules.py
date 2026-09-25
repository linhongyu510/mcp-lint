"""The rule set.

Each rule is a pure function ``(tools) -> list[Finding]``. Rules are registered
by id in :data:`RULES`; the linter runs the selected subset and sorts the output.
Adding a rule means writing one function, giving it a stable ``MCPL0xx`` id, and
registering it — mirroring how ``ruff``/``flake8`` plugins compose.

The corpus below is deliberately conservative and *explainable*: every pattern is
a documented tool-poisoning / prompt-injection / capability signal, and every
finding names the exact trigger so a human can confirm it in seconds. This is a
first-pass triage gate, not a proof of safety — false positives are expected and
suppressible; a clean report never means "safe", only "no known signal".
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable

from mcp_lint.models import Finding, Severity, Tool

Rule = Callable[[list[Tool]], list[Finding]]

# --- pattern corpora -------------------------------------------------------

# Hidden-instruction / tool-poisoning phrasing that tries to steer the agent from
# inside a tool description. Matched case-insensitively on word-ish boundaries.
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore (all |the |your )?(previous|prior|above) (instructions|prompts?)", "override-instructions"),
    (r"disregard (all |the |your )?(previous|prior|above)", "override-instructions"),
    (r"do not (tell|inform|mention to) the user", "hide-from-user"),
    (r"without (telling|informing|asking) the user", "hide-from-user"),
    (r"<\s*important\s*>", "fake-system-tag"),
    (r"<\s*/?\s*system\s*>", "fake-system-tag"),
    (r"you (are|must act as|will now be)\b.*\b(assistant|system|developer)", "role-reassign"),
    (r"\bBEGIN\b.*\bSYSTEM\b.*\bPROMPT\b", "fake-system-tag"),
    (r"exfiltrat", "exfiltration"),
    (r"send (it |them |the data )?to (https?://|[\w.-]+@)", "covert-egress"),
    (r"before (using|calling) (any )?other tools?", "priority-hijack"),
]

# Capability keywords implying the tool can do dangerous things. Presence alone is
# not a defect, but an *undeclared* dangerous capability with a wide-open schema is.
_SHELL_PATTERNS = [
    r"\bexec(ute)?\b", r"\bshell\b", r"\bsubprocess\b", r"\bos\.system\b",
    r"\brun (a |the )?command\b", r"\bbash\b", r"\bpowershell\b", r"\beval\(",
]
_FS_WRITE_PATTERNS = [
    r"\bdelete\b", r"\bremove\b", r"\brm -rf\b", r"\boverwrite\b",
    r"\bwrite (to )?(a |the )?file\b", r"\btruncate\b", r"\bunlink\b",
]
_NETWORK_PATTERNS = [
    r"\bfetch\b", r"\bhttp request\b", r"\bdownload\b", r"\bcurl\b",
    r"\bwebhook\b", r"\bpost to\b", r"\bupload\b",
]

# Sensitive resources and capabilities, not evidence of malicious intent. Keep
# this literal corpus in sync with the MCPL009 README section. Separators allow
# snake_case tool names; alphanumeric boundaries avoid matching unrelated words.
_SENSITIVE_PATTERNS = [
    rf"(?<![a-z0-9])(?:{pattern})(?![a-z0-9])"
    for pattern in (
        r"credentials?", r"private[ _-]+keys?", r"ssh", r"/etc/passwd",
        r"aws_secret(?:_access_key)?", r"keychain", r"send[ _-]+email",
        r"sendmail", r"smtp", r"clipboard", r"screenshots?", r"keylog(?:ger|ging)?",
    )
]

# Secret-leak signals in launch env / descriptions.
_SECRET_KEY_PATTERNS = [
    r"(?i)\b[A-Z0-9_]*(api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[=:]\s*\S+",
    r"\bsk-[A-Za-z0-9]{16,}\b",
    r"\bghp_[A-Za-z0-9]{20,}\b",
    r"AKIA[0-9A-Z]{16}",
]

_BIND_ALL_PATTERN = re.compile(r"0\.0\.0\.0")
_UNPINNED_PATTERN = re.compile(r"@(latest|main|master|next)\b|:latest\b")


def _matches(text: str, patterns: list[str]) -> str | None:
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            return m.group(0)
    return None


# --- rules -----------------------------------------------------------------


def rule_tool_poisoning(tools: list[Tool]) -> list[Finding]:
    """MCPL001: hidden instructions / prompt-injection phrasing in a description."""

    out: list[Finding] = []
    for tool in tools:
        for pat, label in _INJECTION_PATTERNS:
            m = re.search(pat, tool.description, flags=re.IGNORECASE)
            if m:
                out.append(
                    Finding(
                        rule_id="MCPL001",
                        severity=Severity.CRITICAL,
                        tool=tool.qualified_name,
                        message=(
                            f"description contains injection signal "
                            f"[{label}]: {m.group(0)!r}"
                        ),
                        hint=(
                            "Tool descriptions are read into the agent's context "
                            "verbatim. Remove instruction-like text; describe what "
                            "the tool does, not what the agent should do."
                        ),
                    )
                )
    return out


def rule_undeclared_shell(tools: list[Tool]) -> list[Finding]:
    """MCPL002: description implies shell/command execution capability."""

    out: list[Finding] = []
    for tool in tools:
        hit = _matches(tool.description, _SHELL_PATTERNS)
        if hit:
            out.append(
                Finding(
                    rule_id="MCPL002",
                    severity=Severity.HIGH,
                    tool=tool.qualified_name,
                    message=f"description implies command execution: {hit!r}",
                    hint=(
                        "Execution tools are the highest-risk MCP surface. Confirm "
                        "the argument schema constrains the command, require human "
                        "approval, and never expose it to an untrusted agent role."
                    ),
                )
            )
    return out


def rule_destructive_fs(tools: list[Tool]) -> list[Finding]:
    """MCPL003: description implies destructive file-system operations."""

    out: list[Finding] = []
    for tool in tools:
        hit = _matches(tool.description, _FS_WRITE_PATTERNS)
        if hit:
            out.append(
                Finding(
                    rule_id="MCPL003",
                    severity=Severity.MEDIUM,
                    tool=tool.qualified_name,
                    message=f"description implies destructive file operation: {hit!r}",
                    hint=(
                        "Destructive tools should carry an explicit risk flag and be "
                        "gated behind approval rather than auto-invoked."
                    ),
                )
            )
    return out


def rule_unconstrained_schema(tools: list[Tool]) -> list[Finding]:
    """MCPL004: input schema accepts arbitrary input (no properties / additionalProperties)."""

    out: list[Finding] = []
    for tool in tools:
        schema = tool.input_schema
        if not schema:
            # A launch-surface tool has no schema by design; skip it here.
            if tool.name == "<launch>":
                continue
            out.append(
                Finding(
                    rule_id="MCPL004",
                    severity=Severity.LOW,
                    tool=tool.qualified_name,
                    message="tool has no input schema",
                    hint="Declare an inputSchema so arguments can be validated at the boundary.",
                )
            )
            continue
        is_object = schema.get("type") == "object"
        has_props = bool(schema.get("properties"))
        allows_extra = schema.get("additionalProperties", None)
        # Dangerous shape: object with no declared properties but extra allowed,
        # or a shell/exec tool that accepts a free-form string.
        if is_object and not has_props and allows_extra is not False:
            out.append(
                Finding(
                    rule_id="MCPL004",
                    severity=Severity.MEDIUM,
                    tool=tool.qualified_name,
                    message="object schema declares no properties and permits additionalProperties",
                    hint=(
                        "Set additionalProperties:false and declare each argument. An "
                        "open schema lets an agent pass anything the server will accept."
                    ),
                )
            )
    return out


def rule_secret_leak(tools: list[Tool]) -> list[Finding]:
    """MCPL005: a hard-coded secret / credential appears in config or description."""

    out: list[Finding] = []
    for tool in tools:
        hit = _matches(tool.description, _SECRET_KEY_PATTERNS)
        if hit:
            redacted = hit[:8] + "…" if len(hit) > 8 else hit
            out.append(
                Finding(
                    rule_id="MCPL005",
                    severity=Severity.CRITICAL,
                    tool=tool.qualified_name,
                    message=f"possible hard-coded secret: {redacted!r}",
                    hint=(
                        "Never commit live credentials. Inject them from the "
                        "environment or a secret manager, and rotate anything that "
                        "was ever committed to git history."
                    ),
                )
            )
    return out


def rule_bind_all_interfaces(tools: list[Tool]) -> list[Finding]:
    """MCPL006: server launch binds 0.0.0.0 (all interfaces)."""

    out: list[Finding] = []
    for tool in tools:
        if _BIND_ALL_PATTERN.search(tool.description):
            out.append(
                Finding(
                    rule_id="MCPL006",
                    severity=Severity.MEDIUM,
                    tool=tool.qualified_name,
                    message="launch command binds 0.0.0.0 (exposed on all interfaces)",
                    hint=(
                        "Default to 127.0.0.1 for local use; bind 0.0.0.0 only when "
                        "you deliberately need LAN/remote access and have auth in front."
                    ),
                )
            )
    return out


def rule_unpinned_package(tools: list[Tool]) -> list[Finding]:
    """MCPL007: server launched from an unpinned package/image (@latest, :latest)."""

    out: list[Finding] = []
    for tool in tools:
        m = _UNPINNED_PATTERN.search(tool.description)
        if m:
            out.append(
                Finding(
                    rule_id="MCPL007",
                    severity=Severity.LOW,
                    tool=tool.qualified_name,
                    message=f"server launched from an unpinned reference: {m.group(0)!r}",
                    hint=(
                        "Pin the exact version. An unpinned MCP server can silently "
                        "change tool behavior — the supply-chain equivalent of "
                        "unreviewed remote code."
                    ),
                )
            )
    return out


def rule_name_shadowing(tools: list[Tool]) -> list[Finding]:
    """MCPL008: the same tool name is exposed by more than one server (shadowing)."""

    by_name: dict[str, set[str]] = defaultdict(set)
    for tool in tools:
        if tool.name == "<launch>":
            continue
        by_name[tool.name].add(tool.server)
    out: list[Finding] = []
    for name, servers in sorted(by_name.items()):
        if len(servers) > 1:
            joined = ", ".join(sorted(servers))
            for server in sorted(servers):
                out.append(
                    Finding(
                        rule_id="MCPL008",
                        severity=Severity.HIGH,
                        tool=f"{server}:{name}",
                        message=f"tool name {name!r} is exposed by multiple servers: {joined}",
                        hint=(
                            "Name collisions let a malicious server shadow a trusted "
                            "tool. Namespace tool names per server or pin which server "
                            "each name resolves to."
                        ),
                    )
                )
    return out


def rule_sensitive_capability(tools: list[Tool]) -> list[Finding]:
    """MCPL009: sensitive capability keywords in a tool's name or description."""
    out: list[Finding] = []
    for tool in tools:
        for field, text in (("name", tool.name), ("description", tool.description)):
            hit = _matches(text, _SENSITIVE_PATTERNS)
            if hit:
                out.append(Finding(
                    rule_id="MCPL009",
                    severity=Severity.MEDIUM,
                    tool=tool.qualified_name,
                    message=f"{field} mentions sensitive resource or capability: {hit!r}",
                    hint=(
                        "Confirm this capability matches the tool's intended purpose. "
                        "Remove unrelated access, restrict permissions, and require "
                        "approval for sensitive operations. A keyword alone does not prove misuse."
                    ),
                ))
                break
    return out


RULES: dict[str, Rule] = {
    "MCPL001": rule_tool_poisoning,
    "MCPL002": rule_undeclared_shell,
    "MCPL003": rule_destructive_fs,
    "MCPL004": rule_unconstrained_schema,
    "MCPL005": rule_secret_leak,
    "MCPL006": rule_bind_all_interfaces,
    "MCPL007": rule_unpinned_package,
    "MCPL008": rule_name_shadowing,
    "MCPL009": rule_sensitive_capability,
}

RULE_TITLES: dict[str, str] = {
    "MCPL001": "tool-poisoning / prompt injection in description",
    "MCPL002": "undeclared command-execution capability",
    "MCPL003": "destructive file-system capability",
    "MCPL004": "unconstrained input schema",
    "MCPL005": "hard-coded secret",
    "MCPL006": "binds all network interfaces",
    "MCPL007": "unpinned server package/image",
    "MCPL008": "tool-name shadowing across servers",
    "MCPL009": "sensitive resource or capability keyword",
}

import pytest

from mcp_lint.loaders import (
    LoadError,
    detect_and_load,
    load_client_config,
    load_tools_export,
)


def test_load_tools_export_envelope():
    tools = load_tools_export({"tools": [{"name": "a", "description": "d"}]})
    assert len(tools) == 1
    assert tools[0].name == "a"
    assert tools[0].description == "d"


def test_load_tools_export_bare_list():
    tools = load_tools_export([{"name": "a"}])
    assert tools[0].name == "a"
    assert tools[0].server == "<inline>"


def test_load_tools_export_snake_case_schema():
    tools = load_tools_export([{"name": "a", "input_schema": {"type": "object"}}])
    assert tools[0].input_schema == {"type": "object"}


def test_load_tools_rejects_missing_name():
    with pytest.raises(LoadError):
        load_tools_export([{"description": "no name"}])


def test_load_tools_rejects_bad_schema_type():
    with pytest.raises(LoadError):
        load_tools_export([{"name": "a", "inputSchema": "nope"}])


def test_load_client_config_folds_env_and_args():
    tools = load_client_config(
        {
            "mcpServers": {
                "s1": {"command": "npx", "args": ["pkg@latest"], "env": {"K": "v"}},
            }
        }
    )
    assert len(tools) == 1
    t = tools[0]
    assert t.server == "s1"
    assert t.name == "<launch>"
    assert "npx" in t.description
    assert "pkg@latest" in t.description
    assert "K=v" in t.description


def test_load_client_config_requires_mcpservers():
    with pytest.raises(LoadError):
        load_client_config({"nope": {}})


def test_detect_prefers_client_config():
    tools = detect_and_load({"mcpServers": {"s": {"command": "x"}}})
    assert tools[0].name == "<launch>"


def test_detect_falls_back_to_export():
    tools = detect_and_load([{"name": "z"}])
    assert tools[0].name == "z"

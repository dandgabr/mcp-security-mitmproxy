"""Conformance test — the 18-tool MCP surface (Fase 5, architecture 0001 §3.3).

Contract conformance for the *tool surface*, not behaviour: every tool is
discovered, its input schema is a single validated ``params`` object, and every
``*Output`` model is a ``ToolResult`` subclass so invariant I1 holds at the
schema level. Behavioural and E2E coverage lives in
``tests/integration/`` and ``tests/unit/``; this file is the static inventory
gate that catches a tool silently disappearing or gaining an untyped input.

The expected set is derived from the architecture catalogue (0001 §3.3 plus the
six Fase 4 rules tools in 0003), stated per family so a diff points at the
phase that regressed.
"""

from __future__ import annotations

import pytest

from mcp_security_mitmproxy.schemas.common import ToolResult
from mcp_security_mitmproxy.server import create_server

# Fase 3 — one family per executable plus core/session.
PHASE3_TOOLS = frozenset(
    {
        "mitmdump_start",
        "mitmdump_stop",
        "mitmdump_replay",
        "mitmweb_start",
        "mitmweb_stop",
        "mitmweb_get_flows",
        "mitmweb_get_flow_detail",
        "mitm_execute_command",
        "mitm_export_flow",
        "mitm_filter_flows",
        "session_list",
        "session_status",
    }
)

# Fase 4 — one per rule family plus list/clear.
PHASE4_TOOLS = frozenset(
    {
        "mitm_set_map_remote",
        "mitm_set_map_local",
        "mitm_modify_headers",
        "mitm_modify_body",
        "mitm_list_rules",
        "mitm_clear_rules",
    }
)

EXPECTED_TOOLS = PHASE3_TOOLS | PHASE4_TOOLS

# Tools whose input is the empty contract (no agent-supplied parameters).
PARAMETERLESS_TOOLS = frozenset({"session_list"})


@pytest.fixture
def tool_map():
    """The live tool surface, keyed by name. No proxy is started."""
    server = create_server()
    # ``list_tools`` is async; run it without a running event loop so this
    # fixture stays usable from both sync and async tests.
    import asyncio

    tools = asyncio.run(server.list_tools())
    return {tool.name: tool for tool in tools}


def test_surface_has_exactly_eighteen_tools(tool_map) -> None:
    assert len(tool_map) == 18


def test_expected_tool_set_is_exactly_present(tool_map) -> None:
    names = set(tool_map)
    assert names == EXPECTED_TOOLS, (
        f"missing={sorted(EXPECTED_TOOLS - names)} unexpected={sorted(names - EXPECTED_TOOLS)}"
    )


def test_phase3_family_is_complete(tool_map) -> None:
    assert set(tool_map) >= PHASE3_TOOLS


def test_phase4_family_is_complete(tool_map) -> None:
    assert set(tool_map) >= PHASE4_TOOLS


def test_every_tool_has_a_description(tool_map) -> None:
    missing = [name for name, tool in tool_map.items() if not (tool.description or "").strip()]
    assert missing == []


def test_every_tool_declares_exactly_one_input_object(tool_map) -> None:
    """Each tool takes one ``params`` model — never a flattened or untyped arg bag."""
    for name, tool in tool_map.items():
        params = tool.parameters or {}
        props = params.get("properties", {})
        if name in PARAMETERLESS_TOOLS:
            assert props == {}, f"{name} must accept no parameters"
            continue
        assert props, f"{name} declares no input schema"
        assert set(props) == {"params"}, (
            f"{name} must expose a single 'params' object, got {set(props)}"
        )
        assert params.get("required") == ["params"], f"{name} must require 'params'"
        assert params.get("additionalProperties") is False, (
            f"{name} must set additionalProperties=false"
        )


def test_every_tool_declares_a_typed_output_schema(tool_map) -> None:
    """The output contract must be published, not implicit."""
    missing = [name for name, tool in tool_map.items() if not tool.output_schema]
    assert missing == []


@pytest.mark.parametrize("tool_name", sorted(EXPECTED_TOOLS))
def test_output_schema_root_is_a_tool_result(tool_map, tool_name: str) -> None:
    """Every output carries the ``ok`` flag — the I1 envelope is on the wire."""
    schema = tool_map[tool_name].output_schema or {}
    props = schema.get("properties", {})
    assert "ok" in props, f"{tool_name} output is missing the ToolResult 'ok' field"


def test_tool_result_envelope_shape() -> None:
    """The shared envelope is the contract every output extends."""
    schema = ToolResult.model_json_schema()
    assert set(schema["required"]) == {"ok"}
    assert schema["properties"]["ok"]["type"] == "boolean"


def test_reserved_set_options_covers_all_mutation_families() -> None:
    """Fase 4 hardening: no raw --set may reach a mutation option."""
    from mcp_security_mitmproxy.schemas.common import RESERVED_SET_OPTIONS

    required = {
        "confdir",
        "scripts",
        "map_local",
        "map_remote",
        "modify_headers",
        "modify_body",
        "save_stream_file",
        "hardump",
    }
    assert required <= RESERVED_SET_OPTIONS


def test_server_instructions_mention_sessions() -> None:
    server = create_server()
    assert "mitmproxy" in (server.instructions or "")

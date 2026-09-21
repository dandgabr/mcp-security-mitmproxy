"""Static initialization tests for the FastMCP server.

DoD Fase 1: the server must be constructible and inspectable with no mitmproxy
subprocess and no network. These tests never start a proxy.
"""

from __future__ import annotations

import pytest

from mcp_security_mitmproxy import __version__
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.server import SERVER_NAME, app_lifespan, create_server, mcp


def test_create_server_returns_fastmcp_instance() -> None:
    server = create_server()
    assert server.name == SERVER_NAME
    assert server.version == __version__
    assert server.instructions


def test_module_level_server_is_constructed() -> None:
    assert mcp.name == SERVER_NAME
    assert mcp.version == __version__


def test_create_server_is_side_effect_free() -> None:
    first = create_server()
    second = create_server()
    assert first is not second
    assert first.name == second.name == SERVER_NAME


@pytest.mark.asyncio
async def test_lifespan_yields_registry_without_starting_proxy() -> None:
    server = create_server()
    async with app_lifespan(server) as context:
        assert isinstance(context, LifespanContext)
        assert context.settings.web_host == "127.0.0.1"
        assert context.settings.binds_publicly is False
        assert context.registry.active_count == 0
    assert context.registry.active_count == 0


def test_server_name_constant() -> None:
    assert SERVER_NAME == "mcp-security-mitmproxy"

"""Unit and mock tests for FastMCP tools (Fase 3)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import Context, FastMCP
from mitmproxy import io as mio
from mitmproxy.test import tflow

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.core.session import SessionRegistry
from mcp_security_mitmproxy.schemas.common import ExportFormat, ProxyMode, SessionStatus
from mcp_security_mitmproxy.schemas.core_commands import (
    MitmExecuteCommandInput,
    MitmExportFlowInput,
    MitmFilterFlowsInput,
)
from mcp_security_mitmproxy.schemas.mitmdump import (
    MitmdumpStartInput,
)
from mcp_security_mitmproxy.schemas.mitmweb import (
    MitmwebGetFlowsInput,
    MitmwebStartInput,
)
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec, SessionState, StopInput
from mcp_security_mitmproxy.server import create_server


@pytest.fixture
def test_env(tmp_path: Path) -> tuple[FastMCP, LifespanContext, Context]:
    server = create_server()
    settings = Settings(
        allowed_dump_roots=[tmp_path],
        allowed_script_roots=[tmp_path],
        session_root=tmp_path / "sessions",
    )
    registry = SessionRegistry(settings)
    lc = LifespanContext(settings=settings, registry=registry)

    # Mock fastmcp.Context
    ctx = MagicMock(spec=Context)
    ctx.lifespan_context = lc

    return server, lc, ctx


@pytest.mark.asyncio
async def test_mitmdump_start_and_stop_mocked(test_env) -> None:
    server, lc, ctx = test_env

    # We mock registry.start
    with patch.object(lc.registry, "start", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = SessionState(
            session_id="dummy-1",
            executable="mitmdump",
            status=SessionStatus.RUNNING,
        )

        tool = await server.get_tool("mitmdump_start")
        res = await tool.fn(
            MitmdumpStartInput(mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=8080)]),
            ctx,
        )
        assert res.ok is True
        assert res.session.session_id == "dummy-1"
        assert mock_start.await_count == 1

    with patch.object(lc.registry, "stop", new_callable=AsyncMock) as mock_stop:
        mock_stop.return_value = SessionState(
            session_id="dummy-1",
            executable="mitmdump",
            status=SessionStatus.STOPPED,
        )

        tool_stop = await server.get_tool("mitmdump_stop")
        res_stop = await tool_stop.fn(StopInput(session_id="dummy-1"), ctx)
        assert res_stop.ok is True
        assert mock_stop.await_count == 1


@pytest.mark.asyncio
async def test_mitmdump_start_rejects_disallowed_save_path(test_env) -> None:
    server, lc, ctx = test_env
    tool = await server.get_tool("mitmdump_start")

    res = await tool.fn(
        MitmdumpStartInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=8080)],
            save_path="/etc/evil.mitm",
        ),
        ctx,
    )
    assert res.ok is False
    assert res.error is not None
    assert res.error.code.value == "PATH_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_mitmweb_start_allocates_and_registers(test_env) -> None:
    server, lc, ctx = test_env

    with patch.object(lc.registry, "start", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = SessionState(
            session_id="web-1",
            executable="mitmweb",
            status=SessionStatus.RUNNING,
            web_host="127.0.0.1",
            web_port=8081,
        )

        tool = await server.get_tool("mitmweb_start")
        res = await tool.fn(
            MitmwebStartInput(
                mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=8080)],
                web_port=8081,
            ),
            ctx,
        )
        assert res.ok is True
        assert res.web_url == "http://127.0.0.1:8081/"
        assert mock_start.await_count == 1


@pytest.mark.asyncio
async def test_mitmweb_get_flows_requires_running_session(test_env) -> None:
    server, lc, ctx = test_env

    # Empty registry -> session not found
    tool = await server.get_tool("mitmweb_get_flows")
    res = await tool.fn(
        MitmwebGetFlowsInput(session_id="nonexistent"),
        ctx,
    )
    assert res.ok is False
    assert res.error.code.value == "SESSION_NOT_FOUND"


@pytest.mark.asyncio
async def test_mitm_execute_command_enforces_allowlist(test_env) -> None:
    server, lc, ctx = test_env
    tool = await server.get_tool("mitm_execute_command")

    res = await tool.fn(
        MitmExecuteCommandInput(
            session_id="web-1",
            command="system.sh",  # evil command
            arguments=["rm -rf /"],
        ),
        ctx,
    )
    assert res.ok is False
    assert res.error.code.value == "COMMAND_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_mitm_export_flow_from_dump(test_env, tmp_path: Path) -> None:
    server, lc, ctx = test_env

    dump_file = tmp_path / "dump.mitm"
    f = tflow.tflow(resp=True)
    with dump_file.open("wb") as fl:
        mio.FlowWriter(fl).add(f)

    tool = await server.get_tool("mitm_export_flow")
    res = await tool.fn(
        MitmExportFlowInput(
            flow_id=f.id,
            format=ExportFormat.CURL,
            flow_path=str(dump_file),
        ),
        ctx,
    )
    assert res.ok is True
    assert res.content is not None
    assert "curl" in res.content
    assert res.format == ExportFormat.CURL


@pytest.mark.asyncio
async def test_mitm_filter_flows_from_dump(test_env, tmp_path: Path) -> None:
    server, lc, ctx = test_env

    dump_file = tmp_path / "dump.mitm"
    f1 = tflow.tflow(resp=True)
    f2 = tflow.tflow(resp=True)
    f2.request.method = "POST"

    with dump_file.open("wb") as fl:
        w = mio.FlowWriter(fl)
        w.add(f1)
        w.add(f2)

    tool = await server.get_tool("mitm_filter_flows")
    res = await tool.fn(
        MitmFilterFlowsInput(
            flow_path=str(dump_file),
            expression="~m POST",
        ),
        ctx,
    )
    assert res.ok is True
    assert res.count == 1
    assert len(res.matched) == 1
    assert res.matched[0].method == "POST"


@pytest.mark.asyncio
async def test_mitmweb_start_keeps_web_password_off_argv(test_env) -> None:
    server, lc, ctx = test_env
    secret = "s3cr3t-web-password"

    with patch.object(lc.registry, "start", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = SessionState(
            session_id="web-1",
            executable="mitmweb",
            status=SessionStatus.RUNNING,
            web_host="127.0.0.1",
            web_port=8081,
        )

        tool = await server.get_tool("mitmweb_start")
        res = await tool.fn(
            MitmwebStartInput(
                mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=8080)],
                web_port=8081,
                web_password=secret,
            ),
            ctx,
        )

    assert res.ok is True, res.error
    assert secret not in res.model_dump_json()

    kwargs = mock_start.await_args.kwargs
    assert kwargs["web_token"] == secret
    assert kwargs["isolate_confdir"] is True
    assert kwargs["config_options"] == {"web_password": secret}
    assert all(secret not in element for element in kwargs["argv"])
    assert not any("web_password" in element for element in kwargs["argv"])

    # web_port binds web_host, the proxy ports bind listen_host (SEC-4/B5).
    assert kwargs["listen_ports"] == [8080, 8081]
    assert kwargs["port_hosts"] == ["127.0.0.1", "127.0.0.1"]


@pytest.mark.asyncio
async def test_mitmweb_start_generates_token_off_argv(test_env) -> None:
    server, lc, ctx = test_env

    with patch.object(lc.registry, "start", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = SessionState(
            session_id="web-2",
            executable="mitmweb",
            status=SessionStatus.RUNNING,
            web_host="127.0.0.1",
            web_port=8081,
        )

        tool = await server.get_tool("mitmweb_start")
        res = await tool.fn(
            MitmwebStartInput(
                mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=8080)],
                web_port=8081,
            ),
            ctx,
        )

    assert res.ok is True, res.error
    token = mock_start.await_args.kwargs["web_token"]
    assert isinstance(token, str)
    assert len(token) == 32
    assert set(token) <= set("0123456789abcdef")

    kwargs = mock_start.await_args.kwargs
    assert kwargs["config_options"] == {"web_password": token}
    assert all(token not in element for element in kwargs["argv"])
    assert token not in res.model_dump_json()


@pytest.mark.asyncio
async def test_mitm_export_flow_from_dump_redacts_credentials(test_env, tmp_path: Path) -> None:
    server, lc, ctx = test_env

    flow = tflow.tflow(resp=True)
    flow.request.headers["Authorization"] = "Bearer super-secret-token"
    flow.request.headers["Cookie"] = "session=abc123"
    flow.response.headers["Set-Cookie"] = "sid=xyz"

    dump_file = tmp_path / "secrets.mitm"
    with dump_file.open("wb") as handle:
        mio.FlowWriter(handle).add(flow)

    tool = await server.get_tool("mitm_export_flow")
    for fmt in (ExportFormat.CURL, ExportFormat.HTTPIE, ExportFormat.RAW):
        res = await tool.fn(
            MitmExportFlowInput(
                flow_id=flow.id,
                format=fmt,
                flow_path=str(dump_file),
            ),
            ctx,
        )

        assert res.ok is True, res.error
        assert res.content is not None
        assert "super-secret-token" not in res.content
        assert "session=abc123" not in res.content
        assert "sid=xyz" not in res.content
        assert "[REDACTED]" in res.content

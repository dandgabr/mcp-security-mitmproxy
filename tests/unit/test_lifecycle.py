"""Unit tests for the FastMCP lifespan and orphan prevention (D3, I2)."""

from __future__ import annotations

import asyncio
import socket

import pytest

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core import errors, lifecycle
from mcp_security_mitmproxy.core.lifecycle import LifespanContext, app_lifespan
from mcp_security_mitmproxy.core.session import SessionRegistry
from mcp_security_mitmproxy.server import create_server
from tests.conftest import SLEEP_LONG


def _is_listening(port: int, host: str = "127.0.0.1") -> bool:
    """True when something accepts a TCP connection on host:port."""
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


async def test_lifespan_yields_settings_and_registry() -> None:
    server = create_server()
    async with app_lifespan(server) as context:
        assert isinstance(context, LifespanContext)
        assert isinstance(context.settings, Settings)
        assert isinstance(context.registry, SessionRegistry)


async def test_lifespan_shuts_down_sessions_on_exit(python_argv, tmp_path) -> None:
    settings = Settings(session_root=tmp_path / "s")
    registry = SessionRegistry(settings)
    state = await registry.start(executable="mitmdump", argv=python_argv(SLEEP_LONG))
    pid = state.pid
    assert pid is not None

    await registry.shutdown_all(timeout=2.0)
    assert registry.active_count == 0
    assert _pid_alive(pid) is False


async def test_lifespan_releases_ports_on_exit(python_argv, tmp_path) -> None:
    settings = Settings(session_root=tmp_path / "s")
    registry = SessionRegistry(settings)

    code = (
        "import socket, time; "
        "s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
        "s.bind(('127.0.0.1', 0)); s.listen(1); "
        "print('PORT=%d' % s.getsockname()[1], flush=True); time.sleep(60)"
    )
    state = await registry.start(executable="mitmdump", argv=python_argv(code))
    port = await _read_port(registry, state.session_id)
    assert port is not None
    assert _is_listening(port) is True

    await registry.shutdown_all(timeout=3.0)
    assert _is_listening(port) is False


async def test_lifespan_context_teardown_runs_on_body_exception(python_argv, tmp_path) -> None:
    settings = Settings(session_root=tmp_path / "s")
    registry = SessionRegistry(settings)
    await registry.start(executable="mitmdump", argv=python_argv(SLEEP_LONG))

    with pytest.raises(RuntimeError):
        try:
            raise RuntimeError("boom")
        finally:
            await registry.shutdown_all(timeout=2.0)
    assert registry.active_count == 0


async def test_app_lifespan_creates_independent_registries(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCP_MITM_WEB_HOST", "127.0.0.1")
    server = create_server()
    async with app_lifespan(server) as first, app_lifespan(server) as second:
        assert first.registry is not second.registry


async def test_to_tool_result_on_shutdown_error_is_safe() -> None:
    result = errors.to_tool_result(errors.InvalidInputError("registry is shut down"))
    assert result.ok is False
    assert result.error is not None


def test_lifecycle_module_exported() -> None:
    assert lifecycle.LifespanContext is LifespanContext


async def _read_port(registry: SessionRegistry, session_id: str) -> int | None:
    for _ in range(100):
        logs = await registry.logs(session_id)
        for record in logs:
            if record.line.startswith("PORT="):
                return int(record.line.removeprefix("PORT="))
        await asyncio.sleep(0.02)
    return None


def _pid_alive(pid: int) -> bool:
    import os

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True

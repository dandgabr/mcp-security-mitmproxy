"""Load, stress and lifecycle-resilience checks — plan 0004 §2.7 and §3.

Covers the plan's metrics table:

* port leaks: 0 after teardown (``ss -ltn`` before and after the 20 cycles);
* orphan processes: 0 (``ps`` scan by the subprocess's unique argv marker);
* concurrent sessions: 20 starts through ``asyncio.gather`` without deadlock,
  and an empty ``session_list`` at the end;
* a session killed by an external SIGKILL transitions to ``FAILED`` and releases
  the port;
* ``PORT_IN_USE`` when a third party already holds the port;
* ``start`` and ``stop`` timings measured separately, asserting the teardown.

The subprocesses are ``python -c`` snippets carrying a unique marker in argv:
the target is port leasing and the teardown in ``core/session.py``, not the
Tornado boot (that one is covered by the traffic E2E).
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastmcp import Context

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.errors import PortInUseError, ProcessSpawnFailedError
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.core.session import SessionRegistry, allocate_ephemeral_port
from mcp_security_mitmproxy.schemas.common import SessionStatus
from mcp_security_mitmproxy.schemas.process import SessionListOutput
from mcp_security_mitmproxy.server import create_server

_SESSIONS = 20
_START_BUDGET_SECONDS = 15.0
_STOP_BUDGET_SECONDS = 10.0
_SHUTDOWN_TIMEOUT = 10.0
_SLEEP_SECONDS = 120


def _settings(tmp_path: Path) -> Settings:
    return Settings(session_root=tmp_path / "sessions", log_capacity=20)


def _sleep_argv(marker: str) -> list[str]:
    """A ``python -c`` sleeper whose argv carries a unique, greppable marker."""
    return [sys.executable, "-c", f"# {marker}\nimport time; time.sleep({_SLEEP_SECONDS})"]


def _can_bind(host: str, port: int) -> bool:
    """True when the port accepts a fresh bind (no leaked listener)."""
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def _process_gone(pid: int, *, timeout: float = 5.0) -> bool:
    """True once ``pid`` no longer exists.

    ``os.kill(pid, 0)`` also succeeds for a zombie, so this doubles as a reaping
    check: the registry awaits ``proc.wait()``, leaving no unreaped child.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:  # pragma: no cover - foreign process, still alive
            return False
        time.sleep(0.05)
    return False


def _listening_ports() -> set[int]:
    """Local ports currently in LISTEN, per ``ss -ltn``."""
    try:
        output = subprocess.run(
            ["ss", "-ltn"], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - no iproute2
        return set()
    ports: set[int] = set()
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        port = fields[3].rpartition(":")[2]
        if port.isdigit():
            ports.add(int(port))
    return ports


def _processes_with_marker(marker: str) -> list[str]:
    """``ps`` rows whose argv still carries the marker."""
    try:
        output = subprocess.run(
            ["ps", "-eo", "pid=,args="], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return []
    return [line.strip() for line in output.splitlines() if marker in line]


async def _session_list(registry: SessionRegistry) -> SessionListOutput:
    """Call the real ``session_list`` tool against the live registry."""
    server = create_server()
    ctx = MagicMock(spec=Context)
    ctx.lifespan_context = LifespanContext(settings=registry.settings, registry=registry)
    tool = await server.get_tool("session_list")
    return await tool.fn(ctx)


async def test_twenty_concurrent_sessions_teardown_leaks_nothing(tmp_path) -> None:
    """20 sessions open and close concurrently; 0 leaked ports, 0 orphans."""
    registry = SessionRegistry(_settings(tmp_path))
    session_root = tmp_path / "sessions"
    marker = f"qa-load-{uuid.uuid4().hex}"
    argv = _sleep_argv(marker)
    ports = [allocate_ephemeral_port() for _ in range(_SESSIONS)]
    listeners_before = _listening_ports()

    states = await asyncio.gather(
        *(registry.start(executable="mitmdump", argv=argv, listen_ports=[port]) for port in ports)
    )
    pids = [state.pid for state in states if state.pid is not None]

    assert len(pids) == _SESSIONS
    assert len({state.session_id for state in states}) == _SESSIONS
    assert all(state.status is SessionStatus.RUNNING for state in states)
    assert all(registry.port_in_use(port) for port in ports)
    assert len(_processes_with_marker(marker)) == _SESSIONS, "not every child is running"

    # Concurrent stops: no deadlock, every session reaches STOPPED.
    await asyncio.gather(*(registry.stop(state.session_id, force=True) for state in states))

    assert all(registry.get(state.session_id).status is SessionStatus.STOPPED for state in states)
    assert not any(registry.port_in_use(port) for port in ports)
    assert all(_process_gone(pid) for pid in pids)
    assert all(_can_bind("127.0.0.1", port) for port in ports)
    assert _processes_with_marker(marker) == []

    await registry.shutdown_all(timeout=_SHUTDOWN_TIMEOUT)
    assert registry.active_count == 0
    assert list(session_root.iterdir()) == []
    assert await _session_list(registry) == SessionListOutput(ok=True, sessions=[])

    leaked = _listening_ports() - listeners_before
    assert not (leaked & set(ports)), f"ports still in LISTEN after teardown: {leaked & set(ports)}"


async def test_external_sigkill_marks_failed_and_frees_the_port(tmp_path) -> None:
    """A subprocess killed from outside must surface as FAILED, not RUNNING."""
    registry = SessionRegistry(_settings(tmp_path))
    port = allocate_ephemeral_port()
    state = await registry.start(
        executable="mitmdump", argv=_sleep_argv(f"qa-kill-{uuid.uuid4().hex}"), listen_ports=[port]
    )
    assert state.pid is not None

    os.kill(state.pid, signal.SIGKILL)

    deadline = time.time() + 10
    while (
        time.time() < deadline and registry.get(state.session_id).status is not SessionStatus.FAILED
    ):
        await asyncio.sleep(0.05)

    assert registry.get(state.session_id).status is SessionStatus.FAILED
    assert registry.get(state.session_id).exit_code not in (None, 0)

    # The child is gone and the OS-level port is free; remove() clears the lease.
    assert _process_gone(state.pid)
    assert _can_bind("127.0.0.1", port)
    await registry.remove(state.session_id)
    assert not registry.port_in_use(port)
    assert registry.active_count == 0


async def test_port_held_by_a_third_party_yields_port_in_use(tmp_path) -> None:
    registry = SessionRegistry(_settings(tmp_path))
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        held.listen(1)
        port = held.getsockname()[1]

        with pytest.raises(PortInUseError) as excinfo:
            await registry.start(
                executable="mitmdump",
                argv=_sleep_argv(f"qa-held-{uuid.uuid4().hex}"),
                listen_ports=[port],
            )

    assert excinfo.value.detail == {"host": "127.0.0.1", "port": port}
    assert registry.active_count == 0
    # The lease check precedes SessionDirectory.create, so nothing is created.
    assert not (tmp_path / "sessions").exists()


async def test_start_and_stop_are_bounded_and_teardown_is_asserted(tmp_path) -> None:
    """Measure start and stop separately: the risk lives in stop, not start."""
    registry = SessionRegistry(_settings(tmp_path))
    port = allocate_ephemeral_port()
    argv = _sleep_argv(f"qa-timing-{uuid.uuid4().hex}")

    started_at = time.perf_counter()
    state = await registry.start(executable="mitmdump", argv=argv, listen_ports=[port])
    start_seconds = time.perf_counter() - started_at
    assert start_seconds < _START_BUDGET_SECONDS, f"start took {start_seconds:.2f}s"

    stopped_at = time.perf_counter()
    await registry.stop(state.session_id, force=True)
    stop_seconds = time.perf_counter() - stopped_at
    assert stop_seconds < _STOP_BUDGET_SECONDS, f"stop took {stop_seconds:.2f}s"

    assert state.pid is not None and _process_gone(state.pid)
    assert _can_bind("127.0.0.1", port)
    assert not registry.port_in_use(port)

    await registry.remove(state.session_id)
    assert registry.active_count == 0


async def test_racing_requests_for_one_port_have_a_single_winner(tmp_path) -> None:
    """Six racers, one port: the lease check precedes any await, so one wins."""
    registry = SessionRegistry(_settings(tmp_path))
    session_root = tmp_path / "sessions"
    port = allocate_ephemeral_port()
    argv = _sleep_argv(f"qa-race-{uuid.uuid4().hex}")

    outcomes = await asyncio.gather(
        *(registry.start(executable="mitmdump", argv=argv, listen_ports=[port]) for _ in range(6)),
        return_exceptions=True,
    )

    winners = [o for o in outcomes if not isinstance(o, BaseException)]
    losers = [o for o in outcomes if isinstance(o, PortInUseError)]
    assert len(winners) == 1, f"expected a single winner, got {len(winners)}"
    assert len(losers) == 5
    assert registry.active_count == 1
    assert len(list(session_root.iterdir())) == 1, "a loser left a session directory behind"

    await registry.shutdown_all(timeout=_SHUTDOWN_TIMEOUT)
    assert _can_bind("127.0.0.1", port)
    assert list(session_root.iterdir()) == []


async def test_spawn_failure_releases_port_and_session_directory(tmp_path) -> None:
    """A failed spawn must unwind the lease and the 0700 tree it created."""
    registry = SessionRegistry(_settings(tmp_path))
    port = allocate_ephemeral_port()

    with pytest.raises(ProcessSpawnFailedError):
        await registry.start(
            executable="mitmdump",
            argv=["/nonexistent/mitmproxy-binary"],
            listen_ports=[port],
        )

    assert registry.active_count == 0
    assert not registry.port_in_use(port)
    assert _can_bind("127.0.0.1", port)
    assert list((tmp_path / "sessions").iterdir()) == []


async def test_leased_port_is_released_on_stop_and_reusable(tmp_path) -> None:
    """stop() releases the lease but keeps the entry; remove() drops it."""
    registry = SessionRegistry(_settings(tmp_path))
    session_root = tmp_path / "sessions"
    port = allocate_ephemeral_port()
    argv = _sleep_argv(f"qa-lease-{uuid.uuid4().hex}")

    state = await registry.start(executable="mitmdump", argv=argv, listen_ports=[port])
    assert registry.port_in_use(port)

    await registry.stop(state.session_id, force=True)
    assert not registry.port_in_use(port)  # lease released
    assert registry.active_count == 1  # a stopped session stays inspectable
    assert _can_bind("127.0.0.1", port)

    await registry.remove(state.session_id)
    assert registry.active_count == 0
    assert list(session_root.iterdir()) == []

    second = await registry.start(executable="mitmdump", argv=argv, listen_ports=[port])
    assert registry.port_in_use(port)
    await registry.remove(second.session_id)
    assert not registry.port_in_use(port)
    assert registry.active_count == 0


async def test_shutdown_all_frees_every_lease_and_is_idempotent(tmp_path) -> None:
    """I2: teardown is total, and a second sweep is a no-op."""
    settings = _settings(tmp_path)
    registry = SessionRegistry(settings)
    argv = _sleep_argv(f"qa-shutdown-{uuid.uuid4().hex}")
    ports = [allocate_ephemeral_port() for _ in range(_SESSIONS)]
    pids: list[int] = []

    for port in ports:
        state = await registry.start(executable="mitmdump", argv=argv, listen_ports=[port])
        assert state.pid is not None
        pids.append(state.pid)

    results = await registry.shutdown_all(timeout=_SHUTDOWN_TIMEOUT)

    assert len(results) == _SESSIONS
    assert all(result.status is SessionStatus.STOPPED for result in results)
    assert registry.active_count == 0
    for pid in pids:
        assert _process_gone(pid), f"process {pid} survived shutdown_all"
    for port in ports:
        assert _can_bind("127.0.0.1", port), f"port {port} is still bound"
    assert settings.session_root.exists()
    assert list(settings.session_root.iterdir()) == []

    assert await registry.shutdown_all(timeout=_SHUTDOWN_TIMEOUT) == []
    for pid in pids:
        assert _process_gone(pid)

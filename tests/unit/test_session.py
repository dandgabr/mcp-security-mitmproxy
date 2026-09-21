"""Unit tests for the session registry, port leases and temp isolation."""

from __future__ import annotations

import os
import socket
import stat

import pytest

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.errors import (
    InvalidInputError,
    PortInUseError,
    SessionNotFoundError,
)
from mcp_security_mitmproxy.core.process import ProcessExit, RingBuffer
from mcp_security_mitmproxy.core.session import (
    SessionDirectory,
    SessionRegistry,
    allocate_ephemeral_port,
)
from mcp_security_mitmproxy.schemas.common import SessionStatus
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec
from tests.conftest import EXIT_NONZERO, EXIT_ZERO, SLEEP_LONG


@pytest.fixture
def settings(tmp_path):
    return Settings(session_root=tmp_path / "sessions", log_capacity=20)


def test_session_directory_layout_and_permissions(tmp_path) -> None:
    directory = SessionDirectory.create(tmp_path, "abc")
    assert directory.dumps.is_dir()
    assert directory.ca.is_dir()
    assert directory.logs.is_dir()
    mode = stat.S_IMODE(os.stat(directory.root).st_mode)
    assert mode == 0o700


def test_session_directory_cleanup(tmp_path) -> None:
    directory = SessionDirectory.create(tmp_path, "abc")
    directory.cleanup()
    assert not directory.root.exists()


def test_allocate_ephemeral_port_returns_bindable_port() -> None:
    port = allocate_ephemeral_port()
    assert 1 <= port <= 65535
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))


async def test_registry_start_and_stop(python_argv, settings) -> None:
    registry = SessionRegistry(settings)
    state = await registry.start(executable="mitmdump", argv=python_argv(SLEEP_LONG))
    assert state.status is SessionStatus.RUNNING
    assert state.pid is not None
    assert registry.active_count == 1
    stopped = await registry.stop(state.session_id, force=True)
    assert stopped.status is SessionStatus.STOPPED
    assert registry.get(state.session_id).exit_code is not None


async def test_registry_isolates_session_directories(python_argv, settings) -> None:
    registry = SessionRegistry(settings)
    first = await registry.start(executable="mitmdump", argv=python_argv(SLEEP_LONG))
    second = await registry.start(executable="mitmdump", argv=python_argv(SLEEP_LONG))
    root = settings.session_root
    assert (root / first.session_id).is_dir()
    assert (root / second.session_id).is_dir()
    assert first.session_id != second.session_id
    await registry.shutdown_all(timeout=2.0)


async def test_registry_rejects_duplicate_port(python_argv, settings) -> None:
    registry = SessionRegistry(settings)
    port = allocate_ephemeral_port()
    await registry.start(executable="mitmdump", argv=python_argv(SLEEP_LONG), listen_ports=[port])
    with pytest.raises(PortInUseError):
        await registry.start(
            executable="mitmdump", argv=python_argv(SLEEP_LONG), listen_ports=[port]
        )
    await registry.shutdown_all(timeout=2.0)


async def test_registry_rejects_port_held_externally(settings, python_argv) -> None:
    registry = SessionRegistry(settings)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        held = sock.getsockname()[1]
        with pytest.raises(PortInUseError):
            await registry.start(
                executable="mitmdump",
                argv=python_argv(SLEEP_LONG),
                listen_ports=[held],
            )


async def test_registry_unknown_session_raises(settings) -> None:
    registry = SessionRegistry(settings)
    with pytest.raises(SessionNotFoundError):
        registry.get("ghost")
    with pytest.raises(SessionNotFoundError):
        await registry.stop("ghost")


async def test_registry_remove_cleans_directory(python_argv, settings) -> None:
    registry = SessionRegistry(settings)
    state = await registry.start(executable="mitmdump", argv=python_argv(SLEEP_LONG))
    session_dir = settings.session_root / state.session_id
    assert session_dir.is_dir()
    await registry.remove(state.session_id)
    assert not session_dir.exists()
    assert registry.active_count == 0


async def test_registry_maps_nonzero_exit_to_failed(python_argv, settings) -> None:
    registry = SessionRegistry(settings)
    await registry.start(executable="mitmdump", argv=python_argv(EXIT_ZERO))
    state = registry.list()[0]
    await _await_status(registry, state.session_id, SessionStatus.STOPPED)
    assert registry.get(state.session_id).exit_code == 0

    registry2 = SessionRegistry(settings)
    await registry2.start(executable="mitmdump", argv=python_argv(EXIT_NONZERO))
    state2 = registry2.list()[0]
    await _await_status(registry2, state2.session_id, SessionStatus.FAILED)
    assert registry2.get(state2.session_id).exit_code == 3


async def test_registry_shutdown_all_is_idempotent(python_argv, settings) -> None:
    registry = SessionRegistry(settings)
    await registry.start(executable="mitmdump", argv=python_argv(SLEEP_LONG))
    await registry.start(executable="mitmdump", argv=python_argv(SLEEP_LONG))
    first = await registry.shutdown_all(timeout=2.0)
    assert len(first) == 2
    assert registry.active_count == 0
    second = await registry.shutdown_all(timeout=2.0)
    assert second == []


async def test_registry_shutdown_rejects_new_sessions(settings, python_argv) -> None:
    registry = SessionRegistry(settings)
    await registry.shutdown_all()
    with pytest.raises(InvalidInputError):
        await registry.start(executable="mitmdump", argv=python_argv(SLEEP_LONG))


async def test_registry_records_modes(python_argv, settings) -> None:
    from mcp_security_mitmproxy.schemas.common import ProxyMode

    registry = SessionRegistry(settings)
    mode = ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=18888)
    state = await registry.start(
        executable="mitmdump",
        argv=python_argv(SLEEP_LONG),
        modes=[mode],
        web_host="127.0.0.1",
        web_port=8081,
    )
    assert state.modes == [mode]
    assert state.web_host == "127.0.0.1"
    assert state.web_port == 8081
    await registry.shutdown_all(timeout=2.0)


async def _await_status(registry: SessionRegistry, session_id: str, status: SessionStatus):
    import asyncio

    for _ in range(100):
        if registry.get(session_id).status is status:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"session {session_id} never reached {status}")


class _FakeRunner:
    """Records the argv the registry hands to the process layer (no spawn).

    The behaviour under test here is argv assembly and config-file placement;
    actual spawning is exercised by the tests that use the real ProcessRunner.
    """

    instances: list[_FakeRunner] = []

    def __init__(self, argv, *, settings, cwd=None, env=None, on_exit=None) -> None:
        self._argv = list(argv)
        self._logs = RingBuffer(settings.log_capacity)
        self._cwd = cwd
        self._on_exit = on_exit
        _FakeRunner.instances.append(self)

    @property
    def argv(self) -> list[str]:
        return list(self._argv)

    @property
    def logs(self) -> RingBuffer:
        return self._logs

    @property
    def running(self) -> bool:
        return False

    async def start(self) -> int:
        return 4242

    async def stop(self, *, timeout=None, force=False, sig=None) -> ProcessExit:
        return ProcessExit(returncode=0, forced_kill=force)


@pytest.fixture
def fake_runner(monkeypatch):
    _FakeRunner.instances.clear()
    monkeypatch.setattr("mcp_security_mitmproxy.core.session.ProcessRunner", _FakeRunner)
    return _FakeRunner


async def test_start_injects_isolated_confdir_after_executable(settings, fake_runner) -> None:
    registry = SessionRegistry(settings)
    argv = ["mitmweb", "--set", "web_host=127.0.0.1", "--listen-port", "8080"]

    state = await registry.start(executable="mitmweb", argv=argv, isolate_confdir=True)

    session_argv = registry.get_runner(state.session_id).argv
    expected_confdir = str(settings.session_root / state.session_id)
    assert session_argv[0] == "mitmweb"
    assert session_argv[1:3] == ["--set", f"confdir={expected_confdir}"]
    assert session_argv[3:] == argv[1:]
    await registry.shutdown_all()


async def test_start_without_isolate_confdir_preserves_argv(settings, fake_runner) -> None:
    registry = SessionRegistry(settings)
    argv = ["mitmdump", "--mode", "regular"]

    state = await registry.start(executable="mitmdump", argv=argv)

    assert registry.get_runner(state.session_id).argv == argv
    await registry.shutdown_all()


async def test_start_rejects_user_confdir_override(settings, fake_runner) -> None:
    """Item F: a caller-supplied --set confdir must not shadow the isolation."""
    registry = SessionRegistry(settings)
    argv = ["mitmdump", "--set", "confdir=/etc/evil", "--mode", "regular"]

    with pytest.raises(InvalidInputError):
        await registry.start(executable="mitmdump", argv=argv, isolate_confdir=True)

    assert registry.active_count == 0
    await registry.shutdown_all()


async def test_confdir_override_rejected_even_without_isolation(settings, fake_runner) -> None:
    """The guard is unconditional — confdir is always server-controlled."""
    registry = SessionRegistry(settings)

    with pytest.raises(InvalidInputError):
        await registry.start(
            executable="mitmdump",
            argv=["mitmdump", "--set", "confdir=/tmp/x"],
        )

    await registry.shutdown_all()


@pytest.mark.parametrize(
    "argv",
    [
        ["mitmdump", "--set", "confdir=/etc/evil"],
        ["mitmdump", "--set=confdir=/etc/evil"],
    ],
)
async def test_start_rejects_both_confdir_spellings(settings, fake_runner, argv) -> None:
    """Item F: argparse accepts `--set X` and `--set=X`; both must be blocked."""
    registry = SessionRegistry(settings)

    with pytest.raises(InvalidInputError):
        await registry.start(executable="mitmdump", argv=argv, isolate_confdir=True)

    assert registry.active_count == 0
    await registry.shutdown_all()


async def test_single_token_non_reserved_option_allowed(settings, fake_runner) -> None:
    registry = SessionRegistry(settings)
    argv = ["mitmdump", "--set=termlog_verbosity=warn"]

    state = await registry.start(executable="mitmdump", argv=argv)

    assert registry.get_runner(state.session_id).argv == argv
    await registry.shutdown_all()


@pytest.mark.parametrize(
    "argv",
    [
        ["mitmdump", "--set", "scripts=/tmp/evil.py"],
        ["mitmdump", "--set=scripts=/tmp/evil.py"],
    ],
)
async def test_start_rejects_scripts_override(settings, fake_runner, argv) -> None:
    """RCE guard: --set scripts=<path> bypasses the R3 script allowlist."""
    registry = SessionRegistry(settings)

    with pytest.raises(InvalidInputError):
        await registry.start(executable="mitmdump", argv=argv)

    assert registry.active_count == 0
    await registry.shutdown_all()


async def test_non_reserved_set_options_still_allowed(settings, fake_runner) -> None:
    registry = SessionRegistry(settings)
    argv = ["mitmdump", "--set", "termlog_verbosity=warn"]

    state = await registry.start(executable="mitmdump", argv=argv)

    assert registry.get_runner(state.session_id).argv == argv
    await registry.shutdown_all()


async def test_config_options_written_0600_and_kept_off_argv(settings, fake_runner) -> None:
    registry = SessionRegistry(settings)
    secret = "s3cr3t-web-password"

    state = await registry.start(
        executable="mitmweb",
        argv=["mitmweb", "--set", "web_host=127.0.0.1"],
        isolate_confdir=True,
        config_options={"web_password": secret},
    )

    config = settings.session_root / state.session_id / "config.yaml"
    assert config.is_file()
    assert config.parent == settings.session_root / state.session_id
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert config.read_text(encoding="utf-8") == f'web_password: "{secret}"\n'
    assert all(secret not in element for element in registry.get_runner(state.session_id).argv)
    await registry.shutdown_all()


async def test_port_hosts_length_mismatch_rejected(settings, python_argv) -> None:
    registry = SessionRegistry(settings)

    with pytest.raises(InvalidInputError):
        await registry.start(
            executable="mitmdump",
            argv=python_argv(SLEEP_LONG),
            listen_ports=[allocate_ephemeral_port(), allocate_ephemeral_port()],
            port_hosts=["127.0.0.1"],
        )


async def test_port_hosts_selected_host_is_the_one_probed(settings, python_argv) -> None:
    """The probe host comes from port_hosts[i], not listen_host (SEC-4/B5)."""
    registry = SessionRegistry(settings)

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        held = sock.getsockname()[1]

        with pytest.raises(PortInUseError) as excinfo:
            await registry.start(
                executable="mitmdump",
                argv=python_argv(SLEEP_LONG),
                listen_host="0.0.0.0",
                listen_ports=[held],
                port_hosts=["localhost"],
            )

    assert excinfo.value.detail == {"host": "localhost", "port": held}


async def test_port_hosts_aligned_with_ports_is_accepted(settings, fake_runner) -> None:
    registry = SessionRegistry(settings)
    first, second = allocate_ephemeral_port(), allocate_ephemeral_port()

    state = await registry.start(
        executable="mitmweb",
        argv=["mitmweb"],
        listen_ports=[first, second],
        port_hosts=["127.0.0.1", "127.0.0.1"],
    )

    assert state.status is SessionStatus.RUNNING
    await registry.shutdown_all()

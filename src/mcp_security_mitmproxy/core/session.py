"""Session registry: UUID -> live :class:`SessionState` (Fase 2).

Responsibilities:
* Own one :class:`ProcessRunner` per session and mirror its lifecycle into a
  :class:`SessionState` pydantic model.
* Lease proxy ports so two sessions never collide, releasing them on stop.
* Give every session an isolated 0700 temp tree under ``Settings.session_root``
  holding ``dumps/``, ``ca/`` and ``logs/`` — the agent never sees CA private
  material (R2).
* Provide :meth:`SessionRegistry.shutdown_all`, the deterministic, idempotent
  teardown the FastMCP lifespan calls in ``finally`` (invariante I2, D3).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.errors import (
    InvalidInputError,
    PortInUseError,
    SessionNotFoundError,
    SessionNotRunningError,
)
from mcp_security_mitmproxy.core.modes import ensure_mode_privileges
from mcp_security_mitmproxy.core.process import ProcessExit, ProcessRunner
from mcp_security_mitmproxy.schemas.common import RESERVED_SET_OPTIONS, SessionStatus
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec, SessionState


def _check_port_free(host: str, port: int) -> bool:
    """True when ``host:port`` can be bound right now.

    A bind probe, not a connect probe: it answers "could we listen here?" even
    when nothing is listening yet.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def allocate_ephemeral_port(host: str = "127.0.0.1") -> int:
    """Reserve an OS-assigned free port and return it.

    There is an unavoidable race between releasing the socket and the child
    binding it; :meth:`SessionRegistry.start` re-validates with a bind probe and
    fails loudly with ``PORT_IN_USE`` if the lease was stolen.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


@dataclass(slots=True)
class SessionDirectory:
    """Per-session temp tree with restricted permissions."""

    root: Path
    dumps: Path
    ca: Path
    logs: Path

    @classmethod
    def create(cls, base: Path, session_id: str) -> SessionDirectory:
        root = base / session_id
        dumps = root / "dumps"
        ca = root / "ca"
        logs = root / "logs"
        for directory in (root, dumps, ca, logs):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)
        return cls(root=root, dumps=dumps, ca=ca, logs=logs)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def write_config(self, data: dict[str, str]) -> Path:
        """Write ``config.yaml`` (0600) holding secret-bearing options.

        mitmproxy applies ``--set confdir=<root>`` before loading
        ``<confdir>/config.yaml``, so options stored here are picked up without
        ever appearing on the command line (R2) — e.g. ``web_password``.
        Values are JSON-encoded, which is a valid YAML scalar, so arbitrary
        characters survive round-trip.
        """
        path = self.root / "config.yaml"
        text = "".join(f"{key}: {json.dumps(value)}\n" for key, value in data.items())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
        finally:
            os.chmod(path, 0o600)
        return path


@dataclass(slots=True)
class _Entry:
    state: SessionState
    runner: ProcessRunner
    directory: SessionDirectory
    leased_ports: list[int] = field(default_factory=list)
    web_token: str | None = None


_PORT_HOST_ERROR = "listen_ports and port_hosts must have equal length when both are provided"


def _reserved_option_in(token: str) -> str | None:
    """Return the reserved option key carried by a value, if any.

    ``token`` is the RHS of ``--set`` (either the token following ``--set`` or
    the text after ``--set=``). Only the leading ``key=`` is inspected; bare
    keys (no ``=``) are ignored because mitmproxy would fail to parse them.
    """
    key = token.split("=", 1)[0].strip()
    return key if key in RESERVED_SET_OPTIONS else None


def _assert_no_reserved_options(argv: list[str]) -> None:
    """Reject argv that carries a reserved ``--set`` override.

    Defense in depth: even if a caller bypasses the schema guard, the registry
    refuses to spawn a process whose own isolation flags can be shadowed. Both
    argparse spellings are covered — the two-token form ``--set confdir=...``
    and the single-token form ``--set=confdir=...``.
    """
    for index, token in enumerate(argv):
        candidate: str | None = None
        if token == "--set":
            if index + 1 < len(argv):
                candidate = argv[index + 1]
        elif token.startswith("--set="):
            candidate = token[len("--set=") :]
        if candidate is None:
            continue
        key = _reserved_option_in(candidate)
        if key is not None:
            raise InvalidInputError(
                f"--set {key} is reserved and cannot be overridden by the caller",
                detail={"option": key, "reserved": sorted(RESERVED_SET_OPTIONS)},
            )


def _resolve_port_host(
    index: int,
    listen_host: str,
    port_hosts: list[str] | None,
) -> str:
    """Pick the bind host a given leased port must be probed against.

    When ``port_hosts`` is supplied it must align 1:1 with ``listen_ports`` and
    is used verbatim, so the web port is checked against ``web_host`` rather
    than ``listen_host`` (SEC-4/B5). Otherwise every port uses ``listen_host``.
    """
    if not port_hosts:
        return listen_host
    return port_hosts[index]


class SessionRegistry:
    """In-memory, asyncio-safe registry of managed mitmproxy sessions."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()
        self._entries: dict[str, _Entry] = {}
        self._shutdown = False

    @property
    def settings(self) -> Settings:
        return self._settings

    def _require_entry(self, session_id: str) -> _Entry:
        entry = self._entries.get(session_id)
        if entry is None:
            raise SessionNotFoundError(f"session {session_id!r} not found")
        return entry

    def get(self, session_id: str) -> SessionState:
        return self._require_entry(session_id).state

    def list(self) -> list[SessionState]:
        return [entry.state for entry in self._entries.values()]

    def get_runner(self, session_id: str) -> ProcessRunner:
        return self._require_entry(session_id).runner

    def get_directory(self, session_id: str) -> SessionDirectory:
        return self._require_entry(session_id).directory

    def get_web_token(self, session_id: str) -> str | None:
        return self._require_entry(session_id).web_token

    def port_in_use(self, port: int) -> bool:
        return any(port in entry.leased_ports for entry in self._entries.values())

    async def start(
        self,
        *,
        executable: str,
        argv: list[str],
        modes: list[ProxyModeSpec] | None = None,
        listen_host: str = "127.0.0.1",
        listen_ports: list[int] | None = None,
        port_hosts: list[str] | None = None,
        web_host: str | None = None,
        web_port: int | None = None,
        web_token: str | None = None,
        isolate_confdir: bool = False,
        config_options: dict[str, str] | None = None,
        save_path: str | None = None,
        cwd: str | os.PathLike[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> SessionState:
        """Spawn a managed session and register it.

        ``argv`` is already validated and fully assembled by the caller (the
        tool adapter), keeping this layer ignorant of executable-specific flags.

        ``isolate_confdir`` places ``--set confdir=<session>`` right after the
        executable so all CA and config material stays inside the 0700 session
        tree (SEC-5). Optional ``config_options`` are written to
        ``<session>/config.yaml`` (0600) and picked up by mitmproxy after
        ``confdir`` is applied — the channel that keeps ``web_password`` off the
        command line (SEC-3).

        A caller-supplied ``--set confdir=...`` is rejected (Item F): options
        are applied last-wins, so it would shadow our isolation.
        """
        if self._shutdown:
            raise InvalidInputError("registry is shut down")

        _assert_no_reserved_options(argv)

        # R5 (defense in depth): privileged modes are refused at the tool
        # boundary; the registry repeats the check so every caller — present
        # or future — is covered by the same choke point, pre-spawn.
        if modes:
            ensure_mode_privileges(modes)

        requested_ports = list(listen_ports or [])
        if port_hosts and len(port_hosts) != len(requested_ports):
            raise InvalidInputError(_PORT_HOST_ERROR)
        for index, port in enumerate(requested_ports):
            host = _resolve_port_host(index, listen_host, port_hosts)
            if self.port_in_use(port) or not _check_port_free(host, port):
                raise PortInUseError(
                    f"port {port} is already in use",
                    detail={"host": host, "port": port},
                )

        session_id = str(uuid.uuid4())
        directory = SessionDirectory.create(self._settings.session_root, session_id)
        if config_options:
            directory.write_config(config_options)

        final_argv = list(argv)
        if isolate_confdir:
            # Options must follow the executable (argv[0]); putting --set first
            # makes the OS try to exec "--set".
            final_argv = [argv[0], "--set", f"confdir={directory.root}", *argv[1:]]

        state = SessionState(
            session_id=session_id,
            executable=executable,
            status=SessionStatus.STARTING,
            modes=list(modes or []),
            listen_host=listen_host,
            listen_ports=requested_ports,
            web_host=web_host,
            web_port=web_port,
            save_path=save_path,
        )

        runner = ProcessRunner(
            final_argv,
            settings=self._settings,
            cwd=cwd if cwd is not None else directory.root,
            env=env,
            on_exit=lambda outcome: self._on_exit(session_id, outcome),
        )
        entry = _Entry(
            state=state,
            runner=runner,
            directory=directory,
            leased_ports=requested_ports,
            web_token=web_token,
        )
        self._entries[session_id] = entry

        try:
            state.pid = await runner.start()
        except BaseException:
            self._entries.pop(session_id, None)
            directory.cleanup()
            raise
        state.status = SessionStatus.RUNNING
        return state

    def _on_exit(self, session_id: str, outcome: ProcessExit) -> None:
        entry = self._entries.get(session_id)
        if entry is None:
            return
        entry.state.exit_code = outcome.returncode
        if entry.state.status in (SessionStatus.STOPPING, SessionStatus.STOPPED):
            return
        entry.state.status = (
            SessionStatus.STOPPED if outcome.returncode == 0 else SessionStatus.FAILED
        )

    async def stop(
        self, session_id: str, *, timeout: float | None = None, force: bool = False
    ) -> SessionState:
        entry = self._require_entry(session_id)
        if entry.state.status in (SessionStatus.STOPPED, SessionStatus.FAILED):
            return entry.state
        entry.state.status = SessionStatus.STOPPING
        outcome = await entry.runner.stop(timeout=timeout, force=force)
        entry.state.exit_code = outcome.returncode
        entry.state.status = SessionStatus.STOPPED
        entry.leased_ports.clear()
        return entry.state

    async def remove(self, session_id: str) -> None:
        """Stop (if needed), clean the temp tree and drop the session."""
        entry = self._entries.get(session_id)
        if entry is None:
            raise SessionNotFoundError(f"session {session_id!r} not found")
        if entry.state.status not in (SessionStatus.STOPPED, SessionStatus.FAILED):
            await self.stop(session_id, force=True)
        entry.directory.cleanup()
        self._entries.pop(session_id, None)

    async def logs(
        self, session_id: str, *, stream: str | None = None, limit: int | None = None
    ) -> list[Any]:
        entry = self._require_entry(session_id)
        if not entry.runner.running and entry.state.status is SessionStatus.FAILED:
            raise SessionNotRunningError(f"session {session_id!r} failed")
        return entry.runner.logs.snapshot(stream=stream, limit=limit)  # type: ignore[arg-type]

    async def shutdown_all(self, *, timeout: float | None = None) -> list[SessionState]:
        """Deterministically stop every session. Idempotent (invariante I2)."""
        self._shutdown = True
        results: list[SessionState] = []
        for session_id in list(self._entries):
            entry = self._entries.get(session_id)
            if entry is None:
                continue
            try:
                if entry.state.status not in (SessionStatus.STOPPED, SessionStatus.FAILED):
                    entry.state.status = SessionStatus.STOPPING
                    outcome = await entry.runner.stop(timeout=timeout, force=True)
                    entry.state.exit_code = outcome.returncode
                    entry.state.status = SessionStatus.STOPPED
                entry.leased_ports.clear()
                results.append(entry.state)
            except Exception:  # noqa: BLE001 - teardown must not abort the sweep
                entry.state.status = SessionStatus.FAILED
                results.append(entry.state)
            finally:
                entry.directory.cleanup()
                self._entries.pop(session_id, None)
        for entry in self._entries.values():  # pragma: no cover - defensive
            entry.directory.cleanup()
        self._entries.clear()
        return results

    @property
    def active_count(self) -> int:
        return len(self._entries)


__all__ = ["SessionDirectory", "SessionRegistry", "allocate_ephemeral_port"]

"""Asynchronous subprocess runner with ring-buffer log capture (Fase 2).

:class:`ProcessRunner` owns exactly one child process. It spawns the process
with :func:`asyncio.create_subprocess_exec` (never a shell), drains stdout and
stderr concurrently into bounded ring buffers, and drives shutdown through
escalating signals: ``SIGINT`` -> ``SIGTERM`` -> ``SIGKILL``.

The runner is transport-only: it knows how to start, observe and stop a program.
Session bookkeeping lives in :mod:`mcp_security_mitmproxy.core.session`.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import os
import signal
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.errors import ProcessSpawnFailedError, TimeoutError_

StreamName = Literal["stdout", "stderr"]


@dataclass(slots=True)
class LogRecord:
    """One captured output line, timestamped at read time."""

    stream: StreamName
    line: str
    timestamp: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.UTC))


class RingBuffer:
    """Bounded FIFO of log records; the oldest line is evicted past capacity."""

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self._records: deque[LogRecord] = deque(maxlen=capacity)

    @property
    def capacity(self) -> int:
        return self._records.maxlen or 0

    def append(self, record: LogRecord) -> None:
        self._records.append(record)

    def extend(self, records: Iterable[LogRecord]) -> None:
        self._records.extend(records)

    def snapshot(
        self, stream: StreamName | None = None, limit: int | None = None
    ) -> list[LogRecord]:
        """Return records, newest last, optionally filtered/paged.

        ``limit`` keeps the ``limit`` most recent records — the useful window
        when an agent is diagnosing a failure.
        """
        items = [r for r in self._records if stream is None or r.stream == stream]
        if limit is not None:
            items = items[-limit:]
        return items

    def text(self, stream: StreamName | None = None, limit: int | None = None) -> str:
        return "\n".join(r.line for r in self.snapshot(stream=stream, limit=limit))

    def clear(self) -> None:
        self._records.clear()

    def __len__(self) -> int:
        return len(self._records)


@dataclass(slots=True)
class ProcessExit:
    """Outcome of a terminated child process."""

    returncode: int
    forced_kill: bool


class ProcessRunner:
    """Owns one mitmproxy subprocess and its lifecycle."""

    def __init__(
        self,
        argv: Sequence[str],
        *,
        settings: Settings,
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
        on_exit: Callable[[ProcessExit], None] | None = None,
    ) -> None:
        if not argv:
            raise ValueError("argv must not be empty")
        self._argv = list(argv)
        self._settings = settings
        self._cwd = os.fspath(cwd) if cwd is not None else None
        self._env = dict(env) if env is not None else None
        self._logs = RingBuffer(settings.log_capacity)
        self._proc: asyncio.subprocess.Process | None = None
        self._readers: list[asyncio.Task[None]] = []
        self._on_exit = on_exit
        self._exit_notified = False
        self._stopping = False

    @property
    def argv(self) -> list[str]:
        return list(self._argv)

    @property
    def pid(self) -> int | None:
        return None if self._proc is None else self._proc.pid

    @property
    def logs(self) -> RingBuffer:
        return self._logs

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    @property
    def returncode(self) -> int | None:
        return None if self._proc is None else self._proc.returncode

    async def start(self) -> int:
        """Spawn the child and begin draining output. Returns its PID."""
        if self._proc is not None:
            raise ProcessSpawnFailedError("process already started")
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *self._argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self._cwd,
                env=self._env,
            )
        except (OSError, ValueError) as exc:
            raise ProcessSpawnFailedError(
                f"failed to spawn {self._argv[0]!r}: {exc}",
                detail={"argv": self._argv},
            ) from exc

        assert self._proc.stdout is not None
        assert self._proc.stderr is not None
        self._readers = [
            asyncio.create_task(self._drain(self._proc.stdout, "stdout")),
            asyncio.create_task(self._drain(self._proc.stderr, "stderr")),
            asyncio.create_task(self._watch()),
        ]
        return self._proc.pid

    async def _drain(self, reader: asyncio.StreamReader, stream: StreamName) -> None:
        while True:
            raw = await reader.readline()
            if not raw:
                return
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            self._logs.append(LogRecord(stream=stream, line=line))

    async def _watch(self) -> None:
        """Await process end, then flush the tail of its output."""
        proc = self._proc
        assert proc is not None
        await proc.wait()
        await self._drain_tail()
        if not self._exit_notified:
            self._exit_notified = True
            if self._on_exit is not None:
                self._on_exit(ProcessExit(returncode=proc.returncode or 0, forced_kill=False))

    async def _drain_tail(self) -> None:
        for task in self._readers:
            if task is asyncio.current_task():
                continue
            if not task.done():
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    async def wait(self) -> int:
        """Wait for natural termination, drain remaining output and return exit code."""
        if self._proc is None:
            raise ProcessSpawnFailedError("process not started")
        code = await self._proc.wait()
        for task in self._readers:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        return code

    async def stop(
        self,
        *,
        timeout: float | None = None,
        force: bool = False,
        sig: signal.Signals | None = None,
    ) -> ProcessExit:
        """Terminate the child deterministically.

        Sequence: send ``sig`` (default ``SIGINT``), wait up to ``timeout``; if
        still alive send ``SIGTERM``; if still alive and ``force`` is set send
        ``SIGKILL``. Raises :class:`TimeoutError_` when the process survives and
        ``force`` is false — the caller must never leave an orphan.
        """
        if self._proc is None:
            raise ProcessSpawnFailedError("process not started")
        timeout = self._settings.shutdown_timeout_seconds if timeout is None else timeout
        self._stopping = True

        if self._proc.returncode is not None:
            return self._finish(returncode=self._proc.returncode, forced_kill=False)

        self._signal(sig or signal.SIGINT)
        if await self._wait_within(timeout):
            return self._finish(returncode=self._proc.returncode or 0, forced_kill=False)

        self._signal(signal.SIGTERM)
        if await self._wait_within(timeout):
            return self._finish(returncode=self._proc.returncode or 0, forced_kill=False)

        if not force:
            raise TimeoutError_(
                "process did not exit after SIGINT/SIGTERM; pass force=True to SIGKILL",
                detail={"pid": self.pid, "argv": self._argv},
            )

        self._signal(signal.SIGKILL)
        await self._proc.wait()
        return self._finish(returncode=self._proc.returncode or 0, forced_kill=True)

    def _finish(self, *, returncode: int, forced_kill: bool) -> ProcessExit:
        self._cancel_readers()
        return ProcessExit(returncode=returncode, forced_kill=forced_kill)

    async def _wait_within(self, timeout: float) -> bool:
        assert self._proc is not None
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=timeout)
        except TimeoutError:
            return False
        return True

    def _signal(self, sig: signal.Signals) -> None:
        if self._proc is None or self._proc.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            self._proc.send_signal(sig)

    def _cancel_readers(self) -> None:
        for task in self._readers:
            if not task.done():
                task.cancel()

    async def aclose(self) -> None:
        """Best-effort teardown: cancel readers, reap if still alive."""
        if self._proc is not None and self._proc.returncode is None:
            with contextlib.suppress(TimeoutError_, ProcessLookupError):
                await self.stop(force=True)
        for task in self._readers:
            if not task.done():
                task.cancel()
        for task in self._readers:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


__all__ = ["LogRecord", "ProcessExit", "ProcessRunner", "RingBuffer", "StreamName"]

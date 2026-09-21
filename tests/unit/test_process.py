"""Unit tests for the async subprocess runner and its ring buffer."""

from __future__ import annotations

import asyncio
import signal

import pytest

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.errors import ProcessSpawnFailedError, TimeoutError_
from mcp_security_mitmproxy.core.process import ProcessRunner, RingBuffer
from tests.conftest import EXIT_NONZERO, EXIT_ZERO, IGNORE_SIGNALS, SLEEP_LONG


def _settings(**overrides: object) -> Settings:
    return Settings(**overrides)


def test_ring_buffer_evicts_oldest() -> None:
    buffer = RingBuffer(2)
    for i in range(3):
        buffer.append(_record(f"line-{i}"))
    lines = [r.line for r in buffer.snapshot()]
    assert lines == ["line-1", "line-2"]


def test_ring_buffer_limit_keeps_most_recent() -> None:
    buffer = RingBuffer(10)
    for i in range(5):
        buffer.append(_record(f"line-{i}"))
    assert [r.line for r in buffer.snapshot(limit=2)] == ["line-3", "line-4"]


def test_ring_buffer_filter_by_stream() -> None:
    buffer = RingBuffer(10)
    buffer.append(_record("a", stream="stdout"))
    buffer.append(_record("b", stream="stderr"))
    assert [r.line for r in buffer.snapshot(stream="stderr")] == ["b"]


def test_ring_buffer_rejects_zero_capacity() -> None:
    with pytest.raises(ValueError, match="capacity"):
        RingBuffer(0)


def _record(line: str, stream: str = "stdout"):
    from mcp_security_mitmproxy.core.process import LogRecord

    return LogRecord(stream=stream, line=line)  # type: ignore[arg-type]


async def test_runner_captures_both_streams(python_argv) -> None:
    runner = ProcessRunner(python_argv(EXIT_ZERO), settings=_settings())
    await runner.start()
    code = await runner.wait()
    assert code == 0
    stdout = runner.logs.text(stream="stdout")
    stderr = runner.logs.text(stream="stderr")
    assert "out-line" in stdout
    assert "err-line" in stderr


async def test_runner_reports_pid_and_running(python_argv) -> None:
    runner = ProcessRunner(python_argv(SLEEP_LONG), settings=_settings())
    assert runner.running is False
    pid = await runner.start()
    assert pid == runner.pid
    assert runner.running is True
    await runner.stop(force=True)


async def test_runner_stop_graceful_exit(python_argv) -> None:
    runner = ProcessRunner(python_argv(SLEEP_LONG), settings=_settings())
    await runner.start()
    outcome = await runner.stop(timeout=5.0)
    assert outcome.forced_kill is False
    assert runner.running is False


async def test_runner_stop_escalates_to_sigkill(python_argv) -> None:
    runner = ProcessRunner(python_argv(IGNORE_SIGNALS), settings=_settings())
    await runner.start()
    await _wait_for_log(runner, "ready")
    outcome = await runner.stop(timeout=0.3, force=True)
    assert outcome.forced_kill is True
    assert runner.running is False


async def test_runner_stop_without_force_raises_timeout(python_argv) -> None:
    runner = ProcessRunner(python_argv(IGNORE_SIGNALS), settings=_settings())
    await runner.start()
    await _wait_for_log(runner, "ready")
    with pytest.raises(TimeoutError_):
        await runner.stop(timeout=0.2, force=False)
    await runner.stop(force=True)


async def test_runner_on_exit_callback_receives_code(python_argv) -> None:
    seen: list[int] = []
    runner = ProcessRunner(
        python_argv(EXIT_NONZERO),
        settings=_settings(),
        on_exit=lambda outcome: seen.append(outcome.returncode),
    )
    await runner.start()
    await runner.wait()
    await asyncio.sleep(0)
    assert seen == [3]


async def test_runner_spawn_failure_raises_domain_error() -> None:
    runner = ProcessRunner(["/nonexistent/binary-xyz"], settings=_settings())
    with pytest.raises(ProcessSpawnFailedError) as excinfo:
        await runner.start()
    assert excinfo.value.code.value == "PROCESS_SPAWN_FAILED"


async def test_runner_rejects_double_start(python_argv) -> None:
    runner = ProcessRunner(python_argv(SLEEP_LONG), settings=_settings())
    await runner.start()
    with pytest.raises(ProcessSpawnFailedError):
        await runner.start()
    await runner.stop(force=True)


async def test_runner_stop_before_start_raises() -> None:
    runner = ProcessRunner(["echo"], settings=_settings())
    with pytest.raises(ProcessSpawnFailedError):
        await runner.stop()


async def test_runner_acclose_reaps_live_process(python_argv) -> None:
    runner = ProcessRunner(python_argv(SLEEP_LONG), settings=_settings())
    await runner.start()
    await runner.aclose()
    assert runner.running is False


async def test_runner_ring_buffer_caps_logs(python_argv) -> None:
    code = "print('\\n'.join(str(i) for i in range(50)), flush=True)"
    runner = ProcessRunner(python_argv(code), settings=_settings(log_capacity=10))
    await runner.start()
    await runner.wait()
    await asyncio.sleep(0)
    assert len(runner.logs) <= 10


async def test_runner_sends_configured_signal(python_argv) -> None:
    runner = ProcessRunner(python_argv(SLEEP_LONG), settings=_settings())
    await runner.start()
    await _wait_for_log(runner, "ready")
    outcome = await runner.stop(timeout=5.0, sig=signal.SIGTERM)
    assert outcome.returncode is not None


async def _wait_for_log(runner: ProcessRunner, needle: str, timeout: float = 5.0) -> None:
    """Block until ``needle`` appears in stdout, so the child has started."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if any(needle in record.line for record in runner.logs.snapshot()):
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"log line {needle!r} never appeared")

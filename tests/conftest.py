"""Shared fixtures. Kept dependency-free so schema tests never touch the proxy."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def allow_root(tmp_path: Path) -> Path:
    root = tmp_path / "allow"
    root.mkdir()
    return root


@pytest.fixture
def python_argv() -> callable:
    """Build an argv that runs a snippet under the current interpreter."""

    def _build(code: str) -> list[str]:
        return [sys.executable, "-c", code]

    return _build


# Snippet: print one line to each stream, then exit 0.
EXIT_ZERO = (
    "import sys; print('out-line', flush=True); print('err-line', file=sys.stderr, flush=True)"
)
# Snippet: sleep long enough for a test to stop it.
SLEEP_LONG = "import time; print('ready', flush=True); time.sleep(60)"
# Snippet: ignore graceful signals so escalation to SIGKILL is required.
IGNORE_SIGNALS = (
    "import signal, time; "
    "signal.signal(signal.SIGINT, signal.SIG_IGN); "
    "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
    "print('ready', flush=True); time.sleep(60)"
)
# Snippet: exit non-zero to exercise failure mapping.
EXIT_NONZERO = "import sys; sys.exit(3)"
# Snippet: bind an ephemeral port, announce it, then hold it open.
LISTEN_AND_HOLD = (
    "import socket, time; "
    "s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
    "s.bind(('127.0.0.1', 0)); s.listen(1); "
    "print('PORT=%d' % s.getsockname()[1], flush=True); time.sleep(60)"
)

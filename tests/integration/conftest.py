"""Shared fixtures for real-network E2E integration tests.

These tests spawn actual ``mitmweb``/``mitmdump`` subprocesses and drive traffic
through them to a real HTTP upstream bound to a loopback port. Nothing is
mocked: the assertions read bytes that crossed the proxy.

Plain HTTP is used deliberately — no CA trust is required, so the suite runs
anywhere without installing a certificate. TLS interception is covered by the
unit-level mode/argv tests, not here.

Every test skips cleanly when the mitmproxy executables are unavailable.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastmcp import Context

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.core.session import SessionRegistry
from mcp_security_mitmproxy.server import create_server

_BIN = Path(sys.executable).parent
MITMWEB = shutil.which("mitmweb") or str(_BIN / "mitmweb")
MITMDUMP = shutil.which("mitmdump") or str(_BIN / "mitmdump")

mitmproxy_available = pytest.mark.skipif(
    not (Path(MITMWEB).exists() and Path(MITMDUMP).exists()),
    reason="mitmweb/mitmdump executables not available",
)


def free_port() -> int:
    """Return an OS-assigned free TCP port on loopback."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(
    host: str, port: int, *, proc: subprocess.Popen | None = None, timeout: float = 20.0
) -> bool:
    """Poll until ``host:port`` accepts a connection (or the process dies)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


# --------------------------------------------------------------------------- #
# Real upstream HTTP server
# --------------------------------------------------------------------------- #


class _UpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Echo server: ``/echo`` returns JSON of method/path/headers; ``/hello`` a body."""

    def log_message(self, *_args: object) -> None:  # silence stderr
        return

    def _respond(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.startswith("/api/v1/user"):
            payload = b'{"id": 1, "name": "alice"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.startswith("/login"):
            payload = b'{"token": "session-issued"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.startswith("/hello"):
            payload = b"UPSTREAM-HELLO"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Upstream", "mitm-e2e")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.startswith("/secret"):
            payload = b'{"access_token": "upstream-secret-token"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "session=upstream-cookie")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        # default: reflect request
        payload = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": {k: v for k, v in self.headers.items()},
                "body": body.decode("utf-8", errors="replace"),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond


@pytest.fixture
def upstream_server() -> Iterator[dict[str, object]]:
    """A real HTTP server on loopback; yields its host/port and origin URL.

    The ``stop`` callable shuts the server down early — used by the replay
    scenario to prove a replayed response does not touch the network.
    """
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stopped = False

    def stop() -> None:
        nonlocal stopped
        if not stopped:
            stopped = True
            server.shutdown()
            server.server_close()

    try:
        yield {"host": host, "port": port, "origin": f"http://{host}:{port}", "stop": stop}
    finally:
        stop()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# Raw mitmweb subprocess (for direct REST-level integration)
# --------------------------------------------------------------------------- #


@pytest.fixture
def mitmweb_instance(tmp_path: Path) -> Iterator[dict[str, object]]:
    """A real mitmweb process with a known web token; torn down afterward."""
    proxy_port = free_port()
    web_port = free_port()
    token = "e2e-token"
    proc = subprocess.Popen(
        [
            MITMWEB,
            "--no-web-open-browser",
            "--web-host",
            "127.0.0.1",
            "--web-port",
            str(web_port),
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(proxy_port),
            "--set",
            f"web_password={token}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_for_port("127.0.0.1", web_port, proc=proc):
            pytest.skip("mitmweb did not become ready")
        yield {
            "host": "127.0.0.1",
            "web_port": web_port,
            "proxy_port": proxy_port,
            "token": token,
            "proxy_url": f"http://127.0.0.1:{proxy_port}",
            "web_url": f"http://127.0.0.1:{web_port}",
        }
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()
            proc.wait(timeout=10)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


@pytest.fixture
def mitmdump_process(tmp_path: Path) -> Iterator[dict[str, object]]:
    """A real headless mitmdump process; yields its proxy URL and a dump path."""
    proxy_port = free_port()
    dump_path = tmp_path / "capture.mitm"
    proc = subprocess.Popen(
        [
            MITMDUMP,
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(proxy_port),
            "-w",
            str(dump_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_for_port("127.0.0.1", proxy_port, proc=proc):
            pytest.skip("mitmdump did not become ready")
        yield {
            "proxy_port": proxy_port,
            "proxy_url": f"http://127.0.0.1:{proxy_port}",
            "dump_path": dump_path,
        }
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()
            proc.wait(timeout=10)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


# --------------------------------------------------------------------------- #
# Full MCP tool surface wired to a real registry
# --------------------------------------------------------------------------- #


@pytest.fixture
async def tools_env(tmp_path: Path) -> AsyncIterator[dict[str, object]]:
    """Real LifespanContext + Settings + Context for driving the MCP tools.

    ``registry.start`` spawns genuine mitmweb/mitmdump processes, so the tools
    under test exercise the full stack: contract -> registry -> subprocess ->
    REST bridge.
    """
    mock_root = tmp_path / "mocks"
    mock_root.mkdir()
    dump_root = tmp_path / "dumps"
    dump_root.mkdir()
    settings = Settings(
        allowed_mock_roots=[mock_root],
        allowed_dump_roots=[dump_root],
        allowed_ca_roots=[tmp_path / "ca"],
        session_root=tmp_path / "sessions",
    )
    registry = SessionRegistry(settings)
    server = create_server()
    lifespan = LifespanContext(settings=settings, registry=registry)
    ctx = MagicMock(spec=Context)
    ctx.lifespan_context = lifespan

    try:
        yield {
            "server": server,
            "lifespan": lifespan,
            "registry": registry,
            "settings": settings,
            "ctx": ctx,
            "mock_root": mock_root,
            "dump_root": dump_root,
        }
    finally:
        with contextlib.suppress(Exception):
            await registry.shutdown_all(timeout=5.0)

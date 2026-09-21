"""Integration test: Fase 4 rules against a real mitmweb instance.

Spawns ``mitmweb`` as a subprocess, registers a ``map_local`` rule through the
real ``PUT /options`` (including the CSRF bootstrap), then drives a request
through the proxy and asserts the mocked body is served.

Skipped automatically when the ``mitmweb`` executable is unavailable.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from mcp_security_mitmproxy.core.redact import REDACTED  # noqa: F401  (keep imports honest)
from mcp_security_mitmproxy.web_client.client import MitmwebClient

MITMWEB = shutil.which("mitmweb") or str(Path(sys.executable).parent / "mitmweb")
pytestmark = pytest.mark.skipif(
    not Path(MITMWEB).exists(), reason="mitmweb executable not available"
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def mitmweb_instance(tmp_path: Path):
    """Start a real mitmweb, yield its host/port/web_port, then tear it down."""
    proxy_port = _free_port()
    web_port = _free_port()
    token = "integration-token"
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
        deadline = time.time() + 20
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.skip("mitmweb exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", web_port), timeout=0.5):
                    ready = True
                    break
            except OSError:
                time.sleep(0.2)
        if not ready:
            pytest.skip("mitmweb did not become ready")
        yield {"host": "127.0.0.1", "web_port": web_port, "proxy_port": proxy_port, "token": token}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


async def _put_map_local(instance: dict, spec: str) -> None:
    base_url = f"http://{instance['host']}:{instance['web_port']}"
    async with MitmwebClient(base_url, token=instance["token"]) as client:
        options = await client.get_options()
        current = options["map_local"]["value"]
        await client.put_options(map_local=[*current, spec])


async def test_map_local_rule_is_applied_end_to_end(mitmweb_instance, tmp_path: Path) -> None:
    mock = tmp_path / "mock.txt"
    mock.write_text("MOCKED-BODY", encoding="utf-8")

    spec = f"|^http://example.com/mock$|{mock}"
    await _put_map_local(mitmweb_instance, spec)

    # Verify the option landed.
    base_url = f"http://{mitmweb_instance['host']}:{mitmweb_instance['web_port']}"
    async with MitmwebClient(base_url, token=mitmweb_instance["token"]) as client:
        options = await client.get_options()
    assert spec in options["map_local"]["value"]

    # Drive a request through the proxy.
    proxy = f"http://{mitmweb_instance['host']}:{mitmweb_instance['proxy_port']}"
    async with httpx.AsyncClient(proxy=proxy, timeout=15) as proxied:
        response = await proxied.get("http://example.com/mock")
    assert response.status_code == 200
    assert "MOCKED-BODY" in response.text


async def test_put_options_requires_csrf_but_client_solves_it(mitmweb_instance) -> None:
    """A bare PUT without X-XSRFToken is 403; the client's bootstrap fixes it."""
    base_url = f"http://{mitmweb_instance['host']}:{mitmweb_instance['web_port']}"
    token = mitmweb_instance["token"]

    async with httpx.AsyncClient(base_url=base_url) as raw:
        unauthenticated = await raw.put(
            "/options", json={"map_local": []}, headers={"Authorization": f"Bearer {token}"}
        )
    assert unauthenticated.status_code == 403

    async with MitmwebClient(base_url, token=token) as client:
        await client.put_options(map_local=[])  # must succeed via XSRF bootstrap

    async with MitmwebClient(base_url, token=token) as client:
        options = await client.get_options()
    assert options["map_local"]["value"] == []


async def test_get_options_round_trip(mitmweb_instance) -> None:
    base_url = f"http://{mitmweb_instance['host']}:{mitmweb_instance['web_port']}"
    async with MitmwebClient(base_url, token=mitmweb_instance["token"]) as client:
        options = await client.get_options()
    for family in ("map_remote", "map_local", "modify_headers", "modify_body"):
        assert family in options
        assert "value" in options[family]

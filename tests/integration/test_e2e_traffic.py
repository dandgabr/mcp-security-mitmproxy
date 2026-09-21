"""Fase 5 E2E traffic scenarios (architecture 0004 §2, E2E-A..E).

Every scenario drives real bytes through a real mitmweb subprocess to a real
loopback upstream, invoking the MCP tools through ``tool.fn(...)`` exactly as an
MCP client would. Nothing is mocked at the network layer.

The fixture ``mitmweb_instance`` is reused from ``test_rules_integration.py``
(imported from the sibling module so there is a single definition).

Skipped automatically when the mitmproxy executables are unavailable.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import threading

import httpx
import pytest

from mcp_security_mitmproxy.core.redact import REDACTED
from mcp_security_mitmproxy.schemas.common import ExportFormat, ProxyMode
from mcp_security_mitmproxy.schemas.core_commands import (
    MitmExportFlowInput,
    MitmFilterFlowsInput,
)
from mcp_security_mitmproxy.schemas.mitmdump import (
    MitmdumpReplayInput,
    MitmdumpStartInput,
)
from mcp_security_mitmproxy.schemas.mitmweb import (
    MitmwebGetFlowDetailInput,
    MitmwebGetFlowsInput,
    MitmwebStartInput,
)
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec, SessionState, StopInput
from mcp_security_mitmproxy.schemas.rules import (
    MapLocalRuleSpec,
    MapRemoteRuleSpec,
    MitmClearRulesInput,
    MitmListRulesInput,
    MitmModifyHeadersInput,
    MitmSetMapLocalInput,
    MitmSetMapRemoteInput,
    ModifyHeaderRuleSpec,
)

from .conftest import _UpstreamHandler, free_port, mitmproxy_available, wait_for_port
from .test_rules_integration import mitmweb_instance  # noqa: F401  (pytest fixture reuse)

pytestmark = [mitmproxy_available, pytest.mark.integration]


async def _call(server, name: str, params, ctx):
    tool = await server.get_tool(name)
    return await tool.fn(params, ctx)


async def _start_proxy_session(tools_env, *, tool_name: str, dump_root, dump_name: str):
    """Start a headless mitmdump session and block until its proxy port listens.

    ``free_port`` closes the socket before returning, so another process can
    steal the port under load; the child then exits without ever binding. This
    helper retries a bounded number of times on that genuine race and, if the
    port still never opens, fails with the child's own logs instead of leaking a
    ``ConnectError`` from the first request.
    """
    server = tools_env["server"]
    ctx = tools_env["ctx"]
    dump_path = dump_root / dump_name
    last_error = "unknown"

    for _attempt in range(3):
        proxy_port = free_port()
        result = await _call(
            server,
            tool_name,
            MitmdumpStartInput(
                mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=proxy_port)],
                save_path=str(dump_path),
            ),
            ctx,
        )
        assert result.ok is True, result.error
        session = result.session
        runner = tools_env["registry"].get_runner(session.session_id)

        for _ in range(150):
            if wait_for_port("127.0.0.1", proxy_port, timeout=0.2):
                return session, proxy_port, dump_path
            if not runner.running:
                last_error = f"child exited rc={runner.returncode}: {runner.logs.text()[-300:]}"
                break
            await asyncio.sleep(0.1)
        # Tear the failed attempt down before retrying so no port stays leased.
        await _call(server, "mitmdump_stop", StopInput(session_id=session.session_id), ctx)

    pytest.fail(f"mitmdump proxy port never listened after 3 attempts: {last_error}")


async def _start_web_session(tools_env) -> SessionState:
    """Start a real mitmweb through the MCP tool and wait until both ports bind."""
    server = tools_env["server"]
    ctx = tools_env["ctx"]
    proxy_port = free_port()
    result = await _call(
        server,
        "mitmweb_start",
        MitmwebStartInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=proxy_port)],
            web_port=free_port(),
        ),
        ctx,
    )
    assert result.ok is True, result.error
    session = result.session
    assert session is not None
    for _ in range(200):
        web_ok = wait_for_port(session.web_host, session.web_port, timeout=0.2)
        proxy_ok = wait_for_port(session.listen_host, proxy_port, timeout=0.2)
        if web_ok and proxy_ok:
            return session
        await asyncio.sleep(0.1)
    pytest.fail("mitmweb session did not become ready")


async def _proxied(proxy_url: str, method: str, url: str, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(proxy=proxy_url, timeout=20) as client:
        return await client.request(method, url, **kwargs)


async def _wait_flows(server, ctx, session_id: str, *, predicate, tries: int = 100):
    """Poll ``mitmweb_get_flows`` until ``predicate(result)`` holds."""
    last = None
    for _ in range(tries):
        last = await _call(
            server, "mitmweb_get_flows", MitmwebGetFlowsInput(session_id=session_id), ctx
        )
        if last.ok and predicate(last):
            return last
        await asyncio.sleep(0.1)
    pytest.fail(f"flows predicate never satisfied; last={last}")


# --------------------------------------------------------------------------- #
# E2E-A — capture + get_flows + get_flow_detail with redaction
# --------------------------------------------------------------------------- #


async def test_e2e_a_capture_read_and_redact(tools_env, upstream_server, tmp_path) -> None:
    server = tools_env["server"]
    ctx = tools_env["ctx"]
    registry = tools_env["registry"]
    session = await _start_web_session(tools_env)
    proxy_url = f"http://127.0.0.1:{session.listen_ports[0]}"
    origin = upstream_server["origin"]

    try:
        get_resp = await _proxied(proxy_url, "GET", f"{origin}/api/v1/user")
        post_resp = await _proxied(
            proxy_url,
            "POST",
            f"{origin}/login",
            json={"user": "alice"},
            headers={"Authorization": "Bearer super-secret-token"},
        )
        assert get_resp.status_code == 200
        assert post_resp.status_code == 200

        flows = await _wait_flows(server, ctx, session.session_id, predicate=lambda r: r.total >= 2)
        assert flows.total >= 2
        methods_paths = {(f.method, f.path) for f in flows.flows}
        assert ("GET", "/api/v1/user") in methods_paths
        assert ("POST", "/login") in methods_paths
        assert all(f.status_code == 200 for f in flows.flows)

        login = next(f for f in flows.flows if f.path == "/login")
        detail = await _call(
            server,
            "mitmweb_get_flow_detail",
            MitmwebGetFlowDetailInput(session_id=session.session_id, flow_id=login.flow_id),
            ctx,
        )
        assert detail.ok is True, detail.error
        headers = detail.detail["request"]["headers"]
        # R4: the Authorization header is present but redacted.
        auth_values = [v for name, v in headers if name.lower() == "authorization"]
        assert auth_values == [REDACTED]
        assert "super-secret-token" not in json.dumps(detail.detail)
    finally:
        await registry.shutdown_all(timeout=5.0)


# --------------------------------------------------------------------------- #
# E2E-B — map_local mock, LFI defence, options untouched, symlink escape
# --------------------------------------------------------------------------- #


async def test_e2e_b_map_local_mock_and_lfi_defence(tools_env, upstream_server) -> None:
    server = tools_env["server"]
    ctx = tools_env["ctx"]
    registry = tools_env["registry"]
    session = await _start_web_session(tools_env)
    proxy_url = f"http://127.0.0.1:{session.listen_ports[0]}"

    mock = tools_env["mock_root"] / "mock_user.json"
    mock.write_text('{"mocked": true, "user": "bob"}', encoding="utf-8")

    try:
        # Happy path: serve the allowlisted mock.
        set_ok = await _call(
            server,
            "mitm_set_map_local",
            MitmSetMapLocalInput(
                session_id=session.session_id,
                rule=MapLocalRuleSpec(
                    url_pattern=r"^http://mock\.test/api/v1/user$", local_path=str(mock)
                ),
            ),
            ctx,
        )
        assert set_ok.ok is True, set_ok.error
        assert set_ok.canonical_path == str(mock.resolve())

        response = await _proxied(proxy_url, "GET", "http://mock.test/api/v1/user")
        assert response.status_code == 200
        assert json.loads(response.text) == {"mocked": True, "user": "bob"}

        # Snapshot the options so we can prove the failed attempt changed nothing.
        from mcp_security_mitmproxy.web_client.client import MitmwebClient

        base_url = f"http://{session.web_host}:{session.web_port}"
        async with MitmwebClient(base_url, token=registry.get_web_token(session.session_id)) as c:
            before = await c.get_options()

        bad = await _call(
            server,
            "mitm_set_map_local",
            MitmSetMapLocalInput(
                session_id=session.session_id,
                rule=MapLocalRuleSpec(url_pattern=r"/x", local_path="/etc/passwd"),
            ),
            ctx,
        )
        assert bad.ok is False
        assert bad.error is not None
        assert bad.error.code.value == "PATH_NOT_ALLOWED"

        # A symlink inside the root pointing outside must resolve and be refused.
        escape = tools_env["mock_root"] / "escape.json"
        escape.symlink_to("/etc/passwd")
        bad_link = await _call(
            server,
            "mitm_set_map_local",
            MitmSetMapLocalInput(
                session_id=session.session_id,
                rule=MapLocalRuleSpec(url_pattern=r"/y", local_path=str(escape)),
            ),
            ctx,
        )
        assert bad_link.ok is False
        assert bad_link.error is not None
        assert bad_link.error.code.value == "PATH_NOT_ALLOWED"

        # The proxy's options are unchanged by the two rejected attempts.
        async with MitmwebClient(base_url, token=registry.get_web_token(session.session_id)) as c:
            after = await c.get_options()
        assert after["map_local"]["value"] == before["map_local"]["value"]
        assert len(after["map_local"]["value"]) == 1  # only the happy-path rule
    finally:
        await registry.shutdown_all(timeout=5.0)


# --------------------------------------------------------------------------- #
# E2E-C — map_remote + modify_headers, then list and clear
# --------------------------------------------------------------------------- #


async def test_e2e_c_map_remote_and_modify_headers(tools_env, upstream_server) -> None:
    server = tools_env["server"]
    ctx = tools_env["ctx"]
    registry = tools_env["registry"]
    session = await _start_web_session(tools_env)
    proxy_url = f"http://127.0.0.1:{session.listen_ports[0]}"

    # A second real upstream ("staging") on another port.
    staging = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    staging_port = staging.server_address[1]
    staging_thread = threading.Thread(target=staging.serve_forever, daemon=True)
    staging_thread.start()

    try:
        remote = await _call(
            server,
            "mitm_set_map_remote",
            MitmSetMapRemoteInput(
                session_id=session.session_id,
                rule=MapRemoteRuleSpec(
                    url_pattern=r"^http://origin\.test/old/",
                    replacement_url=f"http://127.0.0.1:{staging_port}/new/",
                ),
            ),
            ctx,
        )
        assert remote.ok is True, remote.error

        headers = await _call(
            server,
            "mitm_modify_headers",
            MitmModifyHeadersInput(
                session_id=session.session_id,
                rule=ModifyHeaderRuleSpec(
                    filter_expression="~s", header_name="X-Audit", header_value="1"
                ),
            ),
            ctx,
        )
        assert headers.ok is True, headers.error

        response = await _proxied(proxy_url, "GET", "http://origin.test/old/hello")
        assert response.status_code == 200
        # The upstream received the rewritten path from staging, proving map_remote.
        assert json.loads(response.text)["path"] == "/new/hello"
        assert response.headers.get("X-Audit") == "1"

        listed = await _call(
            server, "mitm_list_rules", MitmListRulesInput(session_id=session.session_id), ctx
        )
        assert listed.ok is True, listed.error
        assert listed.counts.get("map_remote", 0) == 1
        assert listed.counts.get("modify_headers", 0) == 1
        assert all(rule.valid for rule in listed.rules)

        cleared = await _call(
            server, "mitm_clear_rules", MitmClearRulesInput(session_id=session.session_id), ctx
        )
        assert cleared.ok is True, cleared.error
        assert cleared.cleared_count == 2
        assert all(v == 0 for v in cleared.remaining.values())
    finally:
        staging.shutdown()
        staging.server_close()
        staging_thread.join(timeout=5)
        await registry.shutdown_all(timeout=5.0)


# --------------------------------------------------------------------------- #
# E2E-D — server replay from a captured dump
# --------------------------------------------------------------------------- #


async def test_e2e_d_server_replay_from_dump(tools_env, upstream_server, tmp_path) -> None:
    """A recorded flow replays offline; the external network is never touched."""
    server = tools_env["server"]
    ctx = tools_env["ctx"]
    registry = tools_env["registry"]

    # Record a session with mitmdump to produce a real .mitm dump.
    rec_session, proxy_port, dump_path = await _start_proxy_session(
        tools_env,
        tool_name="mitmdump_start",
        dump_root=tools_env["dump_root"],
        dump_name="replay.mitm",
    )

    origin = upstream_server["origin"]
    recorded_url = f"{origin}/api/v1/user"
    resp = await _proxied(f"http://127.0.0.1:{proxy_port}", "GET", recorded_url)
    assert resp.status_code == 200 and resp.text == '{"id": 1, "name": "alice"}'
    await _call(server, "mitmdump_stop", StopInput(session_id=rec_session.session_id), ctx)

    # Wait for the dump to flush.
    for _ in range(200):
        if dump_path.exists() and dump_path.stat().st_size > 0:
            break
        await asyncio.sleep(0.1)
    assert dump_path.exists() and dump_path.stat().st_size > 0, "dump was never written"

    # The upstream is stopped here so a replay can only succeed offline: the
    # fixture's server is shut down and any live connection would fail.
    upstream_server["stop"]()

    replay_port = free_port()
    replay = await _call(
        server,
        "mitmdump_replay",
        MitmdumpReplayInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=replay_port)],
            server_replay=[str(dump_path)],
            replay_kill_extra=True,
        ),
        ctx,
    )
    assert replay.ok is True, replay.error
    try:
        replay_runner = registry.get_runner(replay.session.session_id)
        ready = False
        for _ in range(150):
            if wait_for_port("127.0.0.1", replay_port, timeout=0.2):
                ready = True
                break
            if not replay_runner.running:
                pytest.fail(
                    f"replay process exited early rc={replay_runner.returncode}: "
                    f"{replay_runner.logs.text()[-300:]}"
                )
            await asyncio.sleep(0.1)
        assert ready, "replay proxy port never listened"
        replayed = await _proxied(f"http://127.0.0.1:{replay_port}", "GET", recorded_url)
        assert replayed.status_code == 200
        assert json.loads(replayed.text) == {"id": 1, "name": "alice"}
    finally:
        await registry.shutdown_all(timeout=5.0)


# --------------------------------------------------------------------------- #
# E2E-E — offline export + filter from the recorded dump
# --------------------------------------------------------------------------- #


async def test_e2e_e_export_and_filter_offline(tools_env, upstream_server) -> None:
    server = tools_env["server"]
    ctx = tools_env["ctx"]
    registry = tools_env["registry"]

    session, proxy_port, dump_path = await _start_proxy_session(
        tools_env,
        tool_name="mitmdump_start",
        dump_root=tools_env["dump_root"],
        dump_name="export.mitm",
    )

    origin = upstream_server["origin"]
    await _proxied(f"http://127.0.0.1:{proxy_port}", "GET", f"{origin}/api/v1/user")
    await _proxied(
        f"http://127.0.0.1:{proxy_port}",
        "POST",
        f"{origin}/login",
        json={"user": "alice"},
        headers={"Authorization": "Bearer export-secret"},
    )
    await _call(server, "mitmdump_stop", StopInput(session_id=session.session_id), ctx)

    for _ in range(200):
        if dump_path.exists() and dump_path.stat().st_size > 0:
            break
        await asyncio.sleep(0.1)
    assert dump_path.exists() and dump_path.stat().st_size > 0, "dump was never written"

    try:
        # Filter offline (~m POST & ~u /login) returns exactly the login flow.
        filtered = await _call(
            server,
            "mitm_filter_flows",
            MitmFilterFlowsInput(expression="~m POST & ~u /login", flow_path=str(dump_path)),
            ctx,
        )
        assert filtered.ok is True, filtered.error
        assert filtered.count == 1
        assert filtered.matched[0].method == "POST"
        assert filtered.matched[0].path == "/login"

        login_flow_id = filtered.matched[0].flow_id
        exported = await _call(
            server,
            "mitm_export_flow",
            MitmExportFlowInput(
                flow_id=login_flow_id, format=ExportFormat.CURL, flow_path=str(dump_path)
            ),
            ctx,
        )
        assert exported.ok is True, exported.error
        assert exported.content is not None
        assert exported.content.startswith("curl")
        assert "-X POST" in exported.content
        # R4: the Authorization header is redacted in the exported command.
        assert "export-secret" not in exported.content
    finally:
        await registry.shutdown_all(timeout=5.0)

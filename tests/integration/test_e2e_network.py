"""End-to-end integration: HTTP client -> mitmproxy -> mutation rules -> upstream.

Every test drives real bytes through a real proxy subprocess. Client -> mitmweb
(or mitmdump) -> ``map_remote``/``map_local``/``modify_headers`` -> a real HTTP
upstream bound to loopback.

Skipped automatically when the mitmproxy executables are unavailable.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from mitmproxy import io as mio

from mcp_security_mitmproxy.schemas.common import ProxyMode
from mcp_security_mitmproxy.schemas.mitmweb import MitmwebStartInput
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec, StopInput
from mcp_security_mitmproxy.schemas.rules import (
    MapLocalRuleSpec,
    MapRemoteRuleSpec,
    MitmModifyHeadersInput,
    MitmSetMapLocalInput,
    MitmSetMapRemoteInput,
    ModifyHeaderRuleSpec,
)
from mcp_security_mitmproxy.web_client.client import MitmwebClient

from .conftest import free_port, mitmproxy_available, wait_for_port

pytestmark = mitmproxy_available


async def _proxied_get(proxy_url: str, url: str, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(proxy=proxy_url, timeout=20) as client:
        return await client.get(url, **kwargs)


async def _call_tool(server, name: str, params, ctx):
    tool = await server.get_tool(name)
    return await tool.fn(params, ctx)


async def _wait_session_ready(session) -> None:
    """Block until both the proxy and the web REST bridge accept connections.

    ``registry.start`` returns once the process is spawned; mitmweb then needs a
    moment to bind its proxy and web ports. The rule tools talk to the REST
    bridge, so they must not run before it is listening.
    """
    for _ in range(200):
        proxy_ok = (
            wait_for_port(session.listen_host, session.listen_ports[0], timeout=0.2)
            if session.listen_ports
            else False
        )
        web_ok = (
            wait_for_port(session.web_host, session.web_port, timeout=0.2)
            if session.web_port
            else False
        )
        if proxy_ok and web_ok:
            return
        await asyncio.sleep(0.1)
    pytest.fail("mitmweb session did not become ready in time")


# --------------------------------------------------------------------------- #
# Direct REST bridge (mitmweb subprocess + MitmwebClient)
# --------------------------------------------------------------------------- #


async def test_e2e_http_round_trip_through_proxy(mitmweb_instance, upstream_server) -> None:
    """Baseline: a plain request traverses the proxy to the upstream."""
    response = await _proxied_get(
        mitmweb_instance["proxy_url"], f"{upstream_server['origin']}/hello"
    )
    assert response.status_code == 200
    assert response.text == "UPSTREAM-HELLO"
    assert response.headers["X-Upstream"] == "mitm-e2e"


async def test_e2e_map_remote_rewrites_to_other_upstream(mitmweb_instance, upstream_server) -> None:
    """map_remote rewrites the request host to a second real upstream."""
    import http.server
    import threading

    from .conftest import _UpstreamHandler

    second = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    second_port = second.server_address[1]
    thread = threading.Thread(target=second.serve_forever, daemon=True)
    thread.start()
    try:
        spec = f"|^http://rewrite\\.test/|http://127.0.0.1:{second_port}/"
        async with MitmwebClient(
            mitmweb_instance["web_url"], token=mitmweb_instance["token"]
        ) as client:
            options = await client.get_options()
            await client.put_options(map_remote=[*options["map_remote"]["value"], spec])

        response = await _proxied_get(mitmweb_instance["proxy_url"], "http://rewrite.test/hello")
        assert response.status_code == 200
        assert response.text == "UPSTREAM-HELLO"
    finally:
        second.shutdown()
        second.server_close()
        thread.join(timeout=5)


async def test_e2e_map_local_serves_allowlisted_mock(mitmweb_instance, tmp_path: Path) -> None:
    mock = tmp_path / "mock.json"
    mock.write_text('{"mocked": true}', encoding="utf-8")
    spec = f"|^http://mock\\.test/data$|{mock}"

    async with MitmwebClient(
        mitmweb_instance["web_url"], token=mitmweb_instance["token"]
    ) as client:
        options = await client.get_options()
        await client.put_options(map_local=[*options["map_local"]["value"], spec])

    response = await _proxied_get(mitmweb_instance["proxy_url"], "http://mock.test/data")
    assert response.status_code == 200
    assert json.loads(response.text) == {"mocked": True}


async def test_e2e_modify_headers_injects_on_response(mitmweb_instance, upstream_server) -> None:
    spec = "|~s|X-Injected|by-mitm-e2e"
    async with MitmwebClient(
        mitmweb_instance["web_url"], token=mitmweb_instance["token"]
    ) as client:
        options = await client.get_options()
        await client.put_options(modify_headers=[*options["modify_headers"]["value"], spec])

    response = await _proxied_get(
        mitmweb_instance["proxy_url"], f"{upstream_server['origin']}/hello"
    )
    assert response.status_code == 200
    assert response.headers.get("X-Injected") == "by-mitm-e2e"


async def test_e2e_flows_are_captured_and_readable(mitmweb_instance, upstream_server) -> None:
    await _proxied_get(mitmweb_instance["proxy_url"], f"{upstream_server['origin']}/hello")
    # give the bridge a moment to register the flow
    for _ in range(50):
        async with MitmwebClient(
            mitmweb_instance["web_url"], token=mitmweb_instance["token"]
        ) as client:
            flows, total = await client.get_flows(limit=50)
        if total >= 1:
            break
        await asyncio.sleep(0.1)
    assert total >= 1
    assert any(flow.method == "GET" for flow in flows)


# --------------------------------------------------------------------------- #
# Full MCP tool surface (server.create_server + real registry)
# --------------------------------------------------------------------------- #


async def test_e2e_tools_mitmweb_start_rules_and_proxy(
    tools_env, upstream_server, tmp_path
) -> None:
    """Start via MCP tool, apply rules via MCP tools, verify through the proxy."""
    server = tools_env["server"]
    ctx = tools_env["ctx"]
    registry = tools_env["registry"]
    proxy_port = free_port()

    start = await _call_tool(
        server,
        "mitmweb_start",
        MitmwebStartInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=proxy_port)],
            web_port=free_port(),
        ),
        ctx,
    )
    assert start.ok is True, start.error
    session_id = start.session.session_id
    assert start.session.status.value == "running"
    await _wait_session_ready(start.session)

    try:
        # map_local through the MCP tool (allowlist validated by the tool layer).
        # The file must live under allowed_mock_roots.
        mock = tools_env["mock_root"] / "tool-mock.txt"
        mock.write_text("TOOL-MOCKED", encoding="utf-8")
        set_rule = await _call_tool(
            server,
            "mitm_set_map_local",
            MitmSetMapLocalInput(
                session_id=session_id,
                rule=MapLocalRuleSpec(
                    url_pattern=r"^http://tool\.test/mock$", local_path=str(mock)
                ),
            ),
            ctx,
        )
        assert set_rule.ok is True, set_rule.error
        assert set_rule.canonical_path == str(mock.resolve())

        proxy_url = f"http://127.0.0.1:{proxy_port}"
        response = await _proxied_get(proxy_url, "http://tool.test/mock")
        assert response.status_code == 200
        assert response.text == "TOOL-MOCKED"

        # list + clear via tools
        listed = await _call_tool(server, "mitm_list_rules", _ListInput(session_id), ctx)
        assert listed.ok is True
        assert listed.counts.get("map_local", 0) == 1

        stopped = await _call_tool(server, "mitmweb_stop", StopInput(session_id=session_id), ctx)
        assert stopped.ok is True
    finally:
        await registry.shutdown_all(timeout=5.0)


async def test_e2e_tools_map_remote_and_modify_headers(tools_env, upstream_server) -> None:
    server = tools_env["server"]
    ctx = tools_env["ctx"]
    registry = tools_env["registry"]
    proxy_port = free_port()

    start = await _call_tool(
        server,
        "mitmweb_start",
        MitmwebStartInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=proxy_port)],
            web_port=free_port(),
        ),
        ctx,
    )
    assert start.ok is True, start.error
    session_id = start.session.session_id
    await _wait_session_ready(start.session)
    try:
        remote = await _call_tool(
            server,
            "mitm_set_map_remote",
            MitmSetMapRemoteInput(
                session_id=session_id,
                rule=MapRemoteRuleSpec(
                    url_pattern=r"^http://from\.test/",
                    replacement_url=upstream_server["origin"] + "/",
                ),
            ),
            ctx,
        )
        assert remote.ok is True, remote.error

        headers = await _call_tool(
            server,
            "mitm_modify_headers",
            MitmModifyHeadersInput(
                session_id=session_id,
                rule=ModifyHeaderRuleSpec(
                    filter_expression="~s", header_name="X-Tool-Injected", header_value="yes"
                ),
            ),
            ctx,
        )
        assert headers.ok is True, headers.error

        response = await _proxied_get(f"http://127.0.0.1:{proxy_port}", "http://from.test/hello")
        assert response.status_code == 200
        assert response.text == "UPSTREAM-HELLO"
        assert response.headers.get("X-Tool-Injected") == "yes"
    finally:
        await registry.shutdown_all(timeout=5.0)


async def test_e2e_tools_reject_lfi_before_spawning(tools_env) -> None:
    """A disallowed map_local path fails at the tool layer, no proxy touched.

    A *running* session is required so the failure is the allowlist, not a
    missing session — proving ``ensure_allowed`` (not session lookup) is what
    rejects the path.
    """
    from mcp_security_mitmproxy.schemas.mitmweb import MitmwebStartInput
    from mcp_security_mitmproxy.schemas.rules import MitmSetMapLocalInput

    server = tools_env["server"]
    ctx = tools_env["ctx"]
    registry = tools_env["registry"]
    proxy_port = free_port()

    start = await _call_tool(
        server,
        "mitmweb_start",
        MitmwebStartInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=proxy_port)],
            web_port=free_port(),
        ),
        ctx,
    )
    assert start.ok is True, start.error
    session_id = start.session.session_id
    await _wait_session_ready(start.session)
    try:
        result = await _call_tool(
            server,
            "mitm_set_map_local",
            MitmSetMapLocalInput(
                session_id=session_id,
                rule=MapLocalRuleSpec(url_pattern=r"/x", local_path="/etc/passwd"),
            ),
            ctx,
        )
        assert result.ok is False
        assert result.error is not None
        assert result.error.code.value == "PATH_NOT_ALLOWED"
    finally:
        await registry.shutdown_all(timeout=5.0)


# --------------------------------------------------------------------------- #
# Headless mitmdump capture -> offline read (real .mitm on disk)
# --------------------------------------------------------------------------- #


async def test_e2e_mitmdump_captures_traffic_to_disk(mitmdump_process, upstream_server) -> None:
    response = await _proxied_get(
        mitmdump_process["proxy_url"], f"{upstream_server['origin']}/hello"
    )
    assert response.status_code == 200
    assert response.text == "UPSTREAM-HELLO"

    dump_path = mitmdump_process["dump_path"]
    # The dump is flushed periodically; poll until the flow is present.
    flows = []
    for _ in range(100):
        if dump_path.exists() and dump_path.stat().st_size > 0:
            with dump_path.open("rb") as handle:
                flows = list(mio.FlowReader(handle).stream())
            if flows:
                break
        await asyncio.sleep(0.1)

    assert flows, "no flow was written to the .mitm dump"
    request = flows[0].request
    assert request is not None
    assert request.path == "/hello"
    assert flows[0].response is not None
    assert flows[0].response.status_code == 200


def _ListInput(session_id: str):
    from mcp_security_mitmproxy.schemas.rules import MitmListRulesInput

    return MitmListRulesInput(session_id=session_id)

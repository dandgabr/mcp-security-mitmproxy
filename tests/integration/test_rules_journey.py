"""E2E journey for the Fase 4 rule tools over a real mitmweb + real traffic.

Complements ``test_e2e_network.py``: that file covers single mutations, this one
covers the paths only repetition and state transitions expose —

* ``mitm_modify_body`` rewriting a real request payload,
* ``mitm_modify_headers`` removing a request header,
* repeated mutations on one session, which is the ordering that made the CSRF
  handshake fail intermittently before the cookie-jar fix,
* an invalid FlowFilter, which must be refused without losing the applied rules.

Skipped when the mitmproxy executables are unavailable.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from mcp_security_mitmproxy.schemas.common import ProxyMode
from mcp_security_mitmproxy.schemas.mitmweb import MitmwebStartInput
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec
from mcp_security_mitmproxy.schemas.rules import (
    HeaderOperation,
    MapRemoteRuleSpec,
    MitmClearRulesInput,
    MitmListRulesInput,
    MitmModifyBodyInput,
    MitmModifyHeadersInput,
    MitmSetMapRemoteInput,
    ModifyBodyRuleSpec,
    ModifyHeaderRuleSpec,
    RuleType,
)

from .conftest import free_port, mitmproxy_available, wait_for_port

pytestmark = mitmproxy_available


async def _call(server, name: str, params, ctx):
    tool = await server.get_tool(name)
    return await tool.fn(params, ctx)


async def _start_web_session(server, ctx, *, proxy_port: int):
    started = await _call(
        server,
        "mitmweb_start",
        MitmwebStartInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=proxy_port)],
            web_port=free_port(),
        ),
        ctx,
    )
    assert started.ok is True, started.error
    session = started.session
    for _ in range(200):
        if wait_for_port(session.listen_host, proxy_port, timeout=0.2) and wait_for_port(
            session.web_host, session.web_port, timeout=0.2
        ):
            return session
        await asyncio.sleep(0.1)
    pytest.fail("mitmweb session did not become ready")


def _lower_headers(payload: dict) -> dict:
    return {key.lower(): value for key, value in payload["headers"].items()}


async def _proxied(proxy_url: str, method: str, url: str, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(proxy=proxy_url, timeout=20) as client:
        return await client.request(method, url, **kwargs)


async def test_e2e_modify_body_rewrites_request_payload(tools_env, upstream_server) -> None:
    server, ctx = tools_env["server"], tools_env["ctx"]
    registry = tools_env["registry"]
    proxy_port = free_port()
    session = await _start_web_session(server, ctx, proxy_port=proxy_port)
    sid = session.session_id
    try:
        applied = await _call(
            server,
            "mitm_modify_body",
            MitmModifyBodyInput(
                session_id=sid,
                rule=ModifyBodyRuleSpec(
                    filter_expression="~q",
                    pattern=r'"role":\s*"user"',
                    replacement='"role": "admin"',
                ),
            ),
            ctx,
        )
        assert applied.ok is True, applied.error

        response = await _proxied(
            f"http://127.0.0.1:{proxy_port}",
            "POST",
            f"{upstream_server['origin']}/echo",
            content=b'{"role":"user","id":7}',
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200
        echoed = json.loads(response.json()["body"])
        assert echoed["role"] == "admin"
        assert echoed["id"] == 7
    finally:
        await registry.shutdown_all(timeout=10.0)


async def test_e2e_modify_headers_removes_request_header(tools_env, upstream_server) -> None:
    server, ctx = tools_env["server"], tools_env["ctx"]
    registry = tools_env["registry"]
    proxy_port = free_port()
    session = await _start_web_session(server, ctx, proxy_port=proxy_port)
    sid = session.session_id
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    try:
        # Control: the secret reaches the upstream when no rule is active.
        baseline = await _proxied(
            proxy_url,
            "GET",
            f"{upstream_server['origin']}/echo",
            headers={"X-Api-Key": "leaked-key", "X-Keep": "kept"},
        )
        assert _lower_headers(baseline.json())["x-api-key"] == "leaked-key"

        applied = await _call(
            server,
            "mitm_modify_headers",
            MitmModifyHeadersInput(
                session_id=sid,
                rule=ModifyHeaderRuleSpec(
                    filter_expression="~q",
                    header_name="X-Api-Key",
                    operation=HeaderOperation.REMOVE,
                ),
            ),
            ctx,
        )
        assert applied.ok is True, applied.error

        response = await _proxied(
            proxy_url,
            "GET",
            f"{upstream_server['origin']}/echo",
            headers={"X-Api-Key": "leaked-key", "X-Keep": "kept"},
        )
        headers = _lower_headers(response.json())
        assert "x-api-key" not in headers
        assert headers["x-keep"] == "kept"
    finally:
        await registry.shutdown_all(timeout=10.0)


async def test_e2e_repeated_mutations_keep_the_csrf_bootstrap_alive(tools_env) -> None:
    """Six back-to-back mutations: the jar-primed ordering that used to 403."""
    server, ctx = tools_env["server"], tools_env["ctx"]
    registry = tools_env["registry"]
    session = await _start_web_session(server, ctx, proxy_port=free_port())
    sid = session.session_id
    try:
        for index in range(6):
            result = await _call(
                server,
                "mitm_modify_body",
                MitmModifyBodyInput(
                    session_id=sid,
                    rule=ModifyBodyRuleSpec(pattern=f"token{index}", replacement=f"value{index}"),
                ),
                ctx,
            )
            assert result.ok is True, f"mutation {index} failed: {result.error}"
            assert result.rule_id == f"modify_body:{index}"

        listed = await _call(server, "mitm_list_rules", MitmListRulesInput(session_id=sid), ctx)
        assert listed.ok is True
        assert listed.counts == {"modify_body": 6}
        assert all(rule.valid for rule in listed.rules)

        cleared = await _call(
            server,
            "mitm_clear_rules",
            MitmClearRulesInput(session_id=sid, rule_type=RuleType.MODIFY_BODY),
            ctx,
        )
        assert cleared.ok is True
        assert cleared.cleared_count == 6
        assert cleared.remaining["modify_body"] == 0

        emptied = await _call(server, "mitm_clear_rules", MitmClearRulesInput(session_id=sid), ctx)
        assert emptied.ok is True
        assert emptied.cleared_count == 0
        assert set(emptied.remaining.values()) == {0}
    finally:
        await registry.shutdown_all(timeout=10.0)


async def test_e2e_invalid_filter_is_refused_without_losing_applied_rules(tools_env) -> None:
    server, ctx = tools_env["server"], tools_env["ctx"]
    registry = tools_env["registry"]
    session = await _start_web_session(server, ctx, proxy_port=free_port())
    sid = session.session_id
    try:
        good = await _call(
            server,
            "mitm_set_map_remote",
            MitmSetMapRemoteInput(
                session_id=sid,
                rule=MapRemoteRuleSpec(
                    url_pattern=r"^http://good\.test/", replacement_url="http://127.0.0.1:9/"
                ),
            ),
            ctx,
        )
        assert good.ok is True, good.error

        bad = await _call(
            server,
            "mitm_set_map_remote",
            MitmSetMapRemoteInput(
                session_id=sid,
                rule=MapRemoteRuleSpec(
                    filter_expression="~invalid([[",
                    url_pattern=r"^http://bad\.test/",
                    replacement_url="http://127.0.0.1:9/",
                ),
            ),
            ctx,
        )
        assert bad.ok is False
        assert bad.error is not None
        assert bad.error.code.value == "INVALID_INPUT"

        listed = await _call(server, "mitm_list_rules", MitmListRulesInput(session_id=sid), ctx)
        assert listed.ok is True
        assert listed.counts == {"map_remote": 1}, "the rejected rule leaked into the options"
        assert listed.rules[0].valid is True
    finally:
        await registry.shutdown_all(timeout=10.0)

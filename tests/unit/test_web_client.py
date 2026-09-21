"""Unit tests for the mitmweb REST client (SEC-4 filter encoding, R4 redaction).

The client builds its own ``httpx.AsyncClient``, so the transport is injected by
patching ``httpx.AsyncClient`` with a factory that attaches an
``httpx.MockTransport``. No socket is opened and every request URL is captured
for assertion.
"""

from __future__ import annotations

import io
from collections.abc import Callable

import httpx
import pytest
from mitmproxy import io as mio
from mitmproxy.test import tflow

from mcp_security_mitmproxy.core.errors import (
    InvalidInputError,
    SessionNotRunningError,
    TimeoutError_,
    UpstreamUnreachableError,
)
from mcp_security_mitmproxy.web_client.client import MitmwebClient

BASE_URL = "http://127.0.0.1:8081"
Handler = Callable[[httpx.Request], httpx.Response]


def _install_transport(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> list[httpx.Request]:
    """Route the client's internal AsyncClient through an httpx.MockTransport."""
    captured: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    real_client = httpx.AsyncClient

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(recording)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return captured


def _dump_bytes(*flows: object) -> bytes:
    """Serialise flows into a real ``.mitm`` payload (as ``/flows/dump`` returns)."""
    buffer = io.BytesIO()
    writer = mio.FlowWriter(buffer)
    for flow in flows:
        writer.add(flow)
    return buffer.getvalue()


def _flow_payload(flow_id: str, *, method: str = "GET") -> dict[str, object]:
    """One raw flow dict in the shape ``/flows`` returns."""
    return {
        "id": flow_id,
        "type": "http",
        "timestamp_start": 1.0,
        "timestamp_end": 2.0,
        "request": {
            "method": method,
            "scheme": "http",
            "host": "example.com",
            "port": 80,
            "path": "/",
            "timestamp_start": 1.0,
        },
        "response": {"status_code": 200, "timestamp_end": 2.0},
    }


async def test_get_flows_without_filter_paginates(monkeypatch) -> None:
    payload = [_flow_payload("a"), _flow_payload("b"), _flow_payload("c")]
    captured = _install_transport(monkeypatch, lambda _req: httpx.Response(200, json=payload))

    async with MitmwebClient(BASE_URL, token="tok-123") as client:
        flows, total = await client.get_flows(limit=2, offset=1)

    assert total == 3
    assert [flow.flow_id for flow in flows] == ["b", "c"]
    assert [request.url.path for request in captured] == ["/flows"]
    assert captured[0].headers["Authorization"] == "Bearer tok-123"


async def test_get_flows_with_filter_uses_dump_endpoint(monkeypatch) -> None:
    matching = tflow.tflow(resp=True)
    matching.request.method = "POST"
    dump = _dump_bytes(matching)

    captured = _install_transport(monkeypatch, lambda _req: httpx.Response(200, content=dump))

    async with MitmwebClient(BASE_URL, token="tok") as client:
        flows, total = await client.get_flows(filter_expression="~m POST", limit=10, offset=0)

    assert total == 1
    assert [flow.method for flow in flows] == ["POST"]
    assert flows[0].flow_id == matching.id
    assert [request.url.path for request in captured] == ["/flows/dump"]
    assert captured[0].url.params["filter"] == "~m POST"
    assert " " not in captured[0].url.query.decode()


async def test_get_flows_filter_is_percent_encoded(monkeypatch) -> None:
    captured = _install_transport(
        monkeypatch, lambda _req: httpx.Response(200, content=_dump_bytes())
    )

    async with MitmwebClient(BASE_URL) as client:
        await client.get_flows(filter_expression="~u /api/v1")

    query = captured[0].url.query.decode()
    assert " " not in query
    assert captured[0].url.params["filter"] == "~u /api/v1"
    assert "%2F" in query or "+" in query


async def test_get_dump_without_filter_sends_no_query(monkeypatch) -> None:
    captured = _install_transport(monkeypatch, lambda _req: httpx.Response(200, content=b"raw"))

    async with MitmwebClient(BASE_URL) as client:
        assert await client.get_dump() == b"raw"

    assert captured[0].url.path == "/flows/dump"
    assert captured[0].url.query == b""


async def test_get_flow_detail_redacts_headers_and_content(monkeypatch) -> None:
    payload = [
        {
            "id": "f-1",
            "request": {
                "method": "GET",
                "scheme": "http",
                "host": "example.com",
                "port": 80,
                "path": "/",
                "headers": [["Host", "example.com"], ["Authorization", "Bearer s3cr3t"]],
            },
            "response": {
                "status_code": 200,
                "headers": [["Content-Type", "application/json"], ["Set-Cookie", "sid=abc"]],
            },
        }
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/flows":
            return httpx.Response(200, json=payload)
        if request.url.path == "/flows/f-1/request/content/auto":
            return httpx.Response(
                200, json={"text": '{"access_token": "leak-me"}', "view_name": "auto"}
            )
        if request.url.path == "/flows/f-1/response/content/auto":
            return httpx.Response(200, json={"text": "plain-body", "view_name": "auto"})
        return httpx.Response(404)

    _install_transport(monkeypatch, handler)

    async with MitmwebClient(BASE_URL, token="tok") as client:
        detail = await client.get_flow_detail("f-1")

    assert detail["request"]["headers"] == [
        ["Host", "example.com"],
        ["Authorization", "[REDACTED]"],
    ]
    assert detail["response"]["headers"] == [
        ["Content-Type", "application/json"],
        ["Set-Cookie", "[REDACTED]"],
    ]
    assert "leak-me" not in detail["request"]["content_view"]["text"]
    assert "[REDACTED]" in detail["request"]["content_view"]["text"]


async def test_get_flow_detail_without_redaction_keeps_secrets(monkeypatch) -> None:
    payload = [
        {
            "id": "f-1",
            "request": {
                "method": "GET",
                "scheme": "http",
                "host": "example.com",
                "port": 80,
                "path": "/",
                "headers": [["Authorization", "Bearer s3cr3t"]],
            },
        }
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/flows":
            return httpx.Response(200, json=payload)
        if request.url.path == "/flows/f-1/request/content/auto":
            return httpx.Response(200, json={"text": "leak-me", "view_name": "auto"})
        return httpx.Response(404)

    _install_transport(monkeypatch, handler)

    async with MitmwebClient(BASE_URL, token="tok") as client:
        detail = await client.get_flow_detail("f-1", redact=False)

    assert detail["request"]["headers"] == [["Authorization", "Bearer s3cr3t"]]
    assert detail["request"]["content_view"]["text"] == "leak-me"


async def test_get_flow_detail_unknown_flow_raises(monkeypatch) -> None:
    _install_transport(monkeypatch, lambda _req: httpx.Response(200, json=[]))

    async with MitmwebClient(BASE_URL) as client:
        with pytest.raises(SessionNotRunningError):
            await client.get_flow_detail("ghost")


async def test_get_flows_403_raises_upstream_unreachable(monkeypatch) -> None:
    _install_transport(monkeypatch, lambda _req: httpx.Response(403))

    async with MitmwebClient(BASE_URL) as client:
        with pytest.raises(UpstreamUnreachableError):
            await client.get_flows()


async def test_get_flows_timeout_raises_timeout_error(monkeypatch) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("boom")

    _install_transport(monkeypatch, handler)

    async with MitmwebClient(BASE_URL) as client:
        with pytest.raises(TimeoutError_):
            await client.get_flows()


async def test_rejected_filter_raises_invalid_input(monkeypatch) -> None:
    _install_transport(monkeypatch, lambda _req: httpx.Response(400))

    async with MitmwebClient(BASE_URL) as client:
        with pytest.raises(InvalidInputError):
            await client.get_dump(filter_expression="~broken([")
        with pytest.raises(InvalidInputError):
            await client.get_flows(filter_expression="~broken([")

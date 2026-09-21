"""HTTP client adapter for the mitmweb REST API (architecture §2, §3.3.5, §3.3.6).

Connects to a running mitmweb instance over HTTP, passes bearer authentication,
and fetches flow lists, flow details, content views, or executes web commands.

CSRF: mitmweb registers its Tornado app with ``xsrf_cookies=True``, so every
``PUT``/``POST`` needs an ``X-XSRFToken`` header. The token is bootstrapped once
from the ``/updates`` WebSocket handshake (see
:mod:`mcp_security_mitmproxy.web_client.ws`) and cached for the client's
lifetime.
"""

from __future__ import annotations

import contextlib
from typing import Any

import httpx

from mcp_security_mitmproxy.core.errors import (
    InvalidInputError,
    SessionNotRunningError,
    TimeoutError_,
    UpstreamUnreachableError,
)
from mcp_security_mitmproxy.core.redact import redact_headers, redact_text
from mcp_security_mitmproxy.schemas.mitmweb import FlowSummary
from mcp_security_mitmproxy.web_client.ws import fetch_xsrf_token


def _read_flows(dump: bytes) -> list[Any]:
    """Parse ``.mitm`` bytes into in-process flows (lazy mitmproxy import)."""
    import io as py_io

    from mitmproxy import io as mio

    reader = mio.FlowReader(py_io.BytesIO(dump))
    return list(reader.stream())


class MitmwebClient:
    """Async HTTP client for interacting with mitmweb."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._token = token
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )
        self._base_url = base_url
        self._xsrf_token: str | None = None
        self._xsrf_loaded = False

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _ensure_csrf_token(self) -> str | None:
        """Fetch and cache the ``_mitmproxy_xsrf`` token on first mutation.

        A missing token is not an error: a mitmweb built without CSRF (or an
        older version) accepts the mutation without the header.
        """
        if self._xsrf_loaded:
            return self._xsrf_token
        self._xsrf_loaded = True

        url = httpx.URL(self._base_url)
        host = url.host or "127.0.0.1"
        port = url.port or 80
        auth_header = f"Bearer {self._token}" if self._token else None
        cookie_name = f"mitmproxy-auth-{port}"
        # Any request materialises the auth cookie in the client's jar; a probe
        # is needed only when the jar does not have it yet (e.g. a mutation is
        # the very first call). Read the jar — a response's `.cookies` only
        # carries cookies newly set by that response, which misses the cookie
        # already obtained by an earlier read.
        if self._client.cookies.get(cookie_name) is None:
            with contextlib.suppress(httpx.TimeoutException, httpx.RequestError):
                await self._client.get("/")
        auth_cookie = self._client.cookies.get(cookie_name)
        cookie_header = f"{cookie_name}={auth_cookie}" if auth_cookie else ""

        try:
            self._xsrf_token = await fetch_xsrf_token(
                host, port, cookie_header=cookie_header, authorization=auth_header
            )
        except (OSError, TimeoutError):
            self._xsrf_token = None
        if self._xsrf_token:
            self._client.headers["X-XSRFToken"] = self._xsrf_token
            # Put the token in the client's cookie jar so httpx attaches it to
            # every request deterministically. Relying on a hand-built
            # ``Cookie`` header only when an auth cookie existed left the jar
            # without the XSRF cookie on first mutation, which made Tornado
            # intermittently reject PUT /options with 403.
            self._client.cookies.set("_mitmproxy_xsrf", self._xsrf_token, domain=host, path="/")
        return self._xsrf_token

    async def __aenter__(self) -> MitmwebClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def get_dump(self, *, filter_expression: str | None = None) -> bytes:
        """Download the flow dump (``/flows/dump``) as ``.mitm`` bytes.

        mitmweb evaluates an optional FlowFilter server-side here. The filter is
        passed via ``params`` so httpx percent-encodes it — never interpolated
        into the URL (SEC-4).
        """
        params = {"filter": filter_expression} if filter_expression else None
        try:
            resp = await self._client.get("/flows/dump", params=params)
        except httpx.TimeoutException as exc:
            raise TimeoutError_(f"timeout contacting mitmweb: {exc}") from exc
        except httpx.RequestError as exc:
            raise UpstreamUnreachableError(f"unable to reach mitmweb: {exc}") from exc

        if resp.status_code == 400:
            raise InvalidInputError(f"mitmweb rejected the flow filter: {filter_expression!r}")
        if resp.status_code == 403:
            raise UpstreamUnreachableError("mitmweb authentication failed (403 Forbidden)")
        if resp.status_code != 200:
            raise UpstreamUnreachableError(
                f"mitmweb /flows/dump returned unexpected status {resp.status_code}"
            )
        return resp.content

    async def get_flows(
        self,
        *,
        filter_expression: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FlowSummary], int]:
        """Fetch flows from mitmweb and format as FlowSummary items.

        ``filter_expression`` is applied server-side via ``/flows/dump`` (the
        only endpoint that honours a FlowFilter); ``/flows`` returns the full
        in-memory view without filtering. Filtering happens before pagination so
        ``total`` reflects the matched set, not the whole session.
        """
        raw_flows = await self._fetch_raw_flows(filter_expression)
        total = len(raw_flows)

        # Slice according to pagination offset/limit
        paged = raw_flows[offset : offset + limit]

        summaries: list[FlowSummary] = []
        for f in paged:
            req = f.get("request", {})
            resp_data = f.get("response", {})
            f_type = f.get("type", "http")
            if f_type not in ("http", "tcp", "udp", "dns", "websocket"):
                f_type = "http"

            time_start = f.get("timestamp_start") or req.get("timestamp_start")
            time_end = resp_data.get("timestamp_end") or f.get("timestamp_end")
            duration = (time_end - time_start) if (time_start and time_end) else None

            summaries.append(
                FlowSummary(
                    flow_id=f.get("id", ""),
                    type=f_type,
                    method=req.get("method"),
                    scheme=req.get("scheme"),
                    host=req.get("host", ""),
                    port=req.get("port", 80),
                    path=req.get("path"),
                    status_code=resp_data.get("status_code"),
                    timestamp_start=time_start,
                    duration=duration,
                )
            )

        return summaries, total

    async def _fetch_raw_flows(self, filter_expression: str | None) -> list[dict[str, Any]]:
        """Return the raw flow dicts, applying the filter server-side if given."""
        if filter_expression:
            dump = await self.get_dump(filter_expression=filter_expression)
            return [self._flow_to_dict(flow) for flow in _read_flows(dump)]

        try:
            resp = await self._client.get("/flows")
        except httpx.TimeoutException as exc:
            raise TimeoutError_(f"timeout contacting mitmweb: {exc}") from exc
        except httpx.RequestError as exc:
            raise UpstreamUnreachableError(f"unable to reach mitmweb: {exc}") from exc

        if resp.status_code == 403:
            raise UpstreamUnreachableError("mitmweb authentication failed (403 Forbidden)")
        if resp.status_code != 200:
            raise UpstreamUnreachableError(
                f"mitmweb /flows returned unexpected status {resp.status_code}"
            )
        return resp.json()  # type: ignore[no-any-return]

    @staticmethod
    def _flow_to_dict(flow: Any) -> dict[str, Any]:
        """Minimal projection of an in-process flow into the mitmweb shape."""
        req = getattr(flow, "request", None)
        resp = getattr(flow, "response", None)
        return {
            "id": getattr(flow, "id", ""),
            "type": getattr(flow, "type", "http"),
            "timestamp_start": getattr(flow, "timestamp_start", None),
            "timestamp_end": getattr(flow, "timestamp_end", None),
            "request": {
                "method": getattr(req, "method", None),
                "scheme": getattr(req, "scheme", None),
                "host": getattr(req, "host", ""),
                "port": getattr(req, "port", 80),
                "path": getattr(req, "path", None),
                "timestamp_start": getattr(req, "timestamp_start", None),
            }
            if req is not None
            else {},
            "response": {
                "status_code": getattr(resp, "status_code", None),
                "timestamp_end": getattr(resp, "timestamp_end", None),
            }
            if resp is not None
            else {},
        }

    async def get_flow_detail(
        self,
        flow_id: str,
        *,
        parts: list[str] | None = None,
        content_view: str | None = None,
        redact: bool = True,
    ) -> dict[str, Any]:
        """Fetch structured detail of a single flow from mitmweb."""
        parts_to_fetch = parts or ["request", "response"]
        result: dict[str, Any] = {"flow_id": flow_id}

        # Query main flow metadata
        try:
            resp = await self._client.get("/flows")
        except httpx.TimeoutException as exc:
            raise TimeoutError_(f"timeout contacting mitmweb: {exc}") from exc
        except httpx.RequestError as exc:
            raise UpstreamUnreachableError(f"unable to reach mitmweb: {exc}") from exc

        if resp.status_code != 200:
            raise UpstreamUnreachableError(f"mitmweb /flows returned {resp.status_code}")

        all_flows = resp.json()
        target_flow = next((f for f in all_flows if f.get("id") == flow_id), None)
        if not target_flow:
            raise SessionNotRunningError(f"flow {flow_id!r} not found in session")

        # Process parts
        view_name = content_view or "auto"
        for part in parts_to_fetch:
            if part in ("request", "response"):
                part_data = target_flow.get(part)
                if not part_data:
                    continue

                part_copy = dict(part_data)
                # Redact headers if requested
                if redact and "headers" in part_copy:
                    part_copy["headers"] = redact_headers(part_copy["headers"])

                # Try fetching prettified content view
                try:
                    content_resp = await self._client.get(
                        f"/flows/{flow_id}/{part}/content/{view_name}"
                    )
                    if content_resp.status_code == 200:
                        content_json = content_resp.json()
                        text = content_json.get("text", "")
                        if redact:
                            text = redact_text(text)
                        part_copy["content_view"] = {
                            "text": text,
                            "view_name": content_json.get("view_name"),
                            "description": content_json.get("description"),
                        }
                except Exception:
                    pass

                result[part] = part_copy

            elif part == "messages":
                # WebSocket or TCP/UDP messages
                try:
                    msg_resp = await self._client.get(
                        f"/flows/{flow_id}/messages/content/{view_name}"
                    )
                    if msg_resp.status_code == 200:
                        messages = msg_resp.json()
                        if redact:
                            for m in messages:
                                if "text" in m:
                                    m["text"] = redact_text(m["text"])
                        result["messages"] = messages
                except Exception:
                    pass

        return result

    async def execute_command(self, command: str, arguments: list[str]) -> dict[str, Any]:
        """Invoke a mitmproxy command via mitmweb's /commands endpoint."""
        await self._ensure_csrf_token()
        try:
            resp = await self._client.post(
                f"/commands/{command}",
                json={"arguments": arguments},
            )
        except httpx.TimeoutException as exc:
            raise TimeoutError_(f"timeout contacting mitmweb: {exc}") from exc
        except httpx.RequestError as exc:
            raise UpstreamUnreachableError(f"unable to reach mitmweb: {exc}") from exc

        if resp.status_code != 200:
            raise UpstreamUnreachableError(
                f"mitmweb /commands/{command} returned status {resp.status_code}"
            )

        return resp.json()  # type: ignore[no-any-return]

    async def get_options(self, keys: list[str] | None = None) -> dict[str, Any]:
        """Return the option metadata from ``GET /options``.

        The payload is ``{name: {"value": ..., "default": ..., ...}}``; callers
        read ``["value"]`` for the current setting. ``keys`` is applied
        client-side (the endpoint has no field selector).
        """
        try:
            resp = await self._client.get("/options")
        except httpx.TimeoutException as exc:
            raise TimeoutError_(f"timeout contacting mitmweb: {exc}") from exc
        except httpx.RequestError as exc:
            raise UpstreamUnreachableError(f"unable to reach mitmweb: {exc}") from exc

        if resp.status_code == 403:
            raise UpstreamUnreachableError("mitmweb authentication failed (403 Forbidden)")
        if resp.status_code != 200:
            raise UpstreamUnreachableError(
                f"mitmweb /options returned unexpected status {resp.status_code}"
            )

        payload: dict[str, Any] = resp.json()
        if keys is None:
            return payload
        return {key: payload[key] for key in keys if key in payload}

    async def put_options(self, **update: Any) -> None:
        """Apply an option update via ``PUT /options``.

        mitmproxy replaces a ``Sequence[str]`` option wholesale — it does not
        append — so every mutation is read-modify-write: read with
        :meth:`get_options`, submit the whole new list here.
        """
        await self._ensure_csrf_token()
        try:
            resp = await self._client.put("/options", json=update)
        except httpx.TimeoutException as exc:
            raise TimeoutError_(f"timeout contacting mitmweb: {exc}") from exc
        except httpx.RequestError as exc:
            raise UpstreamUnreachableError(f"unable to reach mitmweb: {exc}") from exc

        if resp.status_code == 400:
            raise InvalidInputError(f"mitmweb rejected the option update: {resp.text}")
        if resp.status_code == 403:
            raise UpstreamUnreachableError("mitmweb authentication failed (403 Forbidden)")
        if resp.status_code != 200:
            raise UpstreamUnreachableError(
                f"mitmweb PUT /options returned unexpected status {resp.status_code}"
            )


__all__ = ["MitmwebClient"]

"""WebSocket bootstrap for mitmweb's CSRF token (Fase 4).

mitmweb registers its Tornado app with ``xsrf_cookies=True``, so every mutating
request (``PUT``/``POST``) is rejected with ``403`` unless it carries an
``X-XSRFToken`` header matching the signed ``_mitmproxy_xsrf`` cookie.

That cookie is **not** returned by any REST GET. Tornado only materialises it
when ``self.xsrf_token`` is touched, which mitmweb does in the WebSocket
``/updates`` handler (``WebSocketEventBroadcaster.prepare``). The bootstrap is
therefore: authenticate over REST (obtains the ``mitmproxy-auth-*`` cookie),
perform the HTTP/1.1 WebSocket upgrade against ``/updates``, and read the
``Set-Cookie`` from the ``101`` response.

The handshake is done with a plain asyncio socket rather than a WebSocket
client: we only need the response headers, and the project does not depend on a
WebSocket library.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import re

XSrfToken = str

_COOKIE_RE = re.compile(r"Set-Cookie:\s*_mitmproxy_xsrf=([^;\r\n]+)", re.IGNORECASE)
_HEADER_TERMINATOR = b"\r\n\r\n"
_MAX_HEADER_BYTES = 64 * 1024


async def fetch_xsrf_token(
    host: str,
    port: int,
    *,
    cookie_header: str,
    authorization: str | None,
    timeout: float = 10.0,
) -> XSrfToken | None:
    """Return the ``_mitmproxy_xsrf`` value set by ``GET /updates`` (WS upgrade).

    Returns ``None`` when the server does not require CSRF (no ``Set-Cookie``),
    which lets the caller fall through to a plain mutating request.
    """
    key = base64.b64encode(os.urandom(16)).decode()
    request_lines = [
        "GET /updates HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if authorization:
        request_lines.append(f"Authorization: {authorization}")
    if cookie_header:
        request_lines.append(f"Cookie: {cookie_header}")
    handshake = ("\r\n".join(request_lines) + "\r\n\r\n").encode()

    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    try:
        writer.write(handshake)
        await writer.drain()
        raw = await asyncio.wait_for(_read_headers(reader), timeout=timeout)
    finally:
        writer.close()
        # Closing must never mask the result already read.
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    match = _COOKIE_RE.search(raw.decode("latin-1", errors="replace"))
    return match.group(1) if match else None


async def _read_headers(reader: asyncio.StreamReader) -> bytes:
    """Read up to and including the HTTP header terminator."""
    buffer = b""
    while _HEADER_TERMINATOR not in buffer:
        chunk = await reader.read(4096)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > _MAX_HEADER_BYTES:
            break
    return buffer


__all__ = ["XSrfToken", "fetch_xsrf_token"]

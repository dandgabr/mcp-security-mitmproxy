"""FastMCP lifespan: deterministic init and teardown (Fase 2, D3, I2).

The async context manager yields a :class:`LifespanContext` carrying the
:class:`Settings` and the shared :class:`SessionRegistry`. Teardown runs in
``finally`` and always calls ``registry.shutdown_all``, so no orphan process,
zombie or bound port survives the server — even when the body raises.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastmcp import FastMCP

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.session import SessionRegistry


@dataclass(slots=True)
class LifespanContext:
    """Object yielded to tools and resources for the server's lifetime."""

    settings: Settings
    registry: SessionRegistry


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[LifespanContext]:
    """Initialize the session registry and guarantee its teardown.

    Invariante I2: ``shutdown_all`` is idempotent and runs in ``finally``. A
    failure during shutdown is swallowed at this boundary so it can never mask
    the original exception bubbling out of the server body.
    """
    settings = Settings.from_env()
    registry = SessionRegistry(settings)
    try:
        yield LifespanContext(settings=settings, registry=registry)
    finally:
        with contextlib.suppress(Exception):
            await registry.shutdown_all(timeout=settings.shutdown_timeout_seconds)


__all__ = ["LifespanContext", "app_lifespan"]

"""Core layer: process lifecycle, session registry, path safety, mode grammar.

Fase 2 adds the stateful modules ``process`` (subprocess runner),
``session`` (registry, port leases, temp isolation) and ``lifecycle``
(FastMCP lifespan + deterministic teardown).
"""

from __future__ import annotations

from mcp_security_mitmproxy.core import errors, lifecycle, modes, paths, process, session

__all__ = ["errors", "lifecycle", "modes", "paths", "process", "session"]

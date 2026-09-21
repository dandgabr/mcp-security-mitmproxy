"""FastMCP application: instantiation, lifespan and registration entrypoint.

Fase 2 wires the shared :class:`SessionRegistry` through ``app_lifespan``.
The server remains constructible and inspectable without starting any proxy,
so the MCP schema is still validated statically (DoD Fase 1).

Boundary note (architecture §2): this is the outermost layer. It may import
``tools``/``resources``; nothing inner may import it.
"""

from __future__ import annotations

from fastmcp import FastMCP

from mcp_security_mitmproxy import __version__
from mcp_security_mitmproxy.core.lifecycle import app_lifespan
from mcp_security_mitmproxy.tools import register_all_tools

SERVER_NAME = "mcp-security-mitmproxy"


def create_server() -> FastMCP:
    """Build the FastMCP instance. Pure construction — no I/O, no subprocess."""
    server = FastMCP(
        name=SERVER_NAME,
        version=__version__,
        instructions=(
            "Exposes mitmproxy's mitmdump/mitmweb/mitmproxy capabilities to AI agents. "
            "Start sessions with explicit modes, read traffic through the mitmweb REST "
            "bridge, and always stop sessions to release ports."
        ),
        lifespan=app_lifespan,
    )
    register_all_tools(server)
    return server


mcp: FastMCP = create_server()


def run() -> None:
    """Run the server over stdio (default MCP transport)."""
    mcp.run()


__all__ = ["SERVER_NAME", "app_lifespan", "create_server", "mcp", "run"]

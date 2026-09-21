"""Export tool registration functions."""

from __future__ import annotations

from fastmcp import FastMCP

from mcp_security_mitmproxy.tools.core_tools import register_core_tools
from mcp_security_mitmproxy.tools.mitmdump import register_mitmdump_tools
from mcp_security_mitmproxy.tools.mitmweb import register_mitmweb_tools
from mcp_security_mitmproxy.tools.rules import register_rules_tools


def register_all_tools(mcp: FastMCP) -> None:
    """Register all MCP tools (mitmdump, mitmweb, core, rules)."""
    register_mitmdump_tools(mcp)
    register_mitmweb_tools(mcp)
    register_core_tools(mcp)
    register_rules_tools(mcp)


__all__ = [
    "register_all_tools",
    "register_core_tools",
    "register_mitmdump_tools",
    "register_mitmweb_tools",
    "register_rules_tools",
]

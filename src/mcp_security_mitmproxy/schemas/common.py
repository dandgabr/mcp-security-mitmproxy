"""Shared enums and the ``ToolResult`` envelope (architecture §3.1)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel

# mitmproxy options the server reserves for itself. A user-supplied ``--set``
# for any of these is refused, because each one either breaks session isolation
# or routes a file/network side effect around the validated Fase 4 tools.
#
#   confdir          — shadows the per-session config (SEC-5/Item F).
#   scripts          — loads addons from arbitrary paths: Python RCE, bypasses
#                      the R3 script allowlist.
#   map_local        — reads an arbitrary host file and serves it (LFI). Must go
#                      through mitm_set_map_local -> ensure_allowed(allowed_mock_roots).
#   map_remote       — contract coherence: routing rules must be compiled by
#                      rules/engine.py, never assembled from raw user strings.
#   modify_headers   — '@path' replacement discloses a host file (R3).
#   modify_body      — '@path' replacement discloses a host file (R3).
#   save_stream_file — strftime-expanded path written to disk: arbitrary write.
#   hardump          — writes a HAR to an arbitrary path: arbitrary write.
#
# Two entry points, one emitter: agent input via ``set_options`` is always
# rejected; only rules/engine.py emits these, after canonical path validation.
RESERVED_SET_OPTIONS: frozenset[str] = frozenset(
    {
        "confdir",
        "scripts",
        "map_local",
        "map_remote",
        "modify_headers",
        "modify_body",
        "save_stream_file",
        "hardump",
    }
)


class ProxyMode(StrEnum):
    REGULAR = "regular"
    LOCAL = "local"
    WIREGUARD = "wireguard"
    REVERSE = "reverse"
    TRANSPARENT = "transparent"
    TUN = "tun"
    UPSTREAM = "upstream"
    SOCKS5 = "socks5"
    DNS = "dns"


class TransportProtocol(StrEnum):
    """Scheme override for ``reverse:`` modes."""

    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    HTTP3 = "http3"
    QUIC = "quic"
    TLS = "tls"
    DTLS = "dtls"


class FlowDetailLevel(StrEnum):
    """mitmdump ``--flow-detail`` level.

    The MCP contract keeps readable names, but mitmproxy's ``flow_detail``
    option is an **int** 0-4 (``addons/dumper.py``). ``--flow-detail short`` is
    rejected by argparse; :attr:`level` maps each name to the integer the CLI
    and the ``flow_detail`` option expect.
    """

    NONE = "none"
    URI = "uri"
    SHORT = "short"
    VERBOSE = "verbose"
    FULL = "full"

    @property
    def level(self) -> int:
        """The integer mitmproxy accepts for this level (0-4)."""
        return _FLOW_DETAIL_LEVELS[self]

    def __str__(self) -> str:
        return self.value


_FLOW_DETAIL_LEVELS: dict[FlowDetailLevel, int] = {
    FlowDetailLevel.NONE: 0,
    FlowDetailLevel.URI: 1,
    FlowDetailLevel.SHORT: 2,
    FlowDetailLevel.VERBOSE: 3,
    FlowDetailLevel.FULL: 4,
}


class ExportFormat(StrEnum):
    CURL = "curl"
    HTTPIE = "httpie"
    RAW = "raw"
    RAW_REQUEST = "raw_request"
    RAW_RESPONSE = "raw_response"


class SessionStatus(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class ErrorCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    SESSION_NOT_RUNNING = "SESSION_NOT_RUNNING"
    PORT_IN_USE = "PORT_IN_USE"
    PROCESS_SPAWN_FAILED = "PROCESS_SPAWN_FAILED"
    PATH_NOT_ALLOWED = "PATH_NOT_ALLOWED"
    COMMAND_NOT_ALLOWED = "COMMAND_NOT_ALLOWED"
    UPSTREAM_UNREACHABLE = "UPSTREAM_UNREACHABLE"
    TIMEOUT = "TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ToolError(BaseModel):
    code: ErrorCode
    message: str
    detail: dict[str, Any] | None = None


class ToolResult(BaseModel):
    """Single return envelope. Every tool returns this (invariant I1)."""

    ok: bool
    error: ToolError | None = None

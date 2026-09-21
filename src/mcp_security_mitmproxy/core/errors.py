"""Domain exceptions and their mapping to the MCP ``ToolResult`` envelope.

Invariante I1 (architecture §3.1): no tool raises to the MCP client. Every
handler funnels failures through :func:`to_tool_result`, which turns a domain
error into ``ToolResult(ok=False, error=...)`` and any unexpected exception into
an ``INTERNAL_ERROR`` with a sanitized message.
"""

from __future__ import annotations

from mcp_security_mitmproxy.schemas.common import ErrorCode, ToolError, ToolResult


class MitmproxyError(Exception):
    """Base class for all expected, domain-level failures."""

    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(self, message: str, *, detail: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_error(self) -> ToolError:
        return ToolError(code=self.code, message=self.message, detail=self.detail)


class InvalidInputError(MitmproxyError):
    code = ErrorCode.INVALID_INPUT


class SessionNotFoundError(MitmproxyError):
    code = ErrorCode.SESSION_NOT_FOUND


class SessionNotRunningError(MitmproxyError):
    code = ErrorCode.SESSION_NOT_RUNNING


class PortInUseError(MitmproxyError):
    code = ErrorCode.PORT_IN_USE


class ProcessSpawnFailedError(MitmproxyError):
    code = ErrorCode.PROCESS_SPAWN_FAILED


class PathNotAllowedError(MitmproxyError):
    code = ErrorCode.PATH_NOT_ALLOWED


class CommandNotAllowedError(MitmproxyError):
    code = ErrorCode.COMMAND_NOT_ALLOWED


class UpstreamUnreachableError(MitmproxyError):
    code = ErrorCode.UPSTREAM_UNREACHABLE


class TimeoutError_(MitmproxyError):  # noqa: N801 - avoid shadowing builtins.TimeoutError
    code = ErrorCode.TIMEOUT


def to_tool_result(exc: BaseException) -> ToolResult:
    """Convert any exception into a non-raising :class:`ToolResult`.

    Unexpected exceptions collapse to ``INTERNAL_ERROR`` and expose only the
    exception class name — never its args, which may carry secrets (R4).
    """
    if isinstance(exc, MitmproxyError):
        return ToolResult(ok=False, error=exc.to_error())
    return ToolResult(
        ok=False,
        error=ToolError(
            code=ErrorCode.INTERNAL_ERROR,
            message=f"unexpected {type(exc).__name__}",
        ),
    )


__all__ = [
    "CommandNotAllowedError",
    "InvalidInputError",
    "MitmproxyError",
    "PathNotAllowedError",
    "PortInUseError",
    "ProcessSpawnFailedError",
    "SessionNotFoundError",
    "SessionNotRunningError",
    "TimeoutError_",
    "UpstreamUnreachableError",
    "to_tool_result",
]

"""Unit tests for domain errors and the invariant I1 no-raise mapping."""

from __future__ import annotations

import pytest

from mcp_security_mitmproxy.core import errors
from mcp_security_mitmproxy.schemas import ErrorCode


@pytest.mark.parametrize(
    ("exc_class", "expected_code"),
    [
        (errors.InvalidInputError, ErrorCode.INVALID_INPUT),
        (errors.SessionNotFoundError, ErrorCode.SESSION_NOT_FOUND),
        (errors.SessionNotRunningError, ErrorCode.SESSION_NOT_RUNNING),
        (errors.PortInUseError, ErrorCode.PORT_IN_USE),
        (errors.ProcessSpawnFailedError, ErrorCode.PROCESS_SPAWN_FAILED),
        (errors.PathNotAllowedError, ErrorCode.PATH_NOT_ALLOWED),
        (errors.CommandNotAllowedError, ErrorCode.COMMAND_NOT_ALLOWED),
        (errors.UpstreamUnreachableError, ErrorCode.UPSTREAM_UNREACHABLE),
        (errors.TimeoutError_, ErrorCode.TIMEOUT),
    ],
)
def test_domain_error_maps_to_expected_code(exc_class: type, expected_code: ErrorCode) -> None:
    error = exc_class("boom")
    assert error.to_error().code is expected_code


def test_base_error_defaults_to_internal() -> None:
    assert errors.MitmproxyError("x").code is ErrorCode.INTERNAL_ERROR


def test_to_tool_result_wraps_domain_error_without_raising() -> None:
    result = errors.to_tool_result(errors.SessionNotFoundError("no such session"))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code is ErrorCode.SESSION_NOT_FOUND
    assert result.error.message == "no such session"


def test_to_tool_result_carries_detail() -> None:
    result = errors.to_tool_result(errors.PathNotAllowedError("bad", detail={"path": "/etc"}))
    assert result.error is not None
    assert result.error.detail == {"path": "/etc"}


def test_unexpected_exception_becomes_internal_without_leaking_args() -> None:
    secret = "Authorization: Bearer super-secret-token"
    result = errors.to_tool_result(RuntimeError(secret))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code is ErrorCode.INTERNAL_ERROR
    assert secret not in result.error.message
    assert "RuntimeError" in result.error.message

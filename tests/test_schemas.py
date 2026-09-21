"""Static contract validation for the MCP schemas (no proxy required).

Covers the DoD clause "schema MCP validado estaticamente": JSON Schema
generation from the Pydantic models, enum membership, the ``ToolResult``
envelope, and the ``ProxyModeSpec`` cross-field validators.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from mcp_security_mitmproxy.schemas import (
    ErrorCode,
    ExportFormat,
    FlowDetailLevel,
    MitmdumpStartInput,
    MitmwebGetFlowsInput,
    MitmwebStartInput,
    ProxyMode,
    ProxyModeSpec,
    SessionState,
    SessionStatus,
    ToolError,
    ToolResult,
)


def test_proxy_mode_enum_members() -> None:
    assert {m.value for m in ProxyMode} == {
        "regular",
        "local",
        "wireguard",
        "reverse",
        "transparent",
        "tun",
        "upstream",
        "socks5",
        "dns",
    }


def test_export_format_matches_mitmproxy_v12() -> None:
    assert {f.value for f in ExportFormat} == {
        "curl",
        "httpie",
        "raw",
        "raw_request",
        "raw_response",
    }
    assert "har" not in {f.value for f in ExportFormat}


def test_flow_detail_and_session_status_members() -> None:
    assert {f.value for f in FlowDetailLevel} == {"none", "uri", "short", "verbose", "full"}
    # mitmproxy's flow_detail option is an int 0-4; every level maps to one.
    assert {f.level for f in FlowDetailLevel} == {0, 1, 2, 3, 4}
    assert FlowDetailLevel.SHORT.level == 2
    assert {s.value for s in SessionStatus} == {
        "starting",
        "running",
        "stopping",
        "stopped",
        "failed",
    }


def test_error_code_members() -> None:
    assert {e.value for e in ErrorCode} == {
        "INVALID_INPUT",
        "SESSION_NOT_FOUND",
        "SESSION_NOT_RUNNING",
        "PORT_IN_USE",
        "PROCESS_SPAWN_FAILED",
        "PATH_NOT_ALLOWED",
        "COMMAND_NOT_ALLOWED",
        "UPSTREAM_UNREACHABLE",
        "TIMEOUT",
        "INTERNAL_ERROR",
    }


def test_tool_result_envelope_success() -> None:
    result = ToolResult(ok=True)
    assert result.ok is True
    assert result.error is None


def test_tool_result_envelope_error() -> None:
    result = ToolResult(
        ok=False,
        error=ToolError(code=ErrorCode.SESSION_NOT_FOUND, message="missing"),
    )
    assert result.ok is False
    assert result.error is not None
    assert result.error.code is ErrorCode.SESSION_NOT_FOUND
    assert result.error.detail is None


def test_reverse_mode_requires_upstream() -> None:
    with pytest.raises(ValidationError):
        ProxyModeSpec(mode=ProxyMode.REVERSE)


def test_upstream_url_rejected_outside_reverse_upstream() -> None:
    with pytest.raises(ValidationError):
        ProxyModeSpec(mode=ProxyMode.REGULAR, upstream_url="https://example.com")


def test_local_mode_defaults_intercept_to_empty() -> None:
    spec = ProxyModeSpec(mode=ProxyMode.LOCAL)
    assert spec.intercept == []


def test_listen_port_bounds() -> None:
    with pytest.raises(ValidationError):
        ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=0)
    with pytest.raises(ValidationError):
        ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=65536)
    assert ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=8888).listen_port == 8888


def test_mitmdump_start_requires_at_least_one_mode() -> None:
    with pytest.raises(ValidationError):
        MitmdumpStartInput(mode=[])
    parsed = MitmdumpStartInput(mode=[ProxyModeSpec(mode=ProxyMode.REGULAR)])
    assert parsed.flow_detail is FlowDetailLevel.SHORT
    assert parsed.listen_host == "127.0.0.1"


def test_mitmdump_start_rejects_reserved_confdir_option() -> None:
    with pytest.raises(ValidationError):
        MitmdumpStartInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR)],
            set_options={"confdir": "/etc/evil"},
        )


def test_mitmdump_start_rejects_reserved_scripts_option() -> None:
    with pytest.raises(ValidationError):
        MitmdumpStartInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR)],
            set_options={"scripts": "/tmp/evil.py"},
        )


def test_mitmdump_start_allows_non_reserved_options() -> None:
    parsed = MitmdumpStartInput(
        mode=[ProxyModeSpec(mode=ProxyMode.REGULAR)],
        set_options={"termlog_verbosity": "warn"},
    )
    assert parsed.set_options == {"termlog_verbosity": "warn"}


def test_mitmweb_start_web_host_defaults_to_loopback() -> None:
    parsed = MitmwebStartInput(mode=[ProxyModeSpec(mode=ProxyMode.REGULAR)])
    assert parsed.web_host == "127.0.0.1"
    assert parsed.web_port == 8081
    assert parsed.web_open_browser is False


def test_get_flows_pagination_bounds() -> None:
    with pytest.raises(ValidationError):
        MitmwebGetFlowsInput(session_id="s", limit=0)
    with pytest.raises(ValidationError):
        MitmwebGetFlowsInput(session_id="s", limit=501)
    parsed = MitmwebGetFlowsInput(session_id="s")
    assert parsed.limit == 50
    assert parsed.offset == 0
    assert parsed.include_body is False


def test_json_schema_generation_is_serializable() -> None:
    schema = MitmdumpStartInput.model_json_schema()
    encoded = json.dumps(schema)
    assert '"mode"' in encoded
    assert "$defs" in schema or "definitions" in schema


def test_session_state_defaults() -> None:
    state = SessionState(session_id="s-1", executable="mitmdump")
    assert state.status is SessionStatus.STARTING
    assert state.listen_host == "127.0.0.1"
    assert state.pid is None

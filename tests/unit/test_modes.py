"""Unit tests for the ``--mode`` argv builders (no subprocess)."""

from __future__ import annotations

import pytest

from mcp_security_mitmproxy.core.errors import InvalidInputError
from mcp_security_mitmproxy.core.modes import (
    build_listen_port_args,
    build_mode_arg,
    build_mode_args,
    ensure_mode_privileges,
    requires_privilege,
)
from mcp_security_mitmproxy.schemas import ProxyMode, ProxyModeSpec, TransportProtocol


def test_regular_mode() -> None:
    assert build_mode_arg(ProxyModeSpec(mode=ProxyMode.REGULAR)) == "regular"


def test_reverse_mode_includes_upstream() -> None:
    spec = ProxyModeSpec(mode=ProxyMode.REVERSE, upstream_url="https://example.com")
    assert build_mode_arg(spec) == "reverse:https://example.com"


def test_reverse_mode_with_protocol_override() -> None:
    spec = ProxyModeSpec(
        mode=ProxyMode.REVERSE,
        upstream_url="example.com",
        protocol=TransportProtocol.TCP,
    )
    assert build_mode_arg(spec) == "reverse:tcp:example.com"


def test_upstream_mode() -> None:
    spec = ProxyModeSpec(mode=ProxyMode.UPSTREAM, upstream_url="http://proxy:8081")
    assert build_mode_arg(spec) == "upstream:http://proxy:8081"


def test_local_mode_empty_intercept_renders_bare_local() -> None:
    assert build_mode_arg(ProxyModeSpec(mode=ProxyMode.LOCAL)) == "local"


def test_local_mode_with_intercept_patterns() -> None:
    spec = ProxyModeSpec(mode=ProxyMode.LOCAL, intercept=["~u example.com", "!chrome"])
    assert build_mode_arg(spec) == "local:~u example.com|!chrome"


def test_wireguard_requires_key_path() -> None:
    with pytest.raises(InvalidInputError):
        build_mode_arg(ProxyModeSpec(mode=ProxyMode.WIREGUARD))


def test_tun_requires_interface() -> None:
    with pytest.raises(InvalidInputError):
        build_mode_arg(ProxyModeSpec(mode=ProxyMode.TUN))


def test_tun_with_interface() -> None:
    spec = ProxyModeSpec(mode=ProxyMode.TUN, interface_name="tun0")
    assert build_mode_arg(spec) == "tun:tun0"


def test_build_mode_args_flattens_multiple_specs() -> None:
    args = build_mode_args(
        [
            ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=8888),
            ProxyModeSpec(mode=ProxyMode.REVERSE, upstream_url="https://a.test"),
        ]
    )
    assert args == ["--mode", "regular", "--mode", "reverse:https://a.test"]


def test_build_mode_args_rejects_empty() -> None:
    with pytest.raises(InvalidInputError):
        build_mode_args([])


def test_listen_port_args_first_declared_wins() -> None:
    args = build_listen_port_args(
        [
            ProxyModeSpec(mode=ProxyMode.REGULAR),
            ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=9000),
        ]
    )
    assert args == ["--listen-port", "9000"]


def test_privileged_modes_detected() -> None:
    assert requires_privilege(ProxyModeSpec(mode=ProxyMode.LOCAL))
    assert requires_privilege(ProxyModeSpec(mode=ProxyMode.TUN, interface_name="tun0"))
    assert not requires_privilege(ProxyModeSpec(mode=ProxyMode.REGULAR))


def test_ensure_mode_privileges_rejects_local_and_tun() -> None:
    """R5: local/tun are refused explicitly, never escalated implicitly."""
    for spec in (
        ProxyModeSpec(mode=ProxyMode.LOCAL),
        ProxyModeSpec(mode=ProxyMode.TUN, interface_name="tun0"),
    ):
        with pytest.raises(InvalidInputError) as excinfo:
            ensure_mode_privileges([spec])
        assert excinfo.value.code.value == "INVALID_INPUT"
        assert spec.mode.value in excinfo.value.message


def test_ensure_mode_privileges_allows_unprivileged_modes() -> None:
    ensure_mode_privileges(
        [
            ProxyModeSpec(mode=ProxyMode.REGULAR),
            ProxyModeSpec(mode=ProxyMode.REVERSE, upstream_url="https://x.test"),
        ]
    )

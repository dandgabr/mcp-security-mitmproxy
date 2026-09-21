"""Build ``--mode`` argv fragments from validated :class:`ProxyModeSpec` values.

Pure functions only — no subprocess, no I/O, no ``mitmproxy`` import. This
keeps the mode grammar unit-testable and lets the process layer stay a thin
spawner.

R5: ``local`` and ``tun`` require elevated privileges on Linux. The builders do
not silently escalate; they emit the canonical argv and the process layer is
responsible for failing explicitly when the capability is absent.
"""

from __future__ import annotations

from mcp_security_mitmproxy.core.errors import InvalidInputError
from mcp_security_mitmproxy.schemas.common import ProxyMode, TransportProtocol
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec

_PRIVILEGED_MODES = frozenset({ProxyMode.LOCAL, ProxyMode.TUN})


def requires_privilege(spec: ProxyModeSpec) -> bool:
    """True when the mode needs elevated capabilities on Linux (R5)."""
    return spec.mode in _PRIVILEGED_MODES


def ensure_mode_privileges(specs: list[ProxyModeSpec]) -> None:
    """Refuse ``local``/``tun`` explicitly instead of failing deep in spawn (R5).

    These modes need elevated capabilities on Linux (``CAP_NET_ADMIN``/eBPF for
    ``local``, a TUN interface for ``tun``). The server never escalates
    privileges implicitly, so a request that needs them is rejected at the tool
    boundary with a precise error rather than producing an opaque spawn failure.
    """
    privileged = [spec.mode.value for spec in specs if requires_privilege(spec)]
    if privileged:
        raise InvalidInputError(
            "modes require elevated privileges and are not granted implicitly: "
            + ", ".join(sorted(set(privileged)))
            + " (run the proxy in an environment with the needed capabilities)",
            detail={"privileged_modes": sorted(set(privileged))},
        )


def build_mode_arg(spec: ProxyModeSpec) -> str:
    """Render a single ``ProxyModeSpec`` as one mitmproxy ``--mode`` value."""
    mode = spec.mode

    if mode in (ProxyMode.REVERSE, ProxyMode.UPSTREAM):
        if not spec.upstream_url:
            raise InvalidInputError(f"mode={mode.value} requires upstream_url")
        prefix = mode.value
        if spec.protocol is not None:
            if spec.protocol is TransportProtocol.HTTP3:
                # mitmproxy spells the HTTP/3 protocol token "http3".
                prefix = f"{mode.value}:http3"
            else:
                prefix = f"{mode.value}:{spec.protocol.value}"
        return f"{prefix}:{spec.upstream_url}"

    if mode is ProxyMode.LOCAL:
        intercept = spec.intercept or []
        if not intercept:
            return "local"
        return "local:" + "|".join(intercept)

    if mode is ProxyMode.WIREGUARD:
        if not spec.wireguard_key_path:
            raise InvalidInputError("mode=wireguard requires wireguard_key_path")
        return f"wireguard:{spec.wireguard_key_path}"

    if mode is ProxyMode.TUN:
        if not spec.interface_name:
            raise InvalidInputError("mode=tun requires interface_name")
        return f"tun:{spec.interface_name}"

    return mode.value


def build_mode_args(specs: list[ProxyModeSpec]) -> list[str]:
    """Expand specs into a flat argv fragment: ``--mode A --mode B``."""
    if not specs:
        raise InvalidInputError("at least one mode is required")
    args: list[str] = []
    for spec in specs:
        args.extend(["--mode", build_mode_arg(spec)])
    return args


def build_listen_host_arg(host: str) -> list[str]:
    return ["--listen-host", host]


def build_listen_port_args(specs: list[ProxyModeSpec]) -> list[str]:
    """Emit ``--listen-port`` for the first spec that declares one."""
    for spec in specs:
        if spec.listen_port is not None:
            return ["--listen-port", str(spec.listen_port)]
    return []


__all__ = [
    "build_listen_host_arg",
    "build_listen_port_args",
    "build_mode_arg",
    "build_mode_args",
    "ensure_mode_privileges",
    "requires_privilege",
]

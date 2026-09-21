"""Process/session contracts (architecture §3.2 and §3.3.2)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from mcp_security_mitmproxy.schemas.common import (
    FlowDetailLevel,
    ProxyMode,
    SessionStatus,
    ToolResult,
    TransportProtocol,
)


class ProxyModeSpec(BaseModel):
    """One ``--mode`` argument for a mitmproxy executable."""

    mode: ProxyMode
    upstream_url: str | None = Field(
        default=None,
        description=(
            "Required for reverse:/upstream:. E.g. https://example.com or http://proxy:8081"
        ),
    )
    protocol: TransportProtocol | None = Field(
        default=None,
        description="Scheme override for reverse: (tcp, udp, dns, http3, quic, tls, dtls).",
    )
    listen_port: int | None = Field(default=None, ge=1, le=65535)
    intercept: list[str] | None = Field(
        default=None,
        description="local:[:process|!process|pid]. Empty list = everything.",
    )
    wireguard_key_path: str | None = None
    interface_name: str | None = Field(default=None, description="tun:<iface>")

    @model_validator(mode="after")
    def _validate(self) -> ProxyModeSpec:
        if self.mode in (ProxyMode.REVERSE, ProxyMode.UPSTREAM) and not self.upstream_url:
            raise ValueError(f"mode={self.mode.value} requires upstream_url")
        if self.mode not in (ProxyMode.REVERSE, ProxyMode.UPSTREAM) and self.upstream_url:
            raise ValueError("upstream_url is only valid for reverse/upstream")
        if self.mode is ProxyMode.LOCAL and self.intercept is None:
            self.intercept = []
        return self


class SessionState(BaseModel):
    """Observable state of a managed mitmproxy subprocess."""

    session_id: str
    executable: str = Field(description="mitmdump | mitmweb | mitmproxy")
    status: SessionStatus = SessionStatus.STARTING
    modes: list[ProxyModeSpec] = Field(default_factory=list)
    listen_host: str = "127.0.0.1"
    listen_ports: list[int] = Field(default_factory=list)
    web_host: str | None = None
    web_port: int | None = None
    pid: int | None = None
    save_path: str | None = None
    created_at: datetime | None = None
    exit_code: int | None = None


class StopInput(BaseModel):
    session_id: str = Field(description="UUID returned by *_start.")
    timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    force: bool = Field(default=False, description="SIGKILL after timeout when True.")


class SessionListOutput(ToolResult):
    sessions: list[SessionState] = Field(default_factory=list)


class SessionStatusInput(BaseModel):
    session_id: str


class SessionStatusOutput(ToolResult):
    session: SessionState | None = None


__all__ = [
    "FlowDetailLevel",
    "ProxyModeSpec",
    "SessionListOutput",
    "SessionState",
    "SessionStatusInput",
    "SessionStatusOutput",
    "StopInput",
]

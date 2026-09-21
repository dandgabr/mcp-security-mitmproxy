"""mitmweb tool contracts (architecture §3.3.4–§3.3.6)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from mcp_security_mitmproxy.schemas.common import ToolResult
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec, SessionState

DEFAULT_WEB_HOST = "127.0.0.1"
DEFAULT_WEB_PORT = 8081


class MitmwebStartInput(BaseModel):
    mode: list[ProxyModeSpec] = Field(min_length=1)
    listen_host: str = "127.0.0.1"
    web_host: str = Field(
        default=DEFAULT_WEB_HOST,
        description="R2: external bind (0.0.0.0) requires an explicit value and is audited.",
    )
    web_port: int = Field(default=DEFAULT_WEB_PORT, ge=1, le=65535)
    web_open_browser: bool = False
    web_password: str | None = Field(default=None, description="Never echoed in the output.")
    save_path: str | None = None
    scripts: list[str] = Field(default_factory=list)


class MitmwebStartOutput(ToolResult):
    session: SessionState | None = None
    web_url: str | None = None


class MitmwebGetFlowsInput(BaseModel):
    session_id: str
    filter_expression: str | None = Field(
        default=None, description="Evaluated server-side by mitmweb when applicable."
    )
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
    include_body: bool = Field(
        default=False, description="When False, omits bodies (smaller payload)."
    )


class FlowSummary(BaseModel):
    flow_id: str
    type: Literal["http", "tcp", "udp", "dns", "websocket"]
    method: str | None
    scheme: str | None
    host: str
    port: int
    path: str | None
    status_code: int | None
    timestamp_start: float | None
    duration: float | None


class MitmwebGetFlowsOutput(ToolResult):
    flows: list[FlowSummary] = Field(default_factory=list)
    total: int = 0


class MitmwebGetFlowDetailInput(BaseModel):
    session_id: str
    flow_id: str
    parts: list[Literal["request", "response", "messages"]] = Field(
        default_factory=lambda: ["request", "response"]
    )
    content_view: str | None = Field(
        default=None, description="Viewer (json, grpc, protobuf...). None = raw."
    )
    redact: bool = Field(default=True, description="R4: applies secret redaction before returning.")


class MitmwebGetFlowDetailOutput(ToolResult):
    detail: dict[str, Any] | None = None


__all__ = [
    "FlowSummary",
    "MitmwebGetFlowDetailInput",
    "MitmwebGetFlowDetailOutput",
    "MitmwebGetFlowsInput",
    "MitmwebGetFlowsOutput",
    "MitmwebStartInput",
    "MitmwebStartOutput",
]

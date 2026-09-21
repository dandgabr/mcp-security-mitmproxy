"""Core command/export/filter contracts (architecture §3.3.7–§3.3.9)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from mcp_security_mitmproxy.schemas.common import ExportFormat, ToolResult
from mcp_security_mitmproxy.schemas.mitmweb import FlowSummary


class MitmExecuteCommandInput(BaseModel):
    session_id: str
    command: str = Field(description="Registered command, e.g. 'view.clear', 'flow.kill'.")
    arguments: list[str] = Field(default_factory=list)


class MitmExecuteCommandOutput(ToolResult):
    result: Any | None = None
    stdout: str | None = None


class MitmExportFlowInput(BaseModel):
    flow_id: str
    format: ExportFormat
    session_id: str | None = Field(
        default=None, description="When omitted, flow_path is required for offline export."
    )
    flow_path: str | None = Field(default=None, description=".mitm file (allowlist).")
    preserve_original_ip: bool = False


class MitmExportFlowOutput(ToolResult):
    content: str | None = None
    format: ExportFormat | None = None


class MitmFilterFlowsInput(BaseModel):
    expression: str = Field(
        description="FlowFilter: ~u, ~m, ~c, ~b, ~h, ~d, ~websocket, ~tcp, ~udp."
    )
    session_id: str | None = None
    flow_path: str | None = None
    limit: int = Field(default=100, ge=1, le=1000)


class MitmFilterFlowsOutput(ToolResult):
    matched: list[FlowSummary] = Field(default_factory=list)
    count: int = 0


__all__ = [
    "MitmExecuteCommandInput",
    "MitmExecuteCommandOutput",
    "MitmExportFlowInput",
    "MitmExportFlowOutput",
    "MitmFilterFlowsInput",
    "MitmFilterFlowsOutput",
]

"""mitmdump tool contracts (architecture §3.3.1–§3.3.3)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from mcp_security_mitmproxy.schemas.common import (
    RESERVED_SET_OPTIONS,
    FlowDetailLevel,
    ToolResult,
)
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec, SessionState


def _reject_reserved_options(options: dict[str, Any]) -> dict[str, Any]:
    reserved = sorted(key for key in options if key in RESERVED_SET_OPTIONS)
    if reserved:
        raise ValueError(f"set_options may not override reserved option(s): {', '.join(reserved)}")
    return options


class MitmdumpStartInput(BaseModel):
    mode: list[ProxyModeSpec] = Field(
        min_length=1,
        description="One or more modes. E.g. [{mode: regular, listen_port: 8888}]",
    )
    listen_host: str = "127.0.0.1"
    save_path: str | None = Field(default=None, description="Output .mitm file (allowlist).")
    flow_detail: FlowDetailLevel = FlowDetailLevel.SHORT
    filter_expression: str | None = Field(
        default=None, description="FlowFilter (e.g. '~d example.com & ~m POST')."
    )
    scripts: list[str] = Field(default_factory=list, description="Python addons (allowlist).")
    set_options: dict[str, Any] = Field(
        default_factory=dict,
        description="mitmproxy option overrides (key allowlist).",
    )

    @field_validator("set_options")
    @classmethod
    def _validate_set_options(cls, options: dict[str, Any]) -> dict[str, Any]:
        return _reject_reserved_options(options)


class MitmdumpStartOutput(ToolResult):
    session: SessionState | None = None


class MitmdumpReplayInput(BaseModel):
    mode: list[ProxyModeSpec] = Field(min_length=1)
    client_replay: list[str] = Field(default_factory=list, description="Flags -C (arquivos .mitm).")
    server_replay: list[str] = Field(default_factory=list, description="Flags -S (arquivos .mitm).")
    replay_kill_extra: bool = True
    save_path: str | None = None


__all__ = [
    "MitmdumpReplayInput",
    "MitmdumpStartInput",
    "MitmdumpStartOutput",
]

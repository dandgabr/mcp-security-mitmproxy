"""Tools exposing core mitmproxy commands, offline flow export and filtering (architecture §3.3.7–§3.3.9)."""

from __future__ import annotations

from fastmcp import Context, FastMCP

from mcp_security_mitmproxy.core.errors import (
    CommandNotAllowedError,
    InvalidInputError,
    SessionNotRunningError,
    to_tool_result,
)
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.core.paths import ensure_allowed
from mcp_security_mitmproxy.core.redact import redact_text
from mcp_security_mitmproxy.flows.manager import (
    export_flow_offline,
    filter_flows,
    find_flow_by_id,
    read_flows_from_bytes,
    read_flows_from_dump,
)
from mcp_security_mitmproxy.schemas.common import SessionStatus
from mcp_security_mitmproxy.schemas.core_commands import (
    MitmExecuteCommandInput,
    MitmExecuteCommandOutput,
    MitmExportFlowInput,
    MitmExportFlowOutput,
    MitmFilterFlowsInput,
    MitmFilterFlowsOutput,
)
from mcp_security_mitmproxy.schemas.process import (
    SessionListOutput,
    SessionStatusInput,
    SessionStatusOutput,
)
from mcp_security_mitmproxy.web_client.client import MitmwebClient

# Allowlist of executable commands to prevent arbitrary invocation (R3)
ALLOWED_COMMANDS = frozenset(
    {
        "view.clear",
        "view.properties.set",
        "flow.kill",
        "flow.resume",
        "flow.mark",
        "flow.comment",
        "replay.client",
        "replay.server",
    }
)


def _resolve_context(ctx: Context) -> LifespanContext:
    obj = ctx.lifespan_context
    if not isinstance(obj, LifespanContext):
        raise RuntimeError("lifespan context not initialized")
    return obj


def register_core_tools(mcp: FastMCP) -> None:
    """Register core commands, session management, export and filter tools."""

    @mcp.tool(
        name="session_list",
        description="List all active, stopped and managed mitmproxy sessions.",
    )
    async def session_list(ctx: Context) -> SessionListOutput:
        try:
            lc = _resolve_context(ctx)
            sessions = lc.registry.list()
            return SessionListOutput(ok=True, sessions=sessions)
        except Exception as exc:
            res = to_tool_result(exc)
            return SessionListOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="session_status",
        description="Get the detailed status and runtime parameters of a session by ID.",
    )
    async def session_status(
        params: SessionStatusInput,
        ctx: Context,
    ) -> SessionStatusOutput:
        try:
            lc = _resolve_context(ctx)
            state = lc.registry.get(params.session_id)
            return SessionStatusOutput(ok=True, session=state)
        except Exception as exc:
            res = to_tool_result(exc)
            return SessionStatusOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitm_execute_command",
        description=(
            "Execute an allowlisted command on an active mitmweb session (e.g. view.clear, flow.kill)."
        ),
    )
    async def mitm_execute_command(
        params: MitmExecuteCommandInput,
        ctx: Context,
    ) -> MitmExecuteCommandOutput:
        try:
            if params.command not in ALLOWED_COMMANDS:
                raise CommandNotAllowedError(
                    f"command {params.command!r} is not in the allowlist",
                    detail={"command": params.command, "allowed": sorted(ALLOWED_COMMANDS)},
                )

            lc = _resolve_context(ctx)
            registry = lc.registry
            state = registry.get(params.session_id)
            if state.status is not SessionStatus.RUNNING:
                raise SessionNotRunningError(
                    f"session {params.session_id} is {state.status.value}, not running"
                )

            token = registry.get_web_token(params.session_id)
            base_url = f"http://{state.web_host}:{state.web_port}"

            async with MitmwebClient(base_url, token=token) as client:
                res = await client.execute_command(params.command, params.arguments)

            if isinstance(res, dict) and "error" in res:
                return MitmExecuteCommandOutput(
                    ok=False,
                    error=CommandNotAllowedError(res["error"]).to_error(),
                )

            return MitmExecuteCommandOutput(
                ok=True, result=res.get("value") if isinstance(res, dict) else res
            )
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmExecuteCommandOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitm_export_flow",
        description=(
            "Export a captured flow to an external format (curl, httpie, raw, raw_request, raw_response) "
            "from an active session's dump or directly from a .mitm dump file. "
            "The exported content has secrets redacted (R4)."
        ),
    )
    async def mitm_export_flow(
        params: MitmExportFlowInput,
        ctx: Context,
    ) -> MitmExportFlowOutput:
        try:
            lc = _resolve_context(ctx)
            settings = lc.settings
            registry = lc.registry

            dump_path: str | None = None
            if params.flow_path:
                dump_path = ensure_allowed(params.flow_path, settings.allowed_dump_roots)
            elif params.session_id:
                state = registry.get(params.session_id)
                if state.save_path:
                    dump_path = state.save_path
                else:
                    # Offline export from the live session's dump endpoint.
                    token = registry.get_web_token(params.session_id)
                    base_url = f"http://{state.web_host}:{state.web_port}"
                    async with MitmwebClient(base_url, token=token) as client:
                        dump = await client.get_dump()
                    target_flow = find_flow_by_id(read_flows_from_bytes(dump), params.flow_id)
                    content = export_flow_offline(
                        target_flow,
                        params.format,
                        preserve_original_ip=params.preserve_original_ip,
                    )
                    return MitmExportFlowOutput(
                        ok=True, content=redact_text(content), format=params.format
                    )

            if not dump_path:
                raise InvalidInputError(
                    "either flow_path or a session with save_path must be provided"
                )

            flows = read_flows_from_dump(dump_path)
            target = find_flow_by_id(flows, params.flow_id)
            content = export_flow_offline(
                target,
                params.format,
                preserve_original_ip=params.preserve_original_ip,
            )
            return MitmExportFlowOutput(ok=True, content=redact_text(content), format=params.format)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmExportFlowOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitm_filter_flows",
        description=(
            "Filter flows using mitmproxy FlowFilter expressions (~u, ~m, ~c, ~b, ~h, ~d, etc.) "
            "evaluated either from a .mitm dump file or from an active session."
        ),
    )
    async def mitm_filter_flows(
        params: MitmFilterFlowsInput,
        ctx: Context,
    ) -> MitmFilterFlowsOutput:
        try:
            lc = _resolve_context(ctx)
            settings = lc.settings
            registry = lc.registry

            dump_path: str | None = None
            if params.flow_path:
                dump_path = ensure_allowed(params.flow_path, settings.allowed_dump_roots)
            elif params.session_id:
                state = registry.get(params.session_id)
                if state.save_path:
                    dump_path = state.save_path
                else:
                    token = registry.get_web_token(params.session_id)
                    base_url = f"http://{state.web_host}:{state.web_port}"
                    async with MitmwebClient(base_url, token=token) as client:
                        dump = await client.get_dump(filter_expression=params.expression)
                    matched_flows = read_flows_from_bytes(dump)
                    matched, count = filter_flows(
                        matched_flows, params.expression, limit=params.limit
                    )
                    return MitmFilterFlowsOutput(ok=True, matched=matched, count=count)

            if not dump_path:
                raise InvalidInputError(
                    "either flow_path or a session with save_path must be provided"
                )

            flows = read_flows_from_dump(dump_path)
            matched, count = filter_flows(flows, params.expression, limit=params.limit)
            return MitmFilterFlowsOutput(ok=True, matched=matched, count=count)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmFilterFlowsOutput(ok=res.ok, error=res.error)


__all__ = ["ALLOWED_COMMANDS", "register_core_tools"]

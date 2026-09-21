"""Tools exposing mitmweb functionality to MCP clients (architecture §3.3.4–§3.3.6)."""

from __future__ import annotations

import secrets

from fastmcp import Context, FastMCP

from mcp_security_mitmproxy.core.errors import (
    SessionNotRunningError,
    to_tool_result,
)
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.core.modes import (
    build_listen_host_arg,
    build_listen_port_args,
    build_mode_args,
    ensure_mode_privileges,
)
from mcp_security_mitmproxy.core.paths import ensure_allowed, ensure_allowed_many
from mcp_security_mitmproxy.schemas.common import SessionStatus, ToolResult
from mcp_security_mitmproxy.schemas.mitmweb import (
    MitmwebGetFlowDetailInput,
    MitmwebGetFlowDetailOutput,
    MitmwebGetFlowsInput,
    MitmwebGetFlowsOutput,
    MitmwebStartInput,
    MitmwebStartOutput,
)
from mcp_security_mitmproxy.schemas.process import StopInput
from mcp_security_mitmproxy.web_client.client import MitmwebClient


def _resolve_context(ctx: Context) -> LifespanContext:
    obj = ctx.lifespan_context
    if not isinstance(obj, LifespanContext):
        raise RuntimeError("lifespan context not initialized")
    return obj


def register_mitmweb_tools(mcp: FastMCP) -> None:
    """Register all mitmweb tools on the FastMCP instance."""

    @mcp.tool(
        name="mitmweb_start",
        description=(
            "Start an interactive mitmweb proxy session with web UI and REST API bridge enabled."
        ),
    )
    async def mitmweb_start(
        params: MitmwebStartInput,
        ctx: Context,
    ) -> MitmwebStartOutput:
        try:
            lc = _resolve_context(ctx)
            settings = lc.settings
            registry = lc.registry

            save_path: str | None = None
            if params.save_path:
                save_path = ensure_allowed(params.save_path, settings.allowed_dump_roots)

            scripts = ensure_allowed_many(params.scripts, settings.allowed_script_roots)

            token = params.web_password or secrets.token_hex(16)

            # R5: refuse privileged modes explicitly, before any argv is built.
            ensure_mode_privileges(params.mode)

            argv = ["mitmweb"]
            argv.extend(build_mode_args(params.mode))
            argv.extend(build_listen_host_arg(params.listen_host))
            argv.extend(build_listen_port_args(params.mode))

            # Web configuration. web_password is a secret: it is delivered via
            # the session's 0600 config.yaml (SEC-3), never on the command line.
            argv.extend(["--set", f"web_host={params.web_host}"])
            argv.extend(["--set", f"web_port={params.web_port}"])
            argv.extend(
                [
                    "--set",
                    f"web_open_browser={'true' if params.web_open_browser else 'false'}",
                ]
            )

            if save_path:
                argv.extend(["-w", save_path])

            for script in scripts:
                argv.extend(["-s", script])

            listen_ports = [s.listen_port for s in params.mode if s.listen_port is not None]
            ports = [*listen_ports, params.web_port]
            # Probe each port against the host it actually binds (B5/SEC-4):
            # web_port binds web_host, proxy ports bind listen_host.
            port_hosts = [params.listen_host] * len(listen_ports) + [params.web_host]

            state = await registry.start(
                executable="mitmweb",
                argv=argv,
                modes=params.mode,
                listen_host=params.listen_host,
                listen_ports=ports,
                port_hosts=port_hosts,
                web_host=params.web_host,
                web_port=params.web_port,
                web_token=token,
                isolate_confdir=True,
                config_options={"web_password": token},
                save_path=save_path,
            )

            web_url = f"http://{params.web_host}:{params.web_port}/"
            return MitmwebStartOutput(ok=True, session=state, web_url=web_url)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmwebStartOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitmweb_stop",
        description="Stop an active mitmweb session and release listen and web ports.",
    )
    async def mitmweb_stop(
        params: StopInput,
        ctx: Context,
    ) -> ToolResult:
        try:
            lc = _resolve_context(ctx)
            await lc.registry.stop(
                params.session_id,
                timeout=params.timeout_seconds,
                force=params.force,
            )
            return ToolResult(ok=True)
        except Exception as exc:
            return to_tool_result(exc)

    @mcp.tool(
        name="mitmweb_get_flows",
        description=(
            "Retrieve captured flows (HTTP/WebSocket/TCP/UDP) from a running mitmweb session."
        ),
    )
    async def mitmweb_get_flows(
        params: MitmwebGetFlowsInput,
        ctx: Context,
    ) -> MitmwebGetFlowsOutput:
        try:
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
                flows, total = await client.get_flows(
                    filter_expression=params.filter_expression,
                    limit=params.limit,
                    offset=params.offset,
                )

            return MitmwebGetFlowsOutput(ok=True, flows=flows, total=total)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmwebGetFlowsOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitmweb_get_flow_detail",
        description=(
            "Fetch detailed inspection data for a single flow from mitmweb, "
            "including headers, payloads and content views, with automatic secret redaction."
        ),
    )
    async def mitmweb_get_flow_detail(
        params: MitmwebGetFlowDetailInput,
        ctx: Context,
    ) -> MitmwebGetFlowDetailOutput:
        try:
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
                detail = await client.get_flow_detail(
                    params.flow_id,
                    parts=list(params.parts),
                    content_view=params.content_view,
                    redact=params.redact,
                )

            return MitmwebGetFlowDetailOutput(ok=True, detail=detail)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmwebGetFlowDetailOutput(ok=res.ok, error=res.error)


__all__ = ["register_mitmweb_tools"]

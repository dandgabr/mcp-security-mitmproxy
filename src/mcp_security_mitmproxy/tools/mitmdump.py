"""Tools exposing mitmdump functionality to MCP clients (architecture §3.3.1–§3.3.3)."""

from __future__ import annotations

from fastmcp import Context, FastMCP

from mcp_security_mitmproxy.core.errors import InvalidInputError, to_tool_result
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.core.modes import (
    build_listen_host_arg,
    build_listen_port_args,
    build_mode_args,
    ensure_mode_privileges,
)
from mcp_security_mitmproxy.core.paths import ensure_allowed, ensure_allowed_many
from mcp_security_mitmproxy.schemas.common import ToolResult
from mcp_security_mitmproxy.schemas.mitmdump import (
    MitmdumpReplayInput,
    MitmdumpStartInput,
    MitmdumpStartOutput,
)
from mcp_security_mitmproxy.schemas.process import StopInput


def _resolve_context(ctx: Context) -> LifespanContext:
    obj = ctx.lifespan_context
    if not isinstance(obj, LifespanContext):
        raise RuntimeError("lifespan context not initialized")
    return obj


def register_mitmdump_tools(mcp: FastMCP) -> None:
    """Register all mitmdump tools on the FastMCP instance."""

    @mcp.tool(
        name="mitmdump_start",
        description=(
            "Start a headless mitmdump capture session with explicit proxy modes, "
            "optional .mitm output saving, flow filtering and scripts."
        ),
    )
    async def mitmdump_start(
        params: MitmdumpStartInput,
        ctx: Context,
    ) -> MitmdumpStartOutput:
        try:
            lc = _resolve_context(ctx)
            settings = lc.settings
            registry = lc.registry

            # Validate paths against allowlists (R3)
            save_path: str | None = None
            if params.save_path:
                save_path = ensure_allowed(params.save_path, settings.allowed_dump_roots)

            scripts = ensure_allowed_many(params.scripts, settings.allowed_script_roots)

            # R5: refuse privileged modes explicitly, before any argv is built.
            ensure_mode_privileges(params.mode)

            # Assemble argv
            argv = ["mitmdump"]
            argv.extend(build_mode_args(params.mode))
            argv.extend(build_listen_host_arg(params.listen_host))
            argv.extend(build_listen_port_args(params.mode))

            if save_path:
                argv.extend(["-w", save_path])

            # mitmproxy's flow_detail is an int 0-4; the readable enum name
            # would make argparse reject the value ("invalid int value").
            argv.extend(["--flow-detail", str(params.flow_detail.level)])

            if params.filter_expression:
                argv.append(params.filter_expression)

            for script in scripts:
                argv.extend(["-s", script])

            for key, val in params.set_options.items():
                argv.extend(["--set", f"{key}={val}"])

            ports = [s.listen_port for s in params.mode if s.listen_port is not None]
            state = await registry.start(
                executable="mitmdump",
                argv=argv,
                modes=params.mode,
                listen_host=params.listen_host,
                listen_ports=ports,
                isolate_confdir=True,
                save_path=save_path,
            )
            return MitmdumpStartOutput(ok=True, session=state)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmdumpStartOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitmdump_stop",
        description="Stop an active mitmproxy/mitmdump/mitmweb session and release ports.",
    )
    async def mitmdump_stop(
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
        name="mitmdump_replay",
        description=(
            "Replay flows through mitmdump using client (-C) or server (-S) replay "
            "from existing .mitm dump files."
        ),
    )
    async def mitmdump_replay(
        params: MitmdumpReplayInput,
        ctx: Context,
    ) -> MitmdumpStartOutput:
        try:
            lc = _resolve_context(ctx)
            settings = lc.settings
            registry = lc.registry

            if not params.client_replay and not params.server_replay:
                raise InvalidInputError("at least one replay file (-C or -S) is required")

            # R5: same explicit refusal on the replay path.
            ensure_mode_privileges(params.mode)

            client_files = ensure_allowed_many(params.client_replay, settings.allowed_dump_roots)
            server_files = ensure_allowed_many(params.server_replay, settings.allowed_dump_roots)

            save_path: str | None = None
            if params.save_path:
                save_path = ensure_allowed(params.save_path, settings.allowed_dump_roots)

            argv = ["mitmdump"]
            argv.extend(build_mode_args(params.mode))
            argv.extend(build_listen_port_args(params.mode))

            for cf in client_files:
                argv.extend(["--client-replay", cf])
            for sf in server_files:
                argv.extend(["--server-replay", sf])

            if params.replay_kill_extra:
                argv.extend(["--set", "replay_kill_extra=true"])

            if save_path:
                argv.extend(["-w", save_path])

            ports = [s.listen_port for s in params.mode if s.listen_port is not None]
            state = await registry.start(
                executable="mitmdump",
                argv=argv,
                modes=params.mode,
                listen_ports=ports,
                isolate_confdir=True,
                save_path=save_path,
            )
            return MitmdumpStartOutput(ok=True, session=state)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmdumpStartOutput(ok=res.ok, error=res.error)


__all__ = ["register_mitmdump_tools"]

"""Fase 4 rules tools — traffic mutation via mitmweb ``/options`` (architecture 0003).

Six tools, one per rule family plus list/clear. Every mutation is a strict
read-modify-write against ``PUT /options``: mitmproxy replaces a ``Sequence[str]``
wholesale, so the full updated list is submitted, never an append.

Security boundary (R3, architecture 0003 §4):
* ``mitm_set_map_local`` validates the path with
  :func:`core.paths.ensure_allowed` against ``settings.allowed_mock_roots``
  **before** compiling the spec — the native parser resolves with ``strict=True``
  and would otherwise raise a raw ``OptionsError``.
* The other three families can only reference remote URLs, header names/values
  and in-payload replacements; ``@file`` syntax is refused at the schema.
* No raw ``--set`` reaches these options: they are in ``RESERVED_SET_OPTIONS``.
"""

from __future__ import annotations

from typing import Any

from fastmcp import Context, FastMCP

from mcp_security_mitmproxy.core.errors import (
    SessionNotRunningError,
    to_tool_result,
)
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.core.paths import ensure_allowed
from mcp_security_mitmproxy.rules.engine import (
    RULE_OPTION_KEYS,
    format_map_local_spec,
    format_map_remote_spec,
    format_modify_body_spec,
    format_modify_headers_spec,
    parse_options,
)
from mcp_security_mitmproxy.schemas.common import SessionStatus
from mcp_security_mitmproxy.schemas.process import SessionState
from mcp_security_mitmproxy.schemas.rules import (
    MitmClearRulesInput,
    MitmClearRulesOutput,
    MitmListRulesInput,
    MitmListRulesOutput,
    MitmModifyBodyInput,
    MitmModifyBodyOutput,
    MitmModifyHeadersInput,
    MitmModifyHeadersOutput,
    MitmSetMapLocalInput,
    MitmSetMapLocalOutput,
    MitmSetMapRemoteInput,
    MitmSetMapRemoteOutput,
    RuleType,
)
from mcp_security_mitmproxy.web_client.client import MitmwebClient


def _resolve_context(ctx: Context) -> LifespanContext:
    obj = ctx.lifespan_context
    if not isinstance(obj, LifespanContext):
        raise RuntimeError("lifespan context not initialized")
    return obj


def _running_web_session(lifespan: LifespanContext, session_id: str) -> SessionState:
    """Return the session, asserting it is a running mitmweb instance.

    Rules are applied over the REST bridge, which only ``mitmweb`` exposes; a
    headless ``mitmdump`` session has no ``/options`` endpoint.
    """
    state = lifespan.registry.get(session_id)
    if state.status is not SessionStatus.RUNNING:
        raise SessionNotRunningError(f"session {session_id} is {state.status.value}, not running")
    if state.web_host is None or state.web_port is None:
        raise SessionNotRunningError(
            f"session {session_id} has no mitmweb bridge (start it with mitmweb_start)"
        )
    return state


def _client(lifespan: LifespanContext, session_id: str) -> MitmwebClient:
    state = lifespan.registry.get(session_id)
    token = lifespan.registry.get_web_token(session_id)
    base_url = f"http://{state.web_host}:{state.web_port}"
    return MitmwebClient(base_url, token=token)


async def _read_rule_values(lifespan: LifespanContext, session_id: str) -> dict[str, Any]:
    """Return the raw ``value`` list for each of the four rule families."""
    async with _client(lifespan, session_id) as client:
        options = await client.get_options()
    return {rule_type.value: _option_list(options, rule_type) for rule_type in RULE_OPTION_KEYS}


def _option_list(options: dict[str, Any], rule_type: RuleType) -> list[str]:
    entry = options.get(rule_type.value)
    if not isinstance(entry, dict):
        return []
    value = entry.get("value")
    return [str(item) for item in value] if isinstance(value, list) else []


async def _append_rule(
    lifespan: LifespanContext,
    session_id: str,
    rule_type: RuleType,
    rendered_spec: str,
) -> str:
    """Read-modify-write one rule family, returning the new rule's index id."""
    async with _client(lifespan, session_id) as client:
        options = await client.get_options()
        current = _option_list(options, rule_type)
        updated = [*current, rendered_spec]
        await client.put_options(**{rule_type.value: updated})
    return f"{rule_type.value}:{len(updated) - 1}"


def register_rules_tools(mcp: FastMCP) -> None:
    """Register the six Fase 4 rules tools on the FastMCP instance."""

    @mcp.tool(
        name="mitm_set_map_remote",
        description=(
            "Redirect requests matching a URL regex to another remote URL "
            "(mitmproxy map_remote). Applied live over mitmweb."
        ),
    )
    async def mitm_set_map_remote(
        params: MitmSetMapRemoteInput,
        ctx: Context,
    ) -> MitmSetMapRemoteOutput:
        try:
            lc = _resolve_context(ctx)
            _running_web_session(lc, params.session_id)
            rendered = format_map_remote_spec(params.rule)
            rule_id = await _append_rule(lc, params.session_id, RuleType.MAP_REMOTE, rendered)
            return MitmSetMapRemoteOutput(ok=True, rule_id=rule_id, rendered_spec=rendered)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmSetMapRemoteOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitm_set_map_local",
        description=(
            "Serve a mocked response for requests matching a URL regex from a local "
            "file or directory. The path MUST be inside allowed_mock_roots (R3)."
        ),
    )
    async def mitm_set_map_local(
        params: MitmSetMapLocalInput,
        ctx: Context,
    ) -> MitmSetMapLocalOutput:
        try:
            lc = _resolve_context(ctx)
            _running_web_session(lc, params.session_id)
            # R3: validate BEFORE compiling — the native parser resolves
            # strict=True and would raise an opaque OptionsError on a bad path.
            canonical_path = ensure_allowed(params.rule.local_path, lc.settings.allowed_mock_roots)
            rendered = format_map_local_spec(params.rule, canonical_path)
            rule_id = await _append_rule(lc, params.session_id, RuleType.MAP_LOCAL, rendered)
            return MitmSetMapLocalOutput(
                ok=True,
                rule_id=rule_id,
                canonical_path=canonical_path,
                rendered_spec=rendered,
            )
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmSetMapLocalOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitm_modify_headers",
        description=(
            "Set or remove an HTTP header on matching requests/responses "
            "(mitmproxy modify_headers)."
        ),
    )
    async def mitm_modify_headers(
        params: MitmModifyHeadersInput,
        ctx: Context,
    ) -> MitmModifyHeadersOutput:
        try:
            lc = _resolve_context(ctx)
            _running_web_session(lc, params.session_id)
            rendered = format_modify_headers_spec(params.rule)
            rule_id = await _append_rule(lc, params.session_id, RuleType.MODIFY_HEADERS, rendered)
            return MitmModifyHeadersOutput(ok=True, rule_id=rule_id, rendered_spec=rendered)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmModifyHeadersOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitm_modify_body",
        description=(
            "Regex-substitute inside matching request/response payloads "
            "(mitmproxy modify_body, DOTALL)."
        ),
    )
    async def mitm_modify_body(
        params: MitmModifyBodyInput,
        ctx: Context,
    ) -> MitmModifyBodyOutput:
        try:
            lc = _resolve_context(ctx)
            _running_web_session(lc, params.session_id)
            rendered = format_modify_body_spec(params.rule)
            rule_id = await _append_rule(lc, params.session_id, RuleType.MODIFY_BODY, rendered)
            return MitmModifyBodyOutput(ok=True, rule_id=rule_id, rendered_spec=rendered)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmModifyBodyOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitm_list_rules",
        description="List the active map_remote/map_local/modify_headers/modify_body rules.",
    )
    async def mitm_list_rules(
        params: MitmListRulesInput,
        ctx: Context,
    ) -> MitmListRulesOutput:
        try:
            lc = _resolve_context(ctx)
            _running_web_session(lc, params.session_id)
            async with _client(lc, params.session_id) as client:
                options = await client.get_options()
            rules = parse_options(options)
            counts: dict[str, int] = {}
            for rule in rules:
                counts[rule.rule_type.value] = counts.get(rule.rule_type.value, 0) + 1
            return MitmListRulesOutput(ok=True, rules=rules, counts=counts)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmListRulesOutput(ok=res.ok, error=res.error)

    @mcp.tool(
        name="mitm_clear_rules",
        description=(
            "Clear active rules. Pass rule_type to clear one family, or omit it to clear all four."
        ),
    )
    async def mitm_clear_rules(
        params: MitmClearRulesInput,
        ctx: Context,
    ) -> MitmClearRulesOutput:
        try:
            lc = _resolve_context(ctx)
            _running_web_session(lc, params.session_id)
            target_types = [params.rule_type] if params.rule_type else list(RULE_OPTION_KEYS)
            async with _client(lc, params.session_id) as client:
                options = await client.get_options()
                cleared = sum(len(_option_list(options, rt)) for rt in target_types)
                await client.put_options(**{rt.value: [] for rt in target_types})
                remaining_options = await client.get_options()
            remaining = {
                rt.value: len(_option_list(remaining_options, rt)) for rt in RULE_OPTION_KEYS
            }
            return MitmClearRulesOutput(ok=True, cleared_count=cleared, remaining=remaining)
        except Exception as exc:
            res = to_tool_result(exc)
            return MitmClearRulesOutput(ok=res.ok, error=res.error)


__all__ = ["register_rules_tools"]

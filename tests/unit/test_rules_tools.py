"""Fase 4 rules tools — security guards and read-modify-write behaviour.

The mitmweb REST bridge is mocked with ``httpx.MockTransport``; no proxy runs.
Security cases assert ``ensure_allowed`` fires *before* any option compiles.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from fastmcp import Context

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.core.session import SessionRegistry
from mcp_security_mitmproxy.schemas.common import SessionStatus
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec, SessionState
from mcp_security_mitmproxy.schemas.rules import (
    HeaderOperation,
    MapLocalRuleSpec,
    MapRemoteRuleSpec,
    MitmClearRulesInput,
    MitmListRulesInput,
    MitmModifyHeadersInput,
    MitmSetMapLocalInput,
    MitmSetMapRemoteInput,
    ModifyHeaderRuleSpec,
)
from mcp_security_mitmproxy.server import create_server


def _options_payload(**values: list[str]) -> dict[str, object]:
    """Build a ``GET /options`` payload with the four rule families."""
    families = ("map_remote", "map_local", "modify_headers", "modify_body")
    return {
        name: {
            "value": values.get(name, []),
            "default": [],
            "type": "sequence of str",
        }
        for name in families
    }


def _install_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler,
) -> list[httpx.Request]:
    captured: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    real_client = httpx.AsyncClient

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(recording)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return captured


def _disable_csrf_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip the /updates WebSocket CSRF bootstrap in unit tests.

    The MockTransport serves no WebSocket, so the client would otherwise emit an
    extra ``GET /`` probe (and a socket handshake). Marking the token as loaded
    keeps read-modify-write assertions focused on /options.
    """
    from mcp_security_mitmproxy.web_client import client as client_module

    async def _noop(self: object) -> None:
        return None

    monkeypatch.setattr(client_module.MitmwebClient, "_ensure_csrf_token", _noop)


@pytest.fixture
def rules_env(tmp_path: Path, monkeypatch) -> tuple[object, LifespanContext, Context, Path]:
    mock_root = tmp_path / "mocks"
    mock_root.mkdir()
    (mock_root / "user.json").write_text("{}", encoding="utf-8")

    server = create_server()
    settings = Settings(
        allowed_mock_roots=[mock_root],
        session_root=tmp_path / "sessions",
    )
    registry = SessionRegistry(settings)
    lc = LifespanContext(settings=settings, registry=registry)

    # Register a fake running mitmweb session directly in the registry.
    state = SessionState(
        session_id="web-1",
        executable="mitmweb",
        status=SessionStatus.RUNNING,
        web_host="127.0.0.1",
        web_port=8081,
    )
    registry._entries["web-1"] = MagicMock(
        state=state, leased_ports=[], web_token="tok", runner=MagicMock()
    )

    ctx = MagicMock(spec=Context)
    ctx.lifespan_context = lc
    _disable_csrf_bootstrap(monkeypatch)
    return server, lc, ctx, mock_root


async def test_set_map_local_rejects_path_outside_allowlist(rules_env, monkeypatch) -> None:
    server, _lc, ctx, _root = rules_env
    _install_transport(monkeypatch, lambda _r: httpx.Response(200, json=_options_payload()))

    tool = await server.get_tool("mitm_set_map_local")
    res = await tool.fn(
        MitmSetMapLocalInput(
            session_id="web-1",
            rule=MapLocalRuleSpec(url_pattern=r"/x", local_path="/etc/passwd"),
        ),
        ctx,
    )
    assert res.ok is False
    assert res.error is not None
    assert res.error.code.value == "PATH_NOT_ALLOWED"


async def test_set_map_local_rejects_ssh_key(rules_env, monkeypatch) -> None:
    server, _lc, ctx, _root = rules_env
    _install_transport(monkeypatch, lambda _r: httpx.Response(200, json=_options_payload()))

    tool = await server.get_tool("mitm_set_map_local")
    res = await tool.fn(
        MitmSetMapLocalInput(
            session_id="web-1",
            rule=MapLocalRuleSpec(url_pattern=r"/x", local_path="~/.ssh/id_rsa"),
        ),
        ctx,
    )
    assert res.ok is False
    assert res.error.code.value == "PATH_NOT_ALLOWED"


async def test_set_map_local_rejects_symlink_escape(rules_env, monkeypatch, tmp_path) -> None:
    server, _lc, ctx, _root = rules_env
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = _root / "escape.json"
    link.symlink_to(outside)
    _install_transport(monkeypatch, lambda _r: httpx.Response(200, json=_options_payload()))

    tool = await server.get_tool("mitm_set_map_local")
    res = await tool.fn(
        MitmSetMapLocalInput(
            session_id="web-1",
            rule=MapLocalRuleSpec(url_pattern=r"/x", local_path=str(link)),
        ),
        ctx,
    )
    assert res.ok is False
    assert res.error.code.value == "PATH_NOT_ALLOWED"


async def test_set_map_local_empty_allowlist_denies(tmp_path, monkeypatch) -> None:
    server = create_server()
    settings = Settings(allowed_mock_roots=[], session_root=tmp_path / "s")
    registry = SessionRegistry(settings)
    lc = LifespanContext(settings=settings, registry=registry)
    state = SessionState(
        session_id="web-1",
        executable="mitmweb",
        status=SessionStatus.RUNNING,
        web_host="127.0.0.1",
        web_port=8081,
    )
    registry._entries["web-1"] = MagicMock(
        state=state, leased_ports=[], web_token=None, runner=MagicMock()
    )
    ctx = MagicMock(spec=Context)
    ctx.lifespan_context = lc
    _disable_csrf_bootstrap(monkeypatch)
    _install_transport(monkeypatch, lambda _r: httpx.Response(200, json=_options_payload()))

    tool = await server.get_tool("mitm_set_map_local")
    res = await tool.fn(
        MitmSetMapLocalInput(
            session_id="web-1",
            rule=MapLocalRuleSpec(url_pattern=r"/x", local_path=str(tmp_path / "m.json")),
        ),
        ctx,
    )
    assert res.ok is False
    assert res.error.code.value == "PATH_NOT_ALLOWED"


async def test_set_map_local_allowed_appends_via_put(rules_env, monkeypatch) -> None:
    server, _lc, ctx, root = rules_env
    target = root / "user.json"
    captured = _install_transport(
        monkeypatch,
        lambda r: (
            httpx.Response(200, json=_options_payload())
            if r.method == "GET"
            else httpx.Response(200)
        ),
    )

    tool = await server.get_tool("mitm_set_map_local")
    res = await tool.fn(
        MitmSetMapLocalInput(
            session_id="web-1",
            rule=MapLocalRuleSpec(url_pattern=r"/api/user", local_path=str(target)),
        ),
        ctx,
    )
    assert res.ok is True
    assert res.canonical_path == str(target.resolve())
    assert res.rule_id == "map_local:0"

    methods = [(r.method, r.url.path) for r in captured]
    assert methods == [("GET", "/options"), ("PUT", "/options")]
    put_body = captured[1].content.decode()
    assert "map_local" in put_body
    assert "api/user" in put_body


async def test_set_map_local_appends_to_existing_list(rules_env, monkeypatch) -> None:
    """Read-modify-write: the existing rule must survive the append."""
    server, _lc, ctx, root = rules_env
    existing = _options_payload(map_local=["|/old|/srv/old.json"])
    captured = _install_transport(
        monkeypatch,
        lambda r: httpx.Response(200, json=existing) if r.method == "GET" else httpx.Response(200),
    )

    tool = await server.get_tool("mitm_set_map_local")
    res = await tool.fn(
        MitmSetMapLocalInput(
            session_id="web-1",
            rule=MapLocalRuleSpec(url_pattern=r"/new", local_path=str(root / "user.json")),
        ),
        ctx,
    )
    assert res.ok is True
    assert res.rule_id == "map_local:1"
    body = captured[1].content.decode()
    assert "/srv/old.json" in body


async def test_set_map_remote_compiles_and_sends(rules_env, monkeypatch) -> None:
    server, _lc, ctx, _root = rules_env
    captured = _install_transport(
        monkeypatch,
        lambda r: (
            httpx.Response(200, json=_options_payload())
            if r.method == "GET"
            else httpx.Response(200)
        ),
    )

    tool = await server.get_tool("mitm_set_map_remote")
    res = await tool.fn(
        MitmSetMapRemoteInput(
            session_id="web-1",
            rule=MapRemoteRuleSpec(
                url_pattern=r"^https://api\.example\.com/",
                replacement_url="https://staging.internal/",
            ),
        ),
        ctx,
    )
    assert res.ok is True
    assert res.rendered_spec is not None
    assert "map_remote" in captured[1].content.decode()


async def test_modify_headers_remove_renders_empty_value(rules_env, monkeypatch) -> None:
    server, _lc, ctx, _root = rules_env
    captured = _install_transport(
        monkeypatch,
        lambda r: (
            httpx.Response(200, json=_options_payload())
            if r.method == "GET"
            else httpx.Response(200)
        ),
    )

    tool = await server.get_tool("mitm_modify_headers")
    res = await tool.fn(
        MitmModifyHeadersInput(
            session_id="web-1",
            rule=ModifyHeaderRuleSpec(header_name="X-Secret", operation=HeaderOperation.REMOVE),
        ),
        ctx,
    )
    assert res.ok is True
    assert res.rendered_spec is not None
    assert captured[1].content.decode().endswith('|X-Secret|"]}')


async def test_rules_require_web_session(rules_env, monkeypatch) -> None:
    server, lc, ctx, _root = rules_env
    state = SessionState(
        session_id="dump-1",
        executable="mitmdump",
        status=SessionStatus.RUNNING,
        listen_ports=[8888],
    )
    lc.registry._entries["dump-1"] = MagicMock(
        state=state, leased_ports=[8888], web_token=None, runner=MagicMock()
    )

    tool = await server.get_tool("mitm_set_map_remote")
    res = await tool.fn(
        MitmSetMapRemoteInput(
            session_id="dump-1",
            rule=MapRemoteRuleSpec(url_pattern="a", replacement_url="b"),
        ),
        ctx,
    )
    assert res.ok is False
    assert res.error.code.value == "SESSION_NOT_RUNNING"


async def test_list_rules_parses_options(rules_env, monkeypatch) -> None:
    server, _lc, ctx, _root = rules_env
    payload = _options_payload(
        map_remote=["|a|b"], map_local=["|c|/tmp/d"], modify_headers=["|X|v"]
    )
    _install_transport(monkeypatch, lambda _r: httpx.Response(200, json=payload))

    tool = await server.get_tool("mitm_list_rules")
    res = await tool.fn(MitmListRulesInput(session_id="web-1"), ctx)
    assert res.ok is True
    assert res.counts == {"map_remote": 1, "map_local": 1, "modify_headers": 1}
    assert len(res.rules) == 3


async def test_clear_rules_all_four(rules_env, monkeypatch) -> None:
    server, _lc, ctx, _root = rules_env
    initial = _options_payload(map_remote=["|a|b"], modify_body=["|x|y"])
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=initial)
        return httpx.Response(200)

    _install_transport(monkeypatch, handler)

    tool = await server.get_tool("mitm_clear_rules")
    res = await tool.fn(MitmClearRulesInput(session_id="web-1"), ctx)
    assert res.ok is True
    assert res.cleared_count == 2
    put_body = [r for r in calls if r.method == "PUT"][0].content.decode()
    for family in ("map_remote", "map_local", "modify_headers", "modify_body"):
        assert family in put_body


async def test_clear_rules_single_family(rules_env, monkeypatch) -> None:
    from mcp_security_mitmproxy.schemas.rules import RuleType

    server, _lc, ctx, _root = rules_env
    initial = _options_payload(map_remote=["|a|b"], modify_body=["|x|y"])
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=initial) if request.method == "GET" else httpx.Response(200)

    _install_transport(monkeypatch, handler)

    tool = await server.get_tool("mitm_clear_rules")
    res = await tool.fn(MitmClearRulesInput(session_id="web-1", rule_type=RuleType.MAP_REMOTE), ctx)
    assert res.ok is True
    assert res.cleared_count == 1


async def test_mitmdump_set_options_rejects_map_local() -> None:
    """Raw --set map_local must be refused at the schema (RESERVED_SET_OPTIONS)."""
    from pydantic import ValidationError

    from mcp_security_mitmproxy.schemas.common import ProxyMode
    from mcp_security_mitmproxy.schemas.mitmdump import MitmdumpStartInput

    with pytest.raises(ValidationError):
        MitmdumpStartInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR)],
            set_options={"map_local": "|/x|/etc/passwd"},
        )
